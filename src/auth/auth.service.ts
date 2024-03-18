import { BadRequestException, Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { CommonService } from '../common/common.service';
import { UsersService } from '../users/users.service';
import { JwtService } from '../jwt/jwt.service';
import { MailerService } from '../mailer/mailer.service';
import { UserEntity } from '../users/entities/user.entity';
import { TokenTypeEnum } from '../jwt/enums/token-type.enum';
import { SignUpDto } from './dtos/sign-up.dto';
import { IMessage } from '../common/interfaces/message.interface';
import { SignInDto } from './dtos/sign-in.dto';
import { IAuthResult } from './interfaces/auth-result.interface';
import { isEmail } from 'class-validator';
import { SLUG_REGEX } from '../common/consts/regex.const';
import { ICredentials } from '../users/interfaces/credentials.interface';
import dayjs from 'dayjs';
import { IRefreshToken } from '../jwt/interfaces/refresh-token.interface';
import { EmailDto } from './dtos/email.dto';
import { isNull, isUndefined } from '../common/utils/validation.util';
import { ResetPasswordDto } from './dtos/reset-password.dto';
import { IEmailToken } from '../jwt/interfaces/email-token.interface';
import { ChangePasswordDto } from './dtos/change-password.dto';
import { CACHE_MANAGER } from '@nestjs/common/cache';
import { Cache } from 'cache-manager'
import * as argon2 from 'argon2';
import { ConfirmEmailDto } from './dtos/confirm-email.dto';

@Injectable()
export class AuthService {
  constructor(
    @Inject(CACHE_MANAGER)
    private readonly cacheManager: Cache,
    private readonly commonService: CommonService,
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly mailerService: MailerService,
  ) {}

  private async generateAuthTokens(
    user: UserEntity,
    domain?: string,
    tokenId?: string,
  ): Promise<[string, string]> {
    return Promise.all([
      this.jwtService.generateToken(
        user,
        TokenTypeEnum.ACCESS,
        domain,
        tokenId,
      ),
      this.jwtService.generateToken(
        user,
        TokenTypeEnum.REFRESH,
        domain,
        tokenId,
      ),
    ]);
  }

  public async signIn(dto: SignInDto, domain?: string): Promise<IAuthResult> {
    const { emailOrUsername, password } = dto;
    const user = await this.userByEmailOrUsername(emailOrUsername);

    if (!(await argon2.verify(user.password, password))) {
      await this.checkLastPassword(user.credentials, password);
    }
    if (!user.confirmed) {
      const confirmationToken = await this.jwtService.generateToken(
        user,
        TokenTypeEnum.CONFIRMATION,
        domain,
      );
      this.mailerService.sendConfirmationEmail(user, confirmationToken);
      throw new UnauthorizedException(
        'Please confirm your email, a new email has been sent',
      );
    }

    const [accessToken, refreshToken] = await this.generateAuthTokens(
      user,
      domain,
    );
    return { user, accessToken, refreshToken };
  }

  // validates the input and fetches the user by email or username
  private async userByEmailOrUsername(
    emailOrUsername: string,
  ): Promise<UserEntity> {
    if (emailOrUsername.includes('@')) {
      if (!isEmail(emailOrUsername)) {
        throw new BadRequestException('Invalid email');
      }

      return this.usersService.findOneByEmail(emailOrUsername);
    }

    if (
      emailOrUsername.length < 3 ||
      emailOrUsername.length > 106 ||
      !SLUG_REGEX.test(emailOrUsername)
    ) {
      throw new BadRequestException('Invalid username');
    }

    return this.usersService.findOneByUsername(emailOrUsername, true);
  }

  // checks if your using your last password
  private async checkLastPassword(
    credentials: ICredentials,
    password: string,
  ): Promise<void> {
    const { lastPassword, passwordUpdatedAt } = credentials;

    if (lastPassword.length === 0 || !(await argon2.verify(lastPassword, password))) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const now = dayjs();
    const time = dayjs.unix(passwordUpdatedAt);
    const months = now.diff(time, 'month');
    const message = 'You changed your password ';

    if (months > 0) {
      throw new UnauthorizedException(
        message + months + (months > 1 ? ' months ago' : ' month ago'),
      );
    }

    const days = now.diff(time, 'day');

    if (days > 0) {
      throw new UnauthorizedException(
        message + days + (days > 1 ? ' days ago' : ' day ago'),
      );
    }

    const hours = now.diff(time, 'hour');

    if (hours > 0) {
      throw new UnauthorizedException(
        message + hours + (hours > 1 ? ' hours ago' : ' hour ago'),
      );
    }

    throw new UnauthorizedException(message + 'recently');
  }

  public async signUp(dto: SignUpDto, domain?: string): Promise<IMessage> {
    const { name, email, password, repeatedPassword } = dto;
    this.comparePasswords(password, repeatedPassword);
    console.log('heere', dto);
    const user = await this.usersService.create(email, name, password);
    const confirmationToken = await this.jwtService.generateToken(
      user,
      TokenTypeEnum.CONFIRMATION,
      domain,
    );
    this.mailerService.sendConfirmationEmail(user, confirmationToken);
    return this.commonService.generateMessage('Registration successful');
  }

  public async refreshTokenAccess(
    refreshToken: string,
    domain?: string,
  ): Promise<IAuthResult> {
    const { id, version, tokenId } =
      await this.jwtService.verifyToken<IRefreshToken>(
        refreshToken,
        TokenTypeEnum.REFRESH,
      );
    await this.checkIfTokenIsBlacklisted(id, tokenId);
    const user = await this.usersService.findOneByCredentials(id, version);
    const [accessToken, newRefreshToken] = await this.generateAuthTokens(
      user,
      domain,
      tokenId,
    );
    return { user, accessToken, refreshToken: newRefreshToken };
  }

  public async logout(refreshToken: string): Promise<IMessage> {
    const { id, tokenId, exp } =
      await this.jwtService.verifyToken<IRefreshToken>(
        refreshToken,
        TokenTypeEnum.REFRESH,
      );
    await this.blacklistToken(id, tokenId, exp);
    return this.commonService.generateMessage('Logout successful');
  }

  public async confirmEmail(
    dto: ConfirmEmailDto,
    domain?: string,
  ): Promise<IAuthResult> {
    const { confirmationToken } = dto;
    const { id, version } = await this.jwtService.verifyToken<IEmailToken>(
      confirmationToken,
      TokenTypeEnum.CONFIRMATION,
    );
    const user = await this.usersService.confirmEmail(id, version);
    const [accessToken, refreshToken] = await this.generateAuthTokens(
      user,
      domain,
    );
    return { user, accessToken, refreshToken };
  }

  public async resetPasswordEmail(
    dto: EmailDto,
    domain?: string,
  ): Promise<IMessage> {
    const user = await this.usersService.uncheckedUserByEmail(dto.email);

    if (!isUndefined(user) && !isNull(user)) {
      const resetToken = await this.jwtService.generateToken(
        user,
        TokenTypeEnum.RESET_PASSWORD,
        domain,
      );
      this.mailerService.sendResetPasswordEmail(user, resetToken);
    }

    return this.commonService.generateMessage('Reset password email sent');
  }

  public async updatePassword(
    userId: number,
    dto: ChangePasswordDto,
    domain?: string
  ): Promise<IAuthResult> {
    // TODO: Debug here
    const { password, repeatedPassword, changedPassword } = dto;
    this.comparePasswords(password, repeatedPassword);
    const user = await this.usersService.updatePassword(
      userId,
      changedPassword,
      password,
    );
    const [accessToken, refreshToken] = await this.generateAuthTokens(user, domain);
    return { user, accessToken, refreshToken };
  }

  public async resetPassword(dto: ResetPasswordDto): Promise<IMessage> {
    const { password, repeatedPassword, resetToken } = dto;
    const { id, version } = await this.jwtService.verifyToken<IEmailToken>(
      resetToken,
      TokenTypeEnum.RESET_PASSWORD,
    );
    this.comparePasswords(password, repeatedPassword);
    await this.usersService.resetPassword(id, version, password);
    return this.commonService.generateMessage('Password reset successful');
  }

  // checks if a blacklist token given a redis key exist on cache
  private async blacklistToken(userId: number, tokenId: string, exp: number): Promise<void> {
    const now = dayjs().unix();
    const ttl = (exp - now) * 1000;

    if (ttl > 0) {
      await this.commonService.throwInternalError(
        this.cacheManager.set(`blacklist:${userId}:${tokenId}`, now, ttl),
      );
    }
  }

  // checks if a token given the ID of the user and ID of token exists on the database
  private async checkIfTokenIsBlacklisted(
    userId: number,
    tokenId: string,
  ): Promise<void> {
    const time = await this.cacheManager.get<number>(
      `blacklist:${userId}:${tokenId}`,
    );

    if (!isUndefined(time) && !isNull(time)) {
      throw new UnauthorizedException('Invalid token');
    }
  }

  private comparePasswords(password: string, repeatedPassword: string): void {
    if (password !== repeatedPassword) {
      throw new BadRequestException('Passwords do not match');
    }
  }
}
