import { IsString, Length } from 'class-validator';
import { PasswordsDto } from './passwords.dto';
import { ApiProperty } from '@nestjs/swagger';

export abstract class SignInDto extends PasswordsDto {
  @ApiProperty({
    description: 'Username or email',
    examples: ['john.doe', 'john.doe@gmail.com'],
    minLength: 3,
    maxLength: 255,
    type: String,
  })
  @IsString()
  @Length(3, 255)
  public emailOrUsername: string;
}