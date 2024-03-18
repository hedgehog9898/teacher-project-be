import { IsString, Length, Matches, MinLength } from 'class-validator';
import { PASSWORD_REGEX } from '../../common/consts/regex.const';
import { ApiProperty } from '@nestjs/swagger';

export abstract class PasswordsDto {
  @ApiProperty({
    description: 'New password',
    minLength: 8,
    maxLength: 35,
    type: String,
  })
  @IsString()
  @Length(8, 35)
  @Matches(PASSWORD_REGEX, {
    message:
      'Password requires a lowercase letter, an uppercase letter, and a number or symbol',
  })
  @IsString()
  @Length(8, 35)
  @Matches(PASSWORD_REGEX, {
    message:
      'Password requires a lowercase letter, an uppercase letter, and a number or symbol',
  })
  public password!: string;

  @ApiProperty({
    description: 'Password confirmation',
    minLength: 8,
    maxLength: 35,
    type: String,
  })
  @IsString()
  @MinLength(1)
  public repeatedPassword!: string;
}