import { IsString, MinLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export abstract class PasswordDto {
  @ApiProperty({
    description: 'The password of the user',
    minLength: 1,
    type: String
  })
  @IsString()
  @MinLength(1)
  public password: string;
}
