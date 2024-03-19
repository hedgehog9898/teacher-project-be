import { IsString, MinLength } from 'class-validator';
import { SinglePasswordDto } from './passwords.dto';
import { ApiProperty } from '@nestjs/swagger';

export abstract class ChangePasswordDto extends SinglePasswordDto {
  @ApiProperty({
    description: 'The current password',
    minLength: 1,
    type: String,
  })
  @IsString()
  @MinLength(1)
  public changedPassword!: string;
}