import { IsString, Length } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export abstract class GetUserParams {
  @ApiProperty({
    description: 'The id or username of the user',
    type: String,
    example: "56262 or 'username'",
  })
  @IsString()
  @Length(1, 106)
  public idOrUsername: string;
}