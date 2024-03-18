import { Embedded, Entity, PrimaryKey, Property } from '@mikro-orm/core';
import { IsBoolean, IsEmail, IsString, Length, Matches } from 'class-validator';
import {
  NAME_REGEX,
  SLUG_REGEX,
} from '../../common/consts/regex.const';
import { IUser } from '../interfaces/user.interface';
import { CredentialsEmbeddable } from '../embeddables/credentials.embeddable';

@Entity({ tableName: 'users' })
export class UserEntity implements IUser {
  @PrimaryKey()
  public id: number;

  @Property({ columnType: 'varchar', length: 100 })
  @IsString()
  @Length(3, 100)
  @Matches(NAME_REGEX, {
    message: 'Name must not have special characters',
  })
  public name: string;

  @Property({ columnType: 'varchar', length: 106 })
  @IsString()
  @Length(3, 106)
  @Matches(SLUG_REGEX, {
    message: 'Username must be a valid slugs',
  })
  public username: string;

  @Property({ columnType: 'varchar', length: 255 })
  @IsString()
  @IsEmail()
  @Length(5, 255)
  public email: string;

  @Property({ columnType: 'boolean', default: false })
  @IsBoolean()
  public confirmed: true | false = false; // since it is saved on the db as binary

  @Property({ columnType: 'varchar', length: 133 })
  @IsString()
  @Length(133, 134)
  public password: string;

  @Embedded(() => CredentialsEmbeddable)
  public credentials: CredentialsEmbeddable = new CredentialsEmbeddable();

  @Property({ onCreate: () => new Date() })
  public createdAt: Date = new Date();

  @Property({ onUpdate: () => new Date() })
  public updatedAt: Date = new Date();
}