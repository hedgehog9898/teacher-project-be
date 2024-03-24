import { MikroOrmModuleOptions } from '@mikro-orm/nestjs';
import { IEmailConfig } from './email-config.interface';
import { IJwt } from './jwt.interface';
import { RedisOptions } from 'ioredis';
import { ThrottlerModuleOptions } from '@nestjs/throttler';

export interface IConfig {
  id: string;
  port: number;
  domain: string;
  db: MikroOrmModuleOptions;
  redis: RedisOptions;
  jwt: IJwt;
  emailService: IEmailConfig;
  throttler: ThrottlerModuleOptions;
  testing: boolean;
}
