import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ConfigModule } from '@nestjs/config';
import { config } from './config';
import { validationSchema } from './config/config.schema';
import { MikroOrmModule } from '@mikro-orm/nestjs';
import { MikroOrmConfig } from './config/mikro-orm.config';
import { JwtModule } from './jwt/jwt.module';
import { MailerModule } from './mailer/mailer.module';
import { AuthModule } from './auth/auth.module';
import { CacheModule } from '@nestjs/common/cache';
import { CacheConfig } from './config/cache.config';
import { CommonModule } from './common/common.module';
import { UsersModule } from './users/users.module';
import { APP_GUARD } from '@nestjs/core';
import { AuthGuard } from './auth/guards/auth.guard';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      validationSchema,
      load: [config]
    }),
    MikroOrmModule.forRootAsync({
      imports: [ConfigModule],
      useClass: MikroOrmConfig
    }),
    // TODO: Rewrite with https://docs.nestjs.com/techniques/caching
    CacheModule.registerAsync({
      isGlobal: true,
      imports: [ConfigModule],
      useClass: CacheConfig
    }),
    CommonModule,
    UsersModule,
    AuthModule,
    JwtModule,
    MailerModule
  ],
  controllers: [AppController],
  providers: [AppService, { provide: APP_GUARD, useClass: AuthGuard }]
})
export class AppModule {}
