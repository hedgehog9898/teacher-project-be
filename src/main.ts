import { ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import { ConfigService } from '@nestjs/config';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { MikroORM } from '@mikro-orm/core';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);

  // Swagger
  const config = new DocumentBuilder()
    .setTitle('German language teacher')
    .setDescription('The German language teacher project description')
    .setVersion('1.0')
    .addBearerAuth()
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document);

  if (process.env.NODE_ENV !== 'production') {
    // ORM Initial setup (only for Development)
    await app.get(MikroORM).getSchemaGenerator().ensureDatabase();
    await app.get(MikroORM).getSchemaGenerator().updateSchema();
  }

  app.enableCors({
    origin: 'http://localhost:3000', // adjust the URL if needed
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE'
  });
  app.use(cookieParser(configService.get<string>('COOKIE_SECRET')));
  app.use(helmet());
  app.enableCors({
    credentials: true,
    origin: `https://${configService.get<string>('domain')}`
  });
  app.useGlobalPipes(
    new ValidationPipe({
      transform: true
    }),
  );
  await app.listen(configService.get<number>('port'));
}
bootstrap();
