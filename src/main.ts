import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ApiDocReady, logApplicationDetails, logServerReady } from './logger';
import { json } from 'express';
import { ValidationPipe } from '@nestjs/common';
import cookieParser from 'cookie-parser';
import { ConfigService } from '@nestjs/config';
import { configureCors } from './cors';
import { AllExceptionsFilter, HttpExceptionFilter } from './error';
import { setupSwagger } from './swagger';
import { join } from 'path';
const port: number = 3336;
const prefix: string = 'xam';
import { NestExpressApplication } from '@nestjs/platform-express';
async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);
  app.use(json({ limit: '50mb' }));

  // Register HttpExceptionFilter first
  app.useGlobalFilters(new HttpExceptionFilter());

  app.useGlobalPipes(
    new ValidationPipe({
      //TODO: IF needed uncomment
      // whitelist: true,
      // forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  setupSwagger(app);

  app.setGlobalPrefix(prefix);

  const configService = app.get(ConfigService);

  configureCors(app, configService);

  app.use(cookieParser());
  // Register AllExceptionsFilter after HttpExceptionFilter
  app.useGlobalFilters(new HttpExceptionFilter(), new AllExceptionsFilter());
  // Serve static files
  app.useStaticAssets(join(__dirname, '..', 'public'));
  await app.listen(configService.get('PORT') || port, '0.0.0.0');
  return configService;
}

bootstrap().then((configService) => {
  logServerReady(configService.get('PORT') || port);
  logApplicationDetails(configService);
  ApiDocReady(configService.get('port') || port, configService);
});
