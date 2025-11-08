import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { PrismaModule } from './prisma';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { LoggerMiddleware } from './logger';
import { AuthModule } from './auth';
import { JwtModule } from '@nestjs/jwt';

import { APP_FILTER } from '@nestjs/core';
import { HttpExceptionFilter } from './error';

import { MulterModule } from '@nestjs/platform-express';

import { ScheduleModule } from '@nestjs/schedule';

import { EmailModule } from './email';
import { validateConfig } from './validate/env.validation';

// For everything
LoggerMiddleware.configure({
  logRequest: true,
  logHeaders: false,
  logBody: true,
  logResponse: true,
  logLatency: true,
  logUserAgent: true,
  logIP: true,
  logProtocol: true,
});

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      cache: true,
      validationSchema: validateConfig,
    }),
    ScheduleModule.forRoot(),

    JwtModule.registerAsync({
      imports: [
        ConfigModule,
        MulterModule.register({
          dest: './uploads',
        }),
      ],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_SECRET'),
        signOptions: {
          expiresIn: '1h',
        },
      }),
      inject: [ConfigService],
    }),
    PrismaModule,
    AuthModule,
    EmailModule,
  ],
  controllers: [AppController],
  providers: [
    AppService,
    {
      provide: APP_FILTER,
      useClass: HttpExceptionFilter,
    },
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(LoggerMiddleware).forRoutes('*');
  }
}
