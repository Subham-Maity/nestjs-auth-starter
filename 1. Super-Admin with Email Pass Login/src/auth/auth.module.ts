import { Module } from '@nestjs/common';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';

import { CommonAuthService, SuperAdminAuthService } from './service';
import {
  CommonAuthRepository,
  SuperAdminAuthRepository,
  UserActivityRepository,
} from './repository';
import { OtpCronService } from './cron';
import { JwtAuthGuard, JwtRefreshAuthGuard } from './guard';
import { JwtRefreshStrategy, JwtStrategy } from './strategy';
import { AuthController } from './controller';
import { minutes, ThrottlerModule } from '@nestjs/throttler';

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.registerAsync({
      global: true,
      imports: [
        ConfigModule,
        ThrottlerModule.forRoot({
          throttlers: [
            {
              ttl: minutes(1),
              limit: 5,
            },
          ],
        }),
      ],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_SECRET'),
        signOptions: { expiresIn: '2h' },
      }),
      inject: [ConfigService],
    }),
  ],
  controllers: [AuthController],
  providers: [
    JwtStrategy,
    JwtRefreshStrategy,
    JwtAuthGuard,
    JwtRefreshAuthGuard,
    CommonAuthRepository,
    SuperAdminAuthRepository,
    CommonAuthService,
    SuperAdminAuthService,
    OtpCronService,
    UserActivityRepository,
  ],
  exports: [
    CommonAuthService,
    SuperAdminAuthService,
    CommonAuthRepository,
    SuperAdminAuthRepository,
    JwtAuthGuard,
    JwtRefreshAuthGuard,
    JwtModule,
    PassportModule,
    UserActivityRepository,
  ],
})
export class AuthModule {}
