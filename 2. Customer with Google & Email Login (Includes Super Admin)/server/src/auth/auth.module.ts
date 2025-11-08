import { Module } from '@nestjs/common';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';

import {
  CommonAuthService,
  CustomerAuthService,
  SuperAdminAuthService,
} from './service';
import {
  CommonAuthRepository,
  CustomerAuthRepository,
  SuperAdminAuthRepository,
  UserActivityRepository,
} from './repository';
import { OtpCronService } from './cron';
import { GoogleAuthGuard, JwtAuthGuard, JwtRefreshAuthGuard } from './guard';
import { GoogleStrategy, JwtRefreshStrategy, JwtStrategy } from './strategy';
import { AuthController } from './controller';
import { minutes, ThrottlerModule } from '@nestjs/throttler';
import { Config } from '../common';

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
        signOptions: {
          expiresIn: Config.jwt.accessToken.expiresIn,
        },
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
    GoogleStrategy,
    GoogleAuthGuard,
    CustomerAuthRepository,
    CustomerAuthService,
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
    CustomerAuthService,
    CustomerAuthRepository,
    GoogleAuthGuard,
  ],
})
export class AuthModule {}
