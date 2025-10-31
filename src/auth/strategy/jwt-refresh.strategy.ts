import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Request } from 'express';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { JwtPayload } from './jwt.strategy';

@Injectable()
export class JwtRefreshStrategy extends PassportStrategy(
  Strategy,
  'jwt-refresh',
) {
  constructor(private configService: ConfigService) {
    const rtSecret = configService.get<string>('RT_SECRET');

    if (!rtSecret) {
      throw new Error('RT_SECRET is not defined in environment variables');
    }

    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        // 1. Extract from Authorization header
        ExtractJwt.fromAuthHeaderAsBearerToken(),
        // 2. Extract from HTTP-only cookie
        (request) => {
          return request?.cookies?.refresh_token;
        },
      ]),
      ignoreExpiration: false,
      secretOrKey: rtSecret,
      passReqToCallback: true, // Pass request to validate method to extract refresh token
    });
  }

  async validate(req: Request, payload: JwtPayload) {
    // Extract refresh token from request
    const refreshToken =
      req?.cookies?.refresh_token ||
      req?.get('authorization')?.replace('Bearer', '').trim();

    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token not found');
    }

    // Return payload with refresh token for use in service
    return {
      ...payload,
      refreshToken,
    };
  }
}
