import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { CommonAuthRepository } from '../repository';

export type JwtPayload = {
  sub: string;
  email?: string;
  phone?: string;
  firstName?: string;
  lastName?: string;
  name?: string;
  role: string;
  isPhoneVerified?: boolean;
  img?: string;
  storeId?: string;
  address?: boolean;
  addressId?: string;
  deviceToken?: string;
};

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(
    private configService: ConfigService,
    private commonRepository: CommonAuthRepository,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        ExtractJwt.fromAuthHeaderAsBearerToken(),
        (request) => request?.cookies?.access_token,
      ]),
      ignoreExpiration: false,
      secretOrKey: configService.getOrThrow<string>('JWT_SECRET'),
    });
  }

  async validate(payload: JwtPayload) {
    // Verify user still exists and is active
    const user = await this.commonRepository.findById(payload.sub);

    if (!user || !user.isActive) {
      throw new UnauthorizedException('User not found or inactive');
    }

    // Return user data that will be attached to request.user
    return {
      id: user.id,
      email: user.email,
      phone: user.phone,
      firstName: user.firstName,
      lastName: user.lastName,
      name: user.name,
      role: user.role,
      isPhoneVerified: user.isPhoneVerified,
      img: user.img,
      storeId: payload.storeId,
      address: payload.address,
      addressId: payload.addressId,
      deviceToken: payload.deviceToken,
    };
  }
}
