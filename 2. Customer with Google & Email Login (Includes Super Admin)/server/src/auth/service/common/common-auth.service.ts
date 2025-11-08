import {
  BadRequestException,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { Role } from '@prisma/client';
import { CommonAuthRepository } from '../../repository';
import { Config } from '../../../common';

@Injectable()
export class CommonAuthService {
  private readonly logger = new Logger(CommonAuthService.name);

  constructor(
    private commonRepository: CommonAuthRepository,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  /**
   * Generate JWT access and refresh tokens
   */
  async generateTokens(user: {
    id: string;
    email?: string | null;
    phone?: string | null;
    firstName?: string | null;
    lastName?: string | null;
    name?: string | null;
    role: Role | null;
    img?: string | null;
    isPhoneVerified?: boolean | null;
    deviceToken?: string | null;
  }) {
    // Get the user's default address if available
    const defaultAddress = await this.commonRepository.findUserDefaultAddress(
      user.id,
    );
    const addressInfo = defaultAddress
      ? { address: true, addressId: defaultAddress.id }
      : { address: false, addressId: null };

    const payload = {
      sub: user.id,
      email: user.email || undefined,
      firstName: user.firstName || undefined,
      lastName: user.lastName || undefined,
      name: user.name || undefined,
      role: user.role || undefined,
      isPhoneVerified: user.isPhoneVerified || undefined,
      img: user.img || undefined,
      address: addressInfo.address,
      addressId: addressInfo.addressId,
    };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload, {
        secret: this.configService.get<string>('JWT_SECRET'),
        expiresIn: Config.jwt.accessToken.expiresIn, // ✅ Use config
      }),
      this.jwtService.signAsync(payload, {
        secret: this.configService.get<string>('RT_SECRET'),
        expiresIn: Config.jwt.refreshToken.expiresIn, // ✅ Use config
      }),
    ]);

    const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
      hashed_refresh_token: hashedRefreshToken,
    };
  }

  /**
   * Refresh access token using refresh token
   */
  async refreshToken(rt: string) {
    try {
      // Verify and decode the refresh token to get userId
      const decoded = await this.jwtService.verifyAsync(rt, {
        secret: this.configService.get<string>('RT_SECRET'),
      });

      const user = await this.commonRepository.findById(decoded.sub);
      if (!user?.rtHash) {
        throw new UnauthorizedException('Access Denied');
      }

      const rtMatches = await bcrypt.compare(rt, user.rtHash);
      if (!rtMatches) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      const tokens = await this.generateTokens({
        id: user.id,
        phone: user.phone,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        name: user.name,
        role: user.role,
        isPhoneVerified: user.isPhoneVerified,
        img: user.img,
      });

      await this.commonRepository.updateRtHash(
        user.id,
        tokens.hashed_refresh_token,
      );

      return {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
      };
    } catch (error) {
      if (error instanceof UnauthorizedException) throw error;

      if (error.name === 'TokenExpiredError') {
        throw new UnauthorizedException('Refresh token expired');
      }
      if (error.name === 'JsonWebTokenError') {
        throw new UnauthorizedException('Invalid refresh token');
      }

      this.logger.error('Refresh token error:', error);
      throw new UnauthorizedException('Token validation failed');
    }
  }

  /**
   * Logout user by clearing refresh token
   */
  async logout(userId: string): Promise<void> {
    try {
      await this.commonRepository.updateRtHash(userId, null);
      this.logger.log(`Successfully logged out user: ${userId}`);
    } catch (error) {
      this.logger.error('Error during logout process:', error);
      throw error;
    }
  }

  /**
   * Check if user exists by phone or email
   */
  async checkUserExists(phone?: string, email?: string) {
    if (!phone && !email) {
      throw new BadRequestException('Either phone number or email is required');
    }
    const user = await this.commonRepository.checkUserExists(phone, email);
    return {
      exists: !!user,
    };
  }
}
