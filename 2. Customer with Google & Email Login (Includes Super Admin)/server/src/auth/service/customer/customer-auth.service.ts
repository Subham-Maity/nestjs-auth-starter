import {
  BadRequestException,
  forwardRef,
  Inject,
  Injectable,
  Logger,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import { ConfigService } from '@nestjs/config';
import { AccountStatus, ActivityType, Role } from '@prisma/client';
import { generateOTP } from '../../otp';
import {
  CustomerLoginDto,
  CustomerRegisterDto,
  ForgotPasswordCustomerDto,
  ResetPasswordCustomerDto,
  VerifyOtpCustomerDto,
} from '../../dto';
import {
  CommonAuthRepository,
  CustomerAuthRepository,
  UserActivityRepository,
} from '../../repository';
import { EmailService } from '../../../email/service';
import { CommonAuthService } from '../common/common-auth.service';
import { Request } from 'express';
import { Config, getExpiryDate } from '../../../common';

@Injectable()
export class CustomerAuthService {
  private readonly logger = new Logger(CustomerAuthService.name);
  private readonly MAX_OTP_ATTEMPTS = Config.otp.maxAttempts;
  private readonly OTP_EXPIRY_MINUTES = Config.otp.expiryMinutes;

  constructor(
    private commonRepository: CommonAuthRepository,
    private customerRepository: CustomerAuthRepository,
    @Inject(forwardRef(() => CommonAuthService))
    private commonService: CommonAuthService,
    private configService: ConfigService,
    private emailService: EmailService,
    private userActivityRepository: UserActivityRepository,
  ) {}

  /**
   * Register a new customer - sends OTP for email verification
   */
  async registerCustomer(dto: CustomerRegisterDto) {
    const { email, password, firstName, lastName, phone } = dto;

    // Check if email already exists with verified account
    const existingUser =
      await this.customerRepository.findCustomerByEmail(email);

    if (existingUser) {
      // If account is pending and OTP expired, clean it up
      if (existingUser.accountStatus === AccountStatus.PENDING_VERIFICATION) {
        const otpRecord = await this.commonRepository.findActiveOtpByEmail(
          email,
          'REGISTRATION',
        );

        if (!otpRecord) {
          // No active OTP - clean up the pending user
          await Promise.all([
            this.customerRepository.deleteCustomer(existingUser.id),
            this.commonRepository.deleteUserOtps(existingUser.id),
          ]);
          this.logger.log(`Cleaned up expired registration for: ${email}`);
        } else {
          throw new BadRequestException(
            'Registration already in progress. Please verify your email or wait for OTP to expire.',
          );
        }
      } else {
        throw new BadRequestException('Email already registered');
      }
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create customer in PENDING state
    const customer = await this.customerRepository.createCustomer({
      email,
      password: hashedPassword,
      firstName,
      lastName,
      phone,
      accountStatus: AccountStatus.PENDING_VERIFICATION,
      isActive: false,
      isEmailVerified: false,
    });

    // Generate OTP
    const otp = this.generateOtp();
    const expiresAt = this.getOtpExpiry();

    // Store OTP
    await this.commonRepository.createOrUpdateOtpEmail(
      email,
      otp,
      expiresAt,
      'REGISTRATION',
      customer.id,
      customer.id,
    );

    // Send OTP email
    await this.sendOtpEmail(email, otp, 'Registration');

    this.logger.log(`Customer registration initiated for: ${email}`);

    return {
      message: 'Registration successful. OTP sent to your email.',
      customer: {
        id: customer.id,
        email: customer.email,
        firstName: customer.firstName,
        lastName: customer.lastName,
        role: customer.role,
      },
    };
  }

  /**
   * Verify OTP for registration - completes the registration process
   */
  async verifyOtpForRegistration(dto: VerifyOtpCustomerDto, req?: Request) {
    const { email, otp } = dto;

    const user = await this.customerRepository.findCustomerByEmail(email);
    if (!user || user.role !== Role.CUSTOMER) {
      throw new NotFoundException('Customer not found');
    }

    // Check account status
    if (user.accountStatus !== AccountStatus.PENDING_VERIFICATION) {
      throw new BadRequestException(
        'Account already verified or invalid state',
      );
    }

    // Find active OTP
    const otpRecord = await this.commonRepository.findActiveOtpByEmail(
      email,
      'REGISTRATION',
    );

    if (!otpRecord) {
      throw new UnauthorizedException('No active OTP found for registration');
    }

    // Check if OTP expired
    if (otpRecord.expiresAt < new Date()) {
      await Promise.all([
        this.customerRepository.deleteCustomer(user.id),
        this.commonRepository.deleteOtpRecord(otpRecord.id),
      ]);
      throw new UnauthorizedException(
        'OTP expired. Your registration has been cancelled. Please register again.',
      );
    }

    // Check max attempts
    if (otpRecord.attempts >= otpRecord.maxAttempts) {
      await Promise.all([
        this.customerRepository.deleteCustomer(user.id),
        this.commonRepository.deleteOtpRecord(otpRecord.id),
      ]);
      throw new UnauthorizedException(
        'Maximum OTP attempts exceeded. Your registration has been cancelled. Please register again.',
      );
    }

    // Verify OTP
    if (otpRecord.otp !== otp) {
      await this.commonRepository.incrementOtpAttempts(otpRecord.id);
      const remainingAttempts =
        otpRecord.maxAttempts - (otpRecord.attempts + 1);
      throw new UnauthorizedException(
        `Invalid OTP. ${remainingAttempts} attempt(s) remaining.`,
      );
    }

    // Mark OTP as verified
    await this.commonRepository.markOtpAsVerified(otpRecord.id, user.id);

    // Activate account
    await this.customerRepository.activateCustomer(user.id);

    // Generate tokens
    const tokens = await this.commonService.generateTokens({
      id: user.id,
      email: user.email,
      role: user.role,
      firstName: user.firstName,
      lastName: user.lastName,
      name: user.name,
      phone: user.phone,
      img: user.img,
      isPhoneVerified: user.isPhoneVerified,
    });

    // Store hashed refresh token
    await this.customerRepository.updateRtHash(
      user.id,
      tokens.hashed_refresh_token,
    );

    this.logger.log(`Customer registration completed: ${email}`);

    // Generate session ID
    const sessionId = crypto.randomBytes(16).toString('hex');

    // Log login activity
    await this.logLoginActivity(
      {
        id: user.id,
        email: user.email,
        role: user.role,
      },
      sessionId,
      req,
    );

    return {
      message: 'Email verified successfully. Your account is now active.',
      tokens: {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
      },
    };
  }

  /**
   * Login customer - sends OTP for 2FA
   */
  async loginCustomer(dto: CustomerLoginDto, req?: Request) {
    const { email, password } = dto;

    const user = await this.customerRepository.findCustomerByEmail(email);

    if (!user || user.role !== Role.CUSTOMER) {
      await this.logFailedLoginActivity(email, 'Invalid credentials', req);
      throw new UnauthorizedException('Invalid credentials');
    }

    // Check if user used Google OAuth
    if (user.authType === 'GOOGLE' && !user.password) {
      throw new UnauthorizedException(
        'This account uses Google Sign-In. Please login with Google.',
      );
    }

    // Check account status
    if (user.accountStatus === AccountStatus.PENDING_VERIFICATION) {
      throw new UnauthorizedException(
        'Please verify your email first. Check your inbox for the verification OTP.',
      );
    }

    if (user.accountStatus === AccountStatus.SUSPENDED) {
      throw new UnauthorizedException('Your account has been suspended');
    }

    if (!user.isActive) {
      throw new UnauthorizedException('Your account is inactive');
    }

    if (!user.password) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      await this.logFailedLoginActivity(email, 'Invalid password', req);
      throw new UnauthorizedException('Invalid credentials');
    }

    // Generate OTP for login
    const otp = this.generateOtp();
    const expiresAt = this.getOtpExpiry();

    await this.commonRepository.createOrUpdateOtpEmail(
      email,
      otp,
      expiresAt,
      'LOGIN',
      user.id,
    );

    await this.sendOtpEmail(email, otp, 'Login');

    this.logger.log(`Customer login OTP sent to: ${email}`);

    return {
      message: 'OTP sent to your email',
    };
  }

  /**
   * Verify OTP for login - issues tokens
   */
  async verifyOtpForLogin(dto: VerifyOtpCustomerDto, req?: Request) {
    const { email, otp } = dto;

    const user = await this.customerRepository.findCustomerByEmail(email);

    if (!user || user.role !== Role.CUSTOMER) {
      throw new NotFoundException('Customer not found');
    }

    if (user.accountStatus !== AccountStatus.ACTIVE) {
      throw new UnauthorizedException('Account not active');
    }

    // Find active OTP
    const otpRecord = await this.commonRepository.findActiveOtpByEmail(
      email,
      'LOGIN',
    );

    if (!otpRecord) {
      throw new UnauthorizedException('No active OTP found for login');
    }

    // Check if OTP expired
    if (otpRecord.expiresAt < new Date()) {
      await this.commonRepository.deleteOtpRecord(otpRecord.id);
      throw new UnauthorizedException('OTP expired. Please request a new one.');
    }

    // Check max attempts
    if (otpRecord.attempts >= otpRecord.maxAttempts) {
      await this.commonRepository.deleteOtpRecord(otpRecord.id);
      throw new UnauthorizedException(
        'Maximum OTP attempts exceeded. Please login again.',
      );
    }

    // Verify OTP
    if (otpRecord.otp !== otp) {
      await this.commonRepository.incrementOtpAttempts(otpRecord.id);
      const remainingAttempts =
        otpRecord.maxAttempts - (otpRecord.attempts + 1);
      throw new UnauthorizedException(
        `Invalid OTP. ${remainingAttempts} attempt(s) remaining.`,
      );
    }

    // Mark OTP as verified
    await this.commonRepository.markOtpAsVerified(otpRecord.id, user.id);

    // Generate tokens
    const tokens = await this.commonService.generateTokens({
      id: user.id,
      email: user.email,
      role: user.role,
      firstName: user.firstName,
      lastName: user.lastName,
      name: user.name,
      phone: user.phone,
      img: user.img,
      isPhoneVerified: user.isPhoneVerified,
    });

    // Store hashed refresh token
    await this.customerRepository.updateRtHash(
      user.id,
      tokens.hashed_refresh_token,
    );

    // Generate session ID
    const sessionId = crypto.randomBytes(16).toString('hex');

    // Log login activity
    await this.logLoginActivity(
      {
        id: user.id,
        email: user.email,
        role: user.role,
      },
      sessionId,
      req,
    );

    this.logger.log(`Customer logged in: ${email}`);

    return {
      message: 'Login successful',
      tokens: {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
      },
    };
  }

  /**
   * Google OAuth login
   */
  async googleLogin(googleUser: any, req?: Request) {
    const { email, firstName, lastName, picture } = googleUser;

    // Upsert user
    const user = await this.customerRepository.upsertGoogleUser({
      email,
      firstName,
      lastName,
      img: picture,
    });

    // Generate tokens
    const tokens = await this.commonService.generateTokens({
      id: user.id,
      email: user.email,
      role: user.role,
      firstName: user.firstName,
      lastName: user.lastName,
      name: user.name,
      phone: user.phone,
      img: user.img,
      isPhoneVerified: user.isPhoneVerified,
    });

    // Store hashed refresh token
    await this.customerRepository.updateRtHash(
      user.id,
      tokens.hashed_refresh_token,
    );

    // Generate session ID
    const sessionId = crypto.randomBytes(16).toString('hex');

    // Log login activity
    await this.logLoginActivity(
      {
        id: user.id,
        email: user.email,
        role: user.role,
      },
      sessionId,
      req,
    );

    this.logger.log(`Customer logged in via Google: ${email}`);

    return {
      message: 'Login successful',
      tokens: {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
      },
    };
  }

  /**
   * Forgot password - sends OTP
   */
  async forgotPassword(dto: ForgotPasswordCustomerDto) {
    const { email } = dto;

    const user = await this.customerRepository.findCustomerByEmail(email);
    if (!user || user.role !== Role.CUSTOMER) {
      throw new NotFoundException('Customer not found');
    }

    // Generate OTP
    const otp = this.generateOtp();
    const expiresAt = this.getOtpExpiry();

    await this.commonRepository.createOrUpdateOtpEmail(
      email,
      otp,
      expiresAt,
      'PASSWORD_RESET',
      user.id,
      user.id,
    );

    await this.sendOtpEmail(email, otp, 'Password Reset');

    this.logger.log(`Password reset OTP sent to: ${email}`);

    return {
      message: 'OTP sent to your email for password reset',
    };
  }

  /**
   * Verify forgot password OTP - returns reset token
   */
  async verifyForgotPasswordOtp(dto: VerifyOtpCustomerDto) {
    const { email, otp } = dto;

    const user = await this.customerRepository.findCustomerByEmail(email);
    if (!user || user.role !== Role.CUSTOMER) {
      throw new NotFoundException('Customer not found');
    }

    const otpRecord = await this.commonRepository.findActiveOtpByEmail(
      email,
      'PASSWORD_RESET',
    );

    if (!otpRecord) {
      throw new UnauthorizedException('No active OTP found for password reset');
    }

    if (otpRecord.expiresAt < new Date()) {
      await this.commonRepository.deleteOtpRecord(otpRecord.id);
      throw new UnauthorizedException('OTP expired. Please request a new one.');
    }

    if (otpRecord.attempts >= otpRecord.maxAttempts) {
      await this.commonRepository.deleteOtpRecord(otpRecord.id);
      throw new UnauthorizedException(
        'Maximum OTP attempts exceeded. Please try again.',
      );
    }

    if (otpRecord.otp !== otp) {
      await this.commonRepository.incrementOtpAttempts(otpRecord.id);
      const remainingAttempts =
        otpRecord.maxAttempts - (otpRecord.attempts + 1);
      throw new UnauthorizedException(
        `Invalid OTP. ${remainingAttempts} attempt(s) remaining.`,
      );
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpiresAt = getExpiryDate(15);
    resetTokenExpiresAt.setMinutes(resetTokenExpiresAt.getMinutes() + 15);

    await Promise.all([
      this.customerRepository.updateResetToken(
        email,
        resetToken,
        resetTokenExpiresAt,
      ),
      this.commonRepository.markOtpAsVerified(otpRecord.id, user.id),
    ]);

    this.logger.log(`Password reset token generated for: ${email}`);

    return {
      message: 'OTP verified successfully',
      data: {
        resetToken,
      },
    };
  }

  /**
   * Reset password
   */
  async resetPassword(dto: ResetPasswordCustomerDto) {
    const { resetToken, newPassword } = dto;

    const user = await this.customerRepository.findUserByResetToken(resetToken);
    if (!user || user.role !== Role.CUSTOMER) {
      throw new UnauthorizedException('Invalid or expired reset token');
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    if (!user.email) {
      throw new UnauthorizedException('No email found');
    }

    await Promise.all([
      this.customerRepository.updateResetToken(user.email, null, null),
      this.customerRepository.updateCustomerPassword(user.id, hashedPassword),
    ]);

    this.logger.log(`Password reset successfully for: ${user.email}`);

    return {
      message: 'Password reset successfully',
    };
  }

  /**
   * Logout
   */
  async logout(userId: string, sessionId?: string) {
    await this.logLogoutActivity(userId, sessionId);
    await this.commonService.logout(userId);
    this.logger.log(`Customer logged out: ${userId}`);
    return { message: 'Logged out successfully' };
  }

  // Helper methods
  private generateOtp(): string {
    const isTestMode = this.configService.get('TEST_OTP_PRODUCTION') !== 'true';

    return isTestMode
      ? '000000'
      : generateOTP({
          length: 6,
          type: 'string',
          digits: true,
          lowerCaseAlphabets: false,
          upperCaseAlphabets: false,
          specialChars: false,
        });
  }

  private getOtpExpiry(): Date {
    const expiresAt = new Date();
    expiresAt.setMinutes(expiresAt.getMinutes() + this.OTP_EXPIRY_MINUTES);
    return expiresAt;
  }

  private async sendOtpEmail(email: string, otp: string, purpose: string) {
    const isTestMode = this.configService.get('TEST_OTP_PRODUCTION') !== 'true';

    if (!isTestMode) {
      await this.emailService.sendDirectEmail(
        `Your OTP for ${purpose} is: ${otp}. It is valid for ${this.OTP_EXPIRY_MINUTES} minutes.`,
        email,
        `Customer ${purpose} OTP`,
      );
    }
  }

  private parseRequestDetails(req: Request) {
    const userAgent = req.headers['user-agent'] || '';
    const ipAddress =
      (req.headers['x-forwarded-for'] as string)?.split(',')[0] ||
      (req.headers['x-real-ip'] as string) ||
      req.socket.remoteAddress ||
      '';

    let deviceType = 'desktop';
    if (/mobile/i.test(userAgent)) deviceType = 'mobile';
    else if (/tablet/i.test(userAgent)) deviceType = 'tablet';

    let browser = 'Unknown';
    if (/chrome/i.test(userAgent)) browser = 'Chrome';
    else if (/firefox/i.test(userAgent)) browser = 'Firefox';
    else if (/safari/i.test(userAgent)) browser = 'Safari';
    else if (/edge/i.test(userAgent)) browser = 'Edge';

    let os = 'Unknown';
    if (/windows/i.test(userAgent)) os = 'Windows';
    else if (/mac/i.test(userAgent)) os = 'MacOS';
    else if (/linux/i.test(userAgent)) os = 'Linux';
    else if (/android/i.test(userAgent)) os = 'Android';
    else if (/ios/i.test(userAgent)) os = 'iOS';

    return {
      ipAddress,
      userAgent,
      deviceType,
      browser,
      os,
    };
  }

  private async logLoginActivity(
    user: { id: string; email?: string | null; role: Role },
    sessionId: string,
    req?: Request,
  ) {
    const requestDetails = req ? this.parseRequestDetails(req) : {};

    const activity = await this.userActivityRepository.createActivity({
      userId: user.id,
      activityType: ActivityType.LOGIN,
      email: user.email || undefined,
      role: user.role,
      sessionId,
      loginAt: new Date(),
      isSuccessful: true,
      ...requestDetails,
    });

    return activity.id;
  }

  private async logLogoutActivity(userId: string, sessionId?: string) {
    const loginActivity =
      await this.userActivityRepository.findLatestLoginActivity(
        userId,
        sessionId,
      );

    if (loginActivity) {
      const duration = Math.floor(
        (new Date().getTime() - new Date(loginActivity.loginAt!).getTime()) /
          1000,
      );

      await this.userActivityRepository.updateActivity(loginActivity.id, {
        logoutAt: new Date(),
        duration,
      });
    }
  }

  private async logFailedLoginActivity(
    email: string,
    reason: string,
    req?: Request,
  ) {
    const requestDetails = req ? this.parseRequestDetails(req) : {};

    await this.userActivityRepository.createActivity({
      userId: undefined,
      activityType: ActivityType.FAILED_LOGIN,
      email,
      isSuccessful: false,
      failureReason: reason,
      ...requestDetails,
    });
  }
}
