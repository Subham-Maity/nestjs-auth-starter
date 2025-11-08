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
  ForgotPasswordSuperAdminDto,
  QueryUserActivityDto,
  ResetPasswordSuperAdminDto,
  SuperAdminLoginDto,
  SuperAdminRegisterDto,
  VerifyOtpSuperAdminDto,
} from '../../dto';
import {
  CommonAuthRepository,
  SuperAdminAuthRepository,
  UserActivityRepository,
} from '../../repository';
import { EmailService } from '../../../email/service';
import { CommonAuthService } from '../common/common-auth.service';
import { Request } from 'express';
import { Config, getExpiryDate } from '../../../common';

@Injectable()
export class SuperAdminAuthService {
  private readonly logger = new Logger(SuperAdminAuthService.name);
  private readonly MAX_OTP_ATTEMPTS = 5;
  private readonly OTP_EXPIRY_MINUTES = 5;

  constructor(
    private commonRepository: CommonAuthRepository,
    private superAdminRepository: SuperAdminAuthRepository,
    @Inject(forwardRef(() => CommonAuthService))
    private commonService: CommonAuthService,
    private configService: ConfigService,
    private emailService: EmailService,
    private userActivityRepository: UserActivityRepository,
  ) {}

  /**
   * Register a new super admin - sends OTP for email verification
   * FIXED: Account created in PENDING_VERIFICATION state
   */
  async registerSuperAdmin(dto: SuperAdminRegisterDto) {
    const { email, password, firstName, lastName } = dto;

    // Check if email already exists with verified account
    const existingUser =
      await this.superAdminRepository.findSuperAdminByEmail(email);

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
            this.superAdminRepository.deleteSuperAdmin(existingUser.id),
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

    // Create super admin user in PENDING state
    const superAdmin = await this.superAdminRepository.createSuperAdmin({
      email,
      password: hashedPassword,
      firstName,
      lastName,
      accountStatus: AccountStatus.PENDING_VERIFICATION,
      isActive: false,
      isEmailVerified: false,
    });

    // Generate OTP
    const otp = this.generateOtp();
    const expiresAt = this.getOtpExpiry();

    // Store OTP with purpose and user link
    await this.commonRepository.createOrUpdateOtpEmail(
      email,
      otp,
      expiresAt,
      'REGISTRATION',
      superAdmin.id,
      superAdmin.id, // createdById - user creating their own OTP
    );

    // Send OTP email
    await this.sendOtpEmail(email, otp, 'Registration');

    this.logger.log(`Super Admin registration initiated for: ${email}`);

    return {
      message: 'Registration successful. OTP sent to your email.',
      superAdmin: {
        id: superAdmin.id,
        email: superAdmin.email,
        firstName: superAdmin.firstName,
        lastName: superAdmin.lastName,
        accountStatus: superAdmin.accountStatus,
      },
    };
  }

  /**
   * Verify OTP for registration - completes the registration process
   * FIXED: Different logic from login OTP - activates account
   */
  async verifyOtpForRegistration(dto: VerifyOtpSuperAdminDto, req?: Request) {
    const { email, otp } = dto;

    const user = await this.superAdminRepository.findSuperAdminByEmail(email);
    if (!user || user.role !== Role.SUPER_ADMIN) {
      throw new NotFoundException('Super Admin not found');
    }

    // Check account status
    if (user.accountStatus !== AccountStatus.PENDING_VERIFICATION) {
      throw new BadRequestException(
        'Account already verified or invalid state',
      );
    }

    // Find active OTP with purpose check
    const otpRecord = await this.commonRepository.findActiveOtpByEmail(
      email,
      'REGISTRATION',
    );

    if (!otpRecord) {
      throw new UnauthorizedException('No active OTP found for registration');
    }

    // Check if OTP expired
    if (otpRecord.expiresAt < new Date()) {
      // Clean up expired registration
      await Promise.all([
        this.superAdminRepository.deleteSuperAdmin(user.id),
        this.commonRepository.deleteOtpRecord(otpRecord.id),
      ]);
      throw new UnauthorizedException(
        'OTP expired. Your registration has been cancelled. Please register again.',
      );
    }

    // Check max attempts
    if (otpRecord.attempts >= otpRecord.maxAttempts) {
      // Clean up after max attempts
      await Promise.all([
        this.superAdminRepository.deleteSuperAdmin(user.id),
        this.commonRepository.deleteOtpRecord(otpRecord.id),
      ]);
      throw new UnauthorizedException(
        'Maximum OTP attempts exceeded. Your registration has been cancelled. Please register again.',
      );
    }

    // Verify OTP
    if (otpRecord.otp !== otp) {
      // Increment attempts
      await this.commonRepository.incrementOtpAttempts(otpRecord.id);
      const remainingAttempts =
        otpRecord.maxAttempts - (otpRecord.attempts + 1);
      throw new UnauthorizedException(
        `Invalid OTP. ${remainingAttempts} attempt(s) remaining.`,
      );
    }

    // ✅ OTP verified successfully
    // Mark OTP as verified and used
    await this.commonRepository.markOtpAsVerified(otpRecord.id, user.id);

    // Activate account
    await this.superAdminRepository.activateSuperAdmin(user.id);

    // Generate tokens
    const tokens = await this.commonService.generateTokens({
      id: user.id,
      email: user.email,
      role: user.role,
      firstName: user.firstName,
      lastName: user.lastName,
      name: user.name,
      img: user.img,
    });

    // Store hashed refresh token
    await this.superAdminRepository.updateRtHash(
      user.id,
      tokens.hashed_refresh_token,
    );

    this.logger.log(
      `Super Admin registration completed and activated: ${email}`,
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
    // Return tokens separately for controller to set as cookies
    return {
      message: 'Email verified successfully. Your account is now active.',
      tokens: {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
      },
    };
  }

  /**
   * Login super admin - sends OTP for 2FA
   * FIXED: Only works for verified accounts
   */
  async loginSuperAdmin(dto: SuperAdminLoginDto, req?: Request) {
    const { email, password } = dto;

    const user = await this.superAdminRepository.findSuperAdminByEmail(email);

    if (!user || user.role !== Role.SUPER_ADMIN) {
      await this.logFailedLoginActivity(email, 'Invalid credentials', req);
      throw new UnauthorizedException('Invalid credentials');
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

    this.logger.log(`Super Admin login OTP sent to: ${email}`);

    return {
      message: 'OTP sent to your email',
    };
  }

  /**
   * Verify OTP for login - issues tokens
   * FIXED: Different from registration - only authenticates
   */
  async verifyOtpForLogin(dto: VerifyOtpSuperAdminDto, req?: Request) {
    const { email, otp } = dto;

    const user = await this.superAdminRepository.findSuperAdminByEmail(email);
    if (!user || user.role !== Role.SUPER_ADMIN) {
      throw new NotFoundException('Super Admin not found');
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

    // ✅ Check if locked out
    if (otpRecord.lockedUntil && otpRecord.lockedUntil > new Date()) {
      const remainingMinutes = Math.ceil(
        (otpRecord.lockedUntil.getTime() - Date.now()) / (1000 * 60),
      );
      throw new UnauthorizedException(
        `Too many failed attempts. Please try again after ${remainingMinutes} minute(s).`,
      );
    }

    // Check if OTP expired
    if (otpRecord.expiresAt < new Date()) {
      await this.commonRepository.deleteOtpRecord(otpRecord.id);
      throw new UnauthorizedException('OTP expired. Please request a new one.');
    }

    // ✅ Check if max attempts reached (will lock after this increment)
    if (otpRecord.attempts >= Config.otp.maxAttempts) {
      throw new UnauthorizedException(
        `Maximum OTP attempts exceeded. Please wait ${Config.otp.lockoutMinutes} minutes and request a new OTP.`,
      );
    }

    // Verify OTP
    if (otpRecord.otp !== otp) {
      // ✅ Increment attempts (will set lockout if max reached)
      const updatedOtp = await this.commonRepository.incrementOtpAttempts(
        otpRecord.id,
      );

      const remainingAttempts = Config.otp.maxAttempts - updatedOtp.attempts;

      if (remainingAttempts <= 0) {
        throw new UnauthorizedException(
          `Maximum OTP attempts exceeded. Please wait ${Config.otp.lockoutMinutes} minutes and request a new OTP.`,
        );
      }

      throw new UnauthorizedException(
        `Invalid OTP. ${remainingAttempts} attempt(s) remaining.`,
      );
    }

    // ✅ OTP verified successfully - mark as verified and delete
    await this.commonRepository.markOtpAsVerified(otpRecord.id, user.id);

    // Generate tokens
    const tokens = await this.commonService.generateTokens({
      id: user.id,
      email: user.email,
      role: user.role,
      firstName: user.firstName,
      lastName: user.lastName,
      name: user.name,
      img: user.img,
    });

    await this.superAdminRepository.updateRtHash(
      user.id,
      tokens.hashed_refresh_token,
    );

    const sessionId = crypto.randomBytes(16).toString('hex');
    await this.logLoginActivity(
      { id: user.id, email: user.email, role: user.role },
      sessionId,
      req,
    );

    this.logger.log(`Super Admin logged in: ${email}`);

    return {
      message: 'Login successful',
      tokens: {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
      },
    };
  }

  /**
   * Forgot password - sends OTP to email
   */
  async forgotPassword(dto: ForgotPasswordSuperAdminDto) {
    const { email } = dto;

    const user = await this.superAdminRepository.findSuperAdminByEmail(email);
    if (!user || user.role !== Role.SUPER_ADMIN) {
      throw new NotFoundException('Super Admin not found');
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
      user.id, // createdById
    );

    // Send email
    await this.sendOtpEmail(email, otp, 'Password Reset');

    this.logger.log(`Password reset OTP sent to: ${email}`);

    return {
      message: 'OTP sent to your email for password reset',
    };
  }

  /**
   * Verify forgot password OTP - returns reset token
   */
  async verifyForgotPasswordOtp(dto: VerifyOtpSuperAdminDto) {
    const { email, otp } = dto;

    const user = await this.superAdminRepository.findSuperAdminByEmail(email);
    if (!user || user.role !== Role.SUPER_ADMIN) {
      throw new NotFoundException('Super Admin not found');
    }

    // Find active OTP with purpose check
    const otpRecord = await this.commonRepository.findActiveOtpByEmail(
      email,
      'PASSWORD_RESET',
    );

    if (!otpRecord) {
      throw new UnauthorizedException('No active OTP found for password reset');
    }

    // Check if expired
    if (otpRecord.expiresAt < new Date()) {
      await this.commonRepository.deleteOtpRecord(otpRecord.id);
      throw new UnauthorizedException('OTP expired. Please request a new one.');
    }

    // Check max attempts
    if (otpRecord.attempts >= otpRecord.maxAttempts) {
      await this.commonRepository.deleteOtpRecord(otpRecord.id);
      throw new UnauthorizedException(
        'Maximum OTP attempts exceeded. Please try again.',
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

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpiresAt = getExpiryDate(15); // ✅ 15 minutes from config

    // Save reset token, mark OTP as verified
    await Promise.all([
      this.superAdminRepository.updateResetToken(
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

  async resetPassword(dto: ResetPasswordSuperAdminDto) {
    const { resetToken, newPassword } = dto;

    // Find user by reset token
    const user =
      await this.superAdminRepository.findUserByResetToken(resetToken);
    if (!user || user.role !== Role.SUPER_ADMIN) {
      throw new UnauthorizedException('Invalid or expired reset token');
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    if (!user.email) {
      throw new UnauthorizedException('No email found');
    }

    // Update password and clear reset token
    await Promise.all([
      this.superAdminRepository.updateResetToken(user.email, null, null),
      this.superAdminRepository.updateSuperAdminPassword(
        user.id,
        hashedPassword,
      ),
    ]);

    this.logger.log(`Password reset successfully for: ${user.email}`);

    return {
      message: 'Password reset successfully',
    };
  }

  async logout(userId: string, sessionId?: string) {
    await this.logLogoutActivity(userId, sessionId);
    await this.commonService.logout(userId);
    this.logger.log(`Super Admin logged out: ${userId}`);
    return { message: 'Logged out successfully' };
  }

  /**
   * Get user activities with filters
   */
  async getUserActivities(query: QueryUserActivityDto) {
    return this.userActivityRepository.findActivities(query);
  }

  /**
   * Get user activity statistics
   */
  async getUserActivityStats(userId: string) {
    return this.userActivityRepository.getUserActivityStats(userId);
  }

  private generateOtp(): string {
    const isTestMode = this.configService.get('TEST_OTP_PRODUCTION') !== 'true';

    return isTestMode
      ? '000000'
      : generateOTP({
          length: Config.otp.length,
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
        `Super Admin ${purpose} OTP`,
      );
    }
  }

  /**
   * Helper: Parse request details
   */
  private parseRequestDetails(req: Request) {
    const userAgent = req.headers['user-agent'] || '';
    const ipAddress =
      (req.headers['x-forwarded-for'] as string)?.split(',')[0] ||
      (req.headers['x-real-ip'] as string) ||
      req.socket.remoteAddress ||
      '';

    // Basic device type detection
    let deviceType = 'desktop';
    if (/mobile/i.test(userAgent)) deviceType = 'mobile';
    else if (/tablet/i.test(userAgent)) deviceType = 'tablet';

    // Basic browser detection
    let browser = 'Unknown';
    if (/chrome/i.test(userAgent)) browser = 'Chrome';
    else if (/firefox/i.test(userAgent)) browser = 'Firefox';
    else if (/safari/i.test(userAgent)) browser = 'Safari';
    else if (/edge/i.test(userAgent)) browser = 'Edge';

    // Basic OS detection
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

  /**
   * Log login activity
   */
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

  /**
   * Log logout activity
   */
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

  /**
   * Log failed login activity
   */
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
