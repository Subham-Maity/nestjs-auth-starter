import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Logger,
  Param,
  Post,
  Query,
  Req,
  Res,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { Request, type Response } from 'express';

import {
  ApiBearerAuth,
  ApiBody,
  ApiOperation,
  ApiResponse,
} from '@nestjs/swagger';
import { CommonAuthRepository } from '../repository';
import {
  ForgotPasswordSuperAdminDto,
  ForgotPasswordSuperAdminResponseDto,
  ForgotPasswordVerifyOtpSuperAdminResponseDto,
  QueryUserActivityDto,
  ResetPasswordSuperAdminDto,
  ResetPasswordSuperAdminResponseDto,
  SuperAdminLoginDto,
  SuperAdminLoginResponseDto,
  SuperAdminRegisterDto,
  SuperAdminRegisterResponseDto,
  UserActivityListResponseDto,
  VerifyOtpSuperAdminDto,
} from '../dto';
import { CommonAuthService, SuperAdminAuthService } from '../service';
import { JwtAuthGuard } from '../guard';
import { ReqWithUser } from '../types';
import { Role } from '@prisma/client';

@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(
    private readonly commonService: CommonAuthService,
    private readonly commonRepository: CommonAuthRepository,
    private readonly superAdminService: SuperAdminAuthService,
  ) {}

  /**
   * 1. Register Super Admin - Send OTP
   */
  @Post('super-admin/register')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Register a new Super Admin',
    description:
      'Creates a Super Admin account and sends OTP to email for verification',
  })
  @ApiBody({ type: SuperAdminRegisterDto })
  @ApiResponse({
    status: HttpStatus.CREATED,
    description: 'Registration successful. OTP sent to email.',
    type: SuperAdminRegisterResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Email already registered or invalid input',
  })
  async registerSuperAdmin(@Body() dto: SuperAdminRegisterDto) {
    return this.superAdminService.registerSuperAdmin(dto);
  }

  /**
   * 2. Register Super Admin - Verify OTP
   */
  @Post('super-admin/register-verify-otp')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Verify OTP for Super Admin registration',
    description:
      'Completes registration by verifying OTP, activates account, and sets auth cookies',
  })
  @ApiBody({ type: VerifyOtpSuperAdminDto })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'OTP verified successfully. Registration completed.',
    schema: {
      type: 'object',
      properties: {
        message: {
          type: 'string',
          example: 'Email verified successfully. Your account is now active.',
        },
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Invalid or expired OTP',
  })
  async verifyRegistrationOtpSuperAdmin(
    @Body() dto: VerifyOtpSuperAdminDto,
    @Res({ passthrough: true }) res: Response,
    @Req() req: Request,
  ) {
    const result = await this.superAdminService.verifyOtpForRegistration(
      dto,
      req,
    );

    // Set tokens in HTTP-only cookies (tokens returned from service)
    res.cookie('access_token', result.tokens.access_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 2 * 60 * 60 * 1000, // 2 hours
    });

    res.cookie('refresh_token', result.tokens.refresh_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    return { message: result.message };
  }

  /**
   * 3. Login Super Admin - Send OTP
   */
  @Post('super-admin/login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Login Super Admin',
    description: 'Authenticates Super Admin and sends OTP for 2FA',
  })
  @ApiBody({ type: SuperAdminLoginDto })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'OTP sent to your email',
    type: SuperAdminLoginResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Invalid credentials or not a Super Admin',
  })
  async loginSuperAdmin(
    @Body() dto: SuperAdminLoginDto,
    req?: Request,
  ): Promise<SuperAdminLoginResponseDto> {
    return this.superAdminService.loginSuperAdmin(dto, req);
  }

  /**
   * 4. Login Super Admin - Verify OTP & Issue Tokens
   */
  @Post('super-admin/verify-otp')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Verify OTP for Super Admin login',
    description: 'Verifies OTP and sets authentication cookies',
  })
  @ApiBody({ type: VerifyOtpSuperAdminDto })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'OTP verified successfully. Login completed.',
    schema: {
      type: 'object',
      properties: {
        message: {
          type: 'string',
          example: 'Login successful',
        },
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Invalid or expired OTP',
  })
  async verifyLoginOtpSuperAdmin(
    @Body() dto: VerifyOtpSuperAdminDto,
    @Res({ passthrough: true }) res: Response,
    @Req() req: Request,
  ) {
    const result = await this.superAdminService.verifyOtpForLogin(dto, req);

    // Set tokens in HTTP-only cookies
    res.cookie('access_token', result.tokens.access_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 2 * 60 * 60 * 1000, // 2 hours
    });

    res.cookie('refresh_token', result.tokens.refresh_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });
    return { message: result.message };
  }

  /**
   * 5. Refresh Token (Common for all roles)
   */
  @Post('refresh-token')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Refresh access token',
    description:
      'Generates new access and refresh tokens using refresh token from cookie',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Tokens refreshed successfully',
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Invalid refresh token',
  })
  async refreshToken(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<{ message: string }> {
    const refreshToken = req.cookies.refresh_token;

    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token is required');
    }

    const tokens = await this.commonService.refreshToken(refreshToken);

    // Set new tokens as cookies
    res.cookie('access_token', tokens.access_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 2 * 60 * 60 * 1000, // 2 hours
    });

    res.cookie('refresh_token', tokens.refresh_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    return { message: 'Tokens refreshed successfully' };
  }

  /**
   * 6. Forgot Password - Send OTP
   */
  @Post('forgot-password/super-admin')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Initiate forgot password for Super Admin',
    description: 'Sends OTP to Super Admin email for password reset',
  })
  @ApiBody({ type: ForgotPasswordSuperAdminDto })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'OTP sent to your email',
    type: ForgotPasswordSuperAdminResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: 'Super Admin not found',
  })
  async forgotPasswordSuperAdmin(
    @Body() dto: ForgotPasswordSuperAdminDto,
  ): Promise<ForgotPasswordSuperAdminResponseDto> {
    return this.superAdminService.forgotPassword(dto);
  }

  /**
   * 7. Forgot Password - Verify OTP
   */
  @Post('forgot-password-verify-otp/super-admin')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Verify OTP for forgot password',
    description: 'Verifies OTP and returns reset token',
  })
  @ApiBody({ type: VerifyOtpSuperAdminDto })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'OTP verified successfully',
    type: ForgotPasswordVerifyOtpSuperAdminResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Invalid or expired OTP',
  })
  async verifyForgotPasswordOtpSuperAdmin(
    @Body() dto: VerifyOtpSuperAdminDto,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ForgotPasswordVerifyOtpSuperAdminResponseDto> {
    const result = await this.superAdminService.verifyForgotPasswordOtp(dto);

    // Set reset token in HTTP-only cookie
    res.cookie('reset_token', result.data.resetToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000, // 15 minutes
    });

    return result;
  }

  /**
   * 8. Reset Password
   */
  @Post('reset-password/super-admin')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Reset password for Super Admin',
    description: 'Resets password using valid reset token',
  })
  @ApiBody({ type: ResetPasswordSuperAdminDto })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Password reset successfully',
    type: ResetPasswordSuperAdminResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Invalid or expired reset token',
  })
  async resetPasswordSuperAdmin(
    @Body() dto: ResetPasswordSuperAdminDto,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ResetPasswordSuperAdminResponseDto> {
    const result = await this.superAdminService.resetPassword(dto);

    // Clear reset token cookie
    res.clearCookie('reset_token');

    return result;
  }

  /**
   * 9. Get Current User (Already exists - just use JwtAuthGuard)
   * Update existing /auth/me route to use JwtAuthGuard instead of AuthGuard
   */
  @Get('me')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthGuard)
  @ApiOperation({
    summary: 'Get current user',
    description: 'Retrieve currently authenticated user information',
  })
  @ApiBearerAuth()
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Current user information retrieved successfully',
  })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: 'Unauthorized' })
  async me(@Req() req: ReqWithUser) {
    if (!req.user.id) {
      throw new UnauthorizedException('User not found in request');
    }
    // Find the default address for the user
    const defaultAddress = await this.commonRepository.findUserDefaultAddress(
      req.user.id,
    );
    const addressInfo = defaultAddress
      ? { address: true, addressId: defaultAddress.id }
      : { address: false, addressId: null };

    return {
      id: req.user.id,
      email: req.user.email,
      phone: req.user.phone,
      firstName: req.user.firstName,
      lastName: req.user.lastName,
      name: req.user.name,
      img: req.user.img,
      role: req.user.role,
      isActive: true,
      isPhoneVerified: req.user.isPhoneVerified,
      createdAt: new Date(),
      updatedAt: new Date(),
      ...addressInfo,
    };
  }

  /**
   * 10. Logout Super Admin
   */
  @Post('logout/admin')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthGuard)
  @ApiOperation({
    summary: 'Logout Super Admin',
    description: 'Revoke session tokens and clear cookies',
  })
  @ApiBearerAuth()
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Logged out successfully',
  })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: 'Unauthorized' })
  async logoutSuperAdmin(
    @Req() req: ReqWithUser,
    @Res({ passthrough: true }) res: Response,
  ): Promise<{ message: string }> {
    if (!req.user.id) {
      throw new UnauthorizedException('User not found in request');
    }

    await this.superAdminService.logout(req.user.id);

    // Clear cookies
    res.clearCookie('access_token');
    res.clearCookie('refresh_token');

    return { message: 'Logged out successfully' };
  }

  /**
   * NEW: Get user activities with filters
   */
  @Get('activities')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Get user activity logs',
    description:
      'Retrieve activity logs with filtering, sorting, and pagination',
  })
  @ApiBearerAuth()
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Activity logs retrieved successfully',
    type: UserActivityListResponseDto,
  })
  async getUserActivities(
    @Query() query: QueryUserActivityDto,
    @Req() req: ReqWithUser,
  ) {
    // Super admins can see all, others see only their own
    if (req.user.role !== Role.SUPER_ADMIN) {
      query.userId = req.user.id;
    }

    return this.superAdminService.getUserActivities(query);
  }

  /**
   * NEW: Get activity statistics
   */
  @Get('activities/stats/:userId')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Get user activity statistics',
    description: 'Get activity statistics for a specific user',
  })
  @ApiBearerAuth()
  async getUserActivityStats(
    @Param('userId') userId: string,
    @Req() req: ReqWithUser,
  ) {
    // Users can only see their own stats unless super admin
    if (req.user.role !== Role.SUPER_ADMIN && req.user.id !== userId) {
      throw new UnauthorizedException('Access denied');
    }

    return this.superAdminService.getUserActivityStats(userId);
  }
}
