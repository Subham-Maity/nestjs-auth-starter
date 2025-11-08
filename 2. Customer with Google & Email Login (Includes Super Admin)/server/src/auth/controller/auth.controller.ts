import {
  BadRequestException,
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
  CustomerLoginDto,
  CustomerLoginResponseDto,
  CustomerRegisterDto,
  CustomerRegisterResponseDto,
  ForgotPasswordCustomerDto,
  ForgotPasswordCustomerResponseDto,
  ForgotPasswordSuperAdminDto,
  ForgotPasswordSuperAdminResponseDto,
  ForgotPasswordVerifyOtpCustomerResponseDto,
  ForgotPasswordVerifyOtpSuperAdminResponseDto,
  QueryUserActivityDto,
  ResetPasswordCustomerDto,
  ResetPasswordCustomerResponseDto,
  ResetPasswordSuperAdminDto,
  ResetPasswordSuperAdminResponseDto,
  SuperAdminLoginDto,
  SuperAdminLoginResponseDto,
  SuperAdminRegisterDto,
  SuperAdminRegisterResponseDto,
  UserActivityListResponseDto,
  VerifyOtpCustomerDto,
  VerifyOtpSuperAdminDto,
} from '../dto';
import {
  CommonAuthService,
  CustomerAuthService,
  SuperAdminAuthService,
} from '../service';
import { GoogleAuthGuard, JwtAuthGuard } from '../guard';
import { ReqWithUser } from '../types';
import { Role } from '@prisma/client';
import { CookieUtil } from '../../common';
import { ConfigService } from '@nestjs/config';

@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(
    private readonly commonService: CommonAuthService,
    private readonly commonRepository: CommonAuthRepository,
    private readonly superAdminService: SuperAdminAuthService,
    private readonly customerService: CustomerAuthService,
    private configService: ConfigService,
  ) {}

  /**
   *~~~~~~~~~~~~~~⚡~~~~~~~~~~~~~~*
   *         𝕊𝕦𝕡𝕖𝕣 𝔸𝕕𝕞𝕚𝕟         *
   *~~~~~~~~~~~~~~⚡~~~~~~~~~~~~~~*
   */

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

    CookieUtil.setAuthTokens(
      res,
      result.tokens.access_token,
      result.tokens.refresh_token,
    );

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
    res.cookie(
      'access_token',
      result.tokens.access_token,
      CookieUtil.getOptions('access'),
    );
    res.cookie(
      'refresh_token',
      result.tokens.refresh_token,
      CookieUtil.getOptions('refresh'),
    );

    return { message: result.message };
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
    res.cookie(
      'reset_token',
      result.data.resetToken,
      CookieUtil.getOptions('reset'),
    );

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
    // Clear only reset token
    const { resetToken } = CookieUtil.getCookieNames();
    res.clearCookie(resetToken);

    return result;
  }

  /**
   * 10. Logout Super Admin
   */
  @Post('logout/super-admin')
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
    CookieUtil.clearAuthCookies(res);

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

  /**
   *~~~~~~~~~~~~~~⚡~~~~~~~~~~~~~~*
   *         Customer            *
   *~~~~~~~~~~~~~~⚡~~~~~~~~~~~~~~*
   */
  /**
   * 1. Register Customer - Send OTP
   */
  @Post('customer/register')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Register a new Customer',
    description:
      'Creates a Customer account and sends OTP to email for verification',
  })
  @ApiBody({ type: CustomerRegisterDto })
  @ApiResponse({
    status: HttpStatus.CREATED,
    description: 'Registration successful. OTP sent to email.',
    type: CustomerRegisterResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Email already registered or invalid input',
  })
  async registerCustomer(@Body() dto: CustomerRegisterDto) {
    return this.customerService.registerCustomer(dto);
  }

  /**
   * 2. Register Customer - Verify OTP
   */
  @Post('customer/register-verify-otp')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Verify OTP for Customer registration',
    description:
      'Completes registration by verifying OTP, activates account, and sets auth cookies',
  })
  @ApiBody({ type: VerifyOtpCustomerDto })
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
  async verifyRegistrationOtpCustomer(
    @Body() dto: VerifyOtpCustomerDto,
    @Res({ passthrough: true }) res: Response,
    @Req() req: Request,
  ) {
    const result = await this.customerService.verifyOtpForRegistration(
      dto,
      req,
    );

    CookieUtil.setAuthTokens(
      res,
      result.tokens.access_token,
      result.tokens.refresh_token,
    );

    return { message: result.message };
  }

  /**
   * 3. Login Customer - Email/Password or Google
   */
  @Post('customer/login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Login Customer',
    description:
      'Authenticates Customer with email/password (sends OTP) or redirects to Google OAuth',
  })
  @ApiBody({ type: CustomerLoginDto })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'OTP sent to your email (email/password login)',
    type: CustomerLoginResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Invalid credentials',
  })
  async loginCustomer(
    @Body() dto: CustomerLoginDto,
    @Query('provider') provider?: string,
    @Res({ passthrough: true }) res?: Response,
    @Req() req?: Request,
  ): Promise<CustomerLoginResponseDto> {
    // Check if social login
    if (provider === 'google') {
      // This will never execute because Google login uses a separate route
      // This is just for documentation
      throw new BadRequestException(
        'Use GET /auth/customer/login/google for Google login',
      );
    }

    // Email/password login
    return this.customerService.loginCustomer(dto, req);
  }

  /**
   * 3a. Google OAuth - Initiate
   */
  @Get('customer/login/google')
  @UseGuards(GoogleAuthGuard)
  @ApiOperation({
    summary: 'Initiate Google OAuth login',
    description: 'Redirects to Google for authentication',
  })
  async googleAuth() {
    // Guard redirects to Google
  }

  /**
   * 3b. Google OAuth - Callback
   */
  @Get('customer/google/callback')
  @UseGuards(GoogleAuthGuard)
  @ApiOperation({
    summary: 'Google OAuth callback',
    description:
      'Handles Google OAuth callback and sets authentication cookies',
  })
  async googleAuthCallback(
    @Req() req: Request & { user: any },
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.customerService.googleLogin(req.user, req);

    CookieUtil.setAuthTokens(
      res,
      result.tokens.access_token,
      result.tokens.refresh_token,
    );

    // Redirect to frontend with success
    const frontendUrl = this.configService.get<string>('FRONTEND_URL');
    return res.redirect(`${frontendUrl}`);
  }

  /**
   * 4. Login Customer - Verify OTP (Email/Password only)
   */
  @Post('customer/verify-otp')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Verify OTP for Customer login',
    description: 'Verifies OTP and sets authentication cookies',
  })
  @ApiBody({ type: VerifyOtpCustomerDto })
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
  async verifyLoginOtpCustomer(
    @Body() dto: VerifyOtpCustomerDto,
    @Res({ passthrough: true }) res: Response,
    @Req() req: Request,
  ) {
    const result = await this.customerService.verifyOtpForLogin(dto, req);

    res.cookie(
      'access_token',
      result.tokens.access_token,
      CookieUtil.getOptions('access'),
    );
    res.cookie(
      'refresh_token',
      result.tokens.refresh_token,
      CookieUtil.getOptions('refresh'),
    );

    return { message: result.message };
  }

  /**
   * 5. Forgot Password Customer - Send OTP
   */
  @Post('forgot-password/customer')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Initiate forgot password for Customer',
    description: 'Sends OTP to Customer email for password reset',
  })
  @ApiBody({ type: ForgotPasswordCustomerDto })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'OTP sent to your email',
    type: ForgotPasswordCustomerResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: 'Customer not found',
  })
  async forgotPasswordCustomer(
    @Body() dto: ForgotPasswordCustomerDto,
  ): Promise<ForgotPasswordCustomerResponseDto> {
    return this.customerService.forgotPassword(dto);
  }

  /**
   * 6. Forgot Password Customer - Verify OTP
   */
  @Post('forgot-password-verify-otp/customer')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Verify OTP for forgot password',
    description: 'Verifies OTP and returns reset token',
  })
  @ApiBody({ type: VerifyOtpCustomerDto })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'OTP verified successfully',
    type: ForgotPasswordVerifyOtpCustomerResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Invalid or expired OTP',
  })
  async verifyForgotPasswordOtpCustomer(
    @Body() dto: VerifyOtpCustomerDto,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ForgotPasswordVerifyOtpCustomerResponseDto> {
    const result = await this.customerService.verifyForgotPasswordOtp(dto);

    res.cookie(
      'reset_token',
      result.data.resetToken,
      CookieUtil.getOptions('reset'),
    );

    return result;
  }

  /**
   * 7. Reset Password Customer
   */
  @Post('reset-password/customer')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Reset password for Customer',
    description: 'Resets password using valid reset token',
  })
  @ApiBody({ type: ResetPasswordCustomerDto })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Password reset successfully',
    type: ResetPasswordCustomerResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Invalid or expired reset token',
  })
  async resetPasswordCustomer(
    @Body() dto: ResetPasswordCustomerDto,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ResetPasswordCustomerResponseDto> {
    const result = await this.customerService.resetPassword(dto);

    const { resetToken } = CookieUtil.getCookieNames();
    res.clearCookie(resetToken);

    return result;
  }

  /**
   * 8. Logout Customer
   */
  @Post('logout/customer')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthGuard)
  @ApiOperation({
    summary: 'Logout Customer',
    description: 'Revoke session tokens and clear cookies',
  })
  @ApiBearerAuth()
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Logged out successfully',
  })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: 'Unauthorized' })
  async logoutCustomer(
    @Req() req: ReqWithUser,
    @Res({ passthrough: true }) res: Response,
  ): Promise<{ message: string }> {
    if (!req.user.id) {
      throw new UnauthorizedException('User not found in request');
    }

    await this.customerService.logout(req.user.id);

    CookieUtil.clearAuthCookies(res);

    return { message: 'Logged out successfully' };
  }
  /**
   *~~~~~~~~~~~~~~⚡~~~~~~~~~~~~~~*
   *         Common              *
   *~~~~~~~~~~~~~~⚡~~~~~~~~~~~~~~*
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
    res.cookie(
      'access_token',
      tokens.access_token,
      CookieUtil.getOptions('access'),
    );
    res.cookie(
      'refresh_token',
      tokens.refresh_token,
      CookieUtil.getOptions('refresh'),
    );

    return { message: 'Tokens refreshed successfully' };
  }
}
