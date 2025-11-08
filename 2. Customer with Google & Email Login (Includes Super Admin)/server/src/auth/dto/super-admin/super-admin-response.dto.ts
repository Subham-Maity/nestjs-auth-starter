import { ApiProperty } from '@nestjs/swagger';

export class SuperAdminRegisterResponseDto {
  @ApiProperty({
    description: 'Success message',
    example: 'Registration successful. OTP sent to your email.',
  })
  message: string;

  @ApiProperty({
    description: 'Super Admin details',
    example: {
      id: 'cuid123',
      email: 'superadmin@example.com',
      firstName: 'John',
      lastName: 'Doe',
      role: 'SUPER_ADMIN',
    },
  })
  superAdmin: {
    id: string;
    email: string;
    firstName: string;
    lastName: string;
    role: string;
  };
}

export class SuperAdminLoginResponseDto {
  @ApiProperty({
    description: 'Success message indicating OTP has been sent',
    example: 'OTP sent to your email',
  })
  message: string;
}

export class VerifyOtpSuperAdminResponseDto {
  @ApiProperty({
    description: 'Success message',
    example: 'OTP verified successfully',
  })
  message: string;
}

export class ForgotPasswordSuperAdminResponseDto {
  @ApiProperty({
    description: 'Success message',
    example: 'OTP sent to your email for password reset',
  })
  message: string;
}

export class ForgotPasswordVerifyOtpSuperAdminResponseDto {
  @ApiProperty({
    description: 'Success message',
    example: 'OTP verified successfully',
  })
  message: string;

  @ApiProperty({
    description: 'Reset token data',
    example: {
      resetToken: 'abc123xyz...',
    },
  })
  data: {
    resetToken: string;
  };
}

export class ResetPasswordSuperAdminResponseDto {
  @ApiProperty({
    description: 'Success message',
    example: 'Password reset successfully',
  })
  message: string;
}
