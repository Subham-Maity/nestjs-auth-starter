import { ApiProperty } from '@nestjs/swagger';

export class AdminRegisterResponseDto {
  @ApiProperty({
    description: 'Success message',
    example: 'Registration successful. OTP sent to your email.',
  })
  message: string;

  @ApiProperty({
    description: 'Admin details',
    example: {
      id: 'cuid123',
      email: 'admin@example.com',
      firstName: 'John',
      lastName: 'Doe',
      role: 'ADMIN',
    },
  })
  admin: {
    id: string;
    email: string;
    firstName: string;
    lastName: string;
    role: string;
  };
}

export class AdminLoginResponseDto {
  @ApiProperty({
    description: 'Success message indicating OTP has been sent',
    example: 'OTP sent to your email',
  })
  message: string;
}

export class VerifyOtpAdminResponseDto {
  @ApiProperty({
    description: 'Success message',
    example: 'OTP verified successfully',
  })
  message: string;
}

export class ForgotPasswordAdminResponseDto {
  @ApiProperty({
    description: 'Success message',
    example: 'OTP sent to your email for password reset',
  })
  message: string;
}

export class ForgotPasswordVerifyOtpAdminResponseDto {
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

export class ResetPasswordAdminResponseDto {
  @ApiProperty({
    description: 'Success message',
    example: 'Password reset successfully',
  })
  message: string;
}
