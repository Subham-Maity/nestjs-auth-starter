import { ApiProperty } from '@nestjs/swagger';

export class CustomerRegisterResponseDto {
  @ApiProperty({
    description: 'Success message',
    example: 'Registration successful. OTP sent to your email.',
  })
  message: string;

  @ApiProperty({
    description: 'Customer details',
    example: {
      id: 'cuid123',
      email: 'customer@example.com',
      firstName: 'John',
      lastName: 'Doe',
      role: 'CUSTOMER',
    },
  })
  customer: {
    id: string;
    email: string;
    firstName: string;
    lastName: string;
    role: string;
  };
}

export class CustomerLoginResponseDto {
  @ApiProperty({
    description: 'Success message indicating OTP has been sent',
    example: 'OTP sent to your email',
  })
  message: string;
}

export class ForgotPasswordCustomerResponseDto {
  @ApiProperty({
    description: 'Success message',
    example: 'OTP sent to your email for password reset',
  })
  message: string;
}

export class ForgotPasswordVerifyOtpCustomerResponseDto {
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

export class ResetPasswordCustomerResponseDto {
  @ApiProperty({
    description: 'Success message',
    example: 'Password reset successfully',
  })
  message: string;
}
