import {
  IsEmail,
  IsNotEmpty,
  IsString,
  Matches,
  MaxLength,
  MinLength,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { Transform } from 'class-transformer';

export class AdminRegisterDto {
  @ApiProperty({
    description: 'Admin email address',
    example: 'admin@example.com',
  })
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @ApiProperty({
    description:
      'Password must include at least one lowercase letter, one uppercase letter, one number, and one special character',
    example: 'Admin@123',
    minLength: 8,
  })
  @IsString()
  @IsNotEmpty()
  @MinLength(8)
  @Matches(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=[\]{};:'",.<>/?]).{8,}$/,
    {
      message:
        'Password too weak. It must include at least one lowercase letter, one uppercase letter, one number, and one special character.',
    },
  )
  password: string;

  @ApiProperty({
    description: 'First name of the admin',
    example: 'John',
  })
  @IsString()
  @IsNotEmpty()
  @Transform(({ value }) => value?.trim())
  @MaxLength(50)
  firstName: string;

  @ApiProperty({
    description: 'Last name of the admin',
    example: 'Doe',
  })
  @IsString()
  @IsNotEmpty()
  @Transform(({ value }) => value?.trim())
  @MaxLength(50)
  lastName: string;
}

export class AdminLoginDto {
  @ApiProperty({
    description: 'Admin email address',
    example: 'admin@example.com',
  })
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @ApiProperty({
    description: 'Admin password',
    example: 'Admin@123',
  })
  @IsString()
  @IsNotEmpty()
  password: string;
}

export class VerifyOtpAdminDto {
  @ApiProperty({
    description: 'Email address for OTP verification',
    example: 'admin@example.com',
  })
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @ApiProperty({
    description: 'OTP code sent to email',
    example: '123456',
  })
  @IsString()
  @IsNotEmpty()
  @MinLength(6)
  otp: string;
}

export class ForgotPasswordAdminDto {
  @ApiProperty({
    description: 'Admin email address',
    example: 'admin@example.com',
  })
  @IsEmail()
  @IsNotEmpty()
  email: string;
}

export class ResetPasswordAdminDto {
  @ApiProperty({
    description: 'Reset token received after OTP verification',
    example: 'abc123xyz...',
  })
  @IsString()
  @IsNotEmpty()
  resetToken: string;

  @ApiProperty({
    description:
      'New password (minimum 8 characters with complexity requirements)',
    example: 'NewPassword@123',
    minLength: 8,
  })
  @IsString()
  @IsNotEmpty()
  @MinLength(8)
  @Matches(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=[\]{};:'",.<>/?]).{8,}$/,
    {
      message:
        'Password too weak. It must include at least one lowercase letter, one uppercase letter, one number, and one special character.',
    },
  )
  newPassword: string;
}
