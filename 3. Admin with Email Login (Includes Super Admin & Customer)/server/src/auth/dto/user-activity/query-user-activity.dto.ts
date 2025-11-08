import { ApiProperty } from '@nestjs/swagger';
import { IsBoolean, IsEnum, IsOptional, IsString } from 'class-validator';
import { Transform } from 'class-transformer';
import { PaginationDto } from '../../../common';
import { ActivityType, Role } from '@prisma/client';

export class QueryUserActivityDto extends PaginationDto {
  @ApiProperty({
    required: false,
    description: 'Search by email, IP address, device, or browser',
  })
  @IsString()
  @IsOptional()
  search?: string;

  @ApiProperty({
    required: false,
    description: 'Filter by user ID',
  })
  @IsString()
  @IsOptional()
  userId?: string;

  @ApiProperty({
    required: false,
    description: 'Filter by activity type',
    enum: ActivityType,
  })
  @IsEnum(ActivityType)
  @IsOptional()
  activityType?: ActivityType;

  @ApiProperty({
    required: false,
    description: 'Filter by role',
    enum: Role,
  })
  @IsEnum(Role)
  @IsOptional()
  role?: Role;

  @ApiProperty({
    required: false,
    description: 'Filter by IP address',
  })
  @IsString()
  @IsOptional()
  ipAddress?: string;

  @ApiProperty({
    required: false,
    description: 'Filter by successful/failed activities',
  })
  @IsBoolean()
  @IsOptional()
  @Transform(({ value }) => {
    if (value === 'true') return true;
    if (value === 'false') return false;
    return value;
  })
  isSuccessful?: boolean;

  @ApiProperty({
    required: false,
    description: 'Filter suspicious activities',
  })
  @IsBoolean()
  @IsOptional()
  @Transform(({ value }) => {
    if (value === 'true') return true;
    if (value === 'false') return false;
    return value;
  })
  isSuspicious?: boolean;

  @ApiProperty({
    description: 'Field to sort by',
    required: false,
    example: 'createdAt',
    enum: ['createdAt', 'loginAt', 'logoutAt', 'duration', 'email'],
  })
  @IsString()
  @IsOptional()
  sortBy?: string;

  @ApiProperty({
    description: 'Sort order',
    required: false,
    example: 'desc',
    enum: ['asc', 'desc'],
  })
  @IsString()
  @IsOptional()
  sortOrder?: 'asc' | 'desc';

  @ApiProperty({
    required: false,
    description: 'Filter by date from (ISO string)',
    example: '2024-01-01T00:00:00.000Z',
  })
  @IsString()
  @IsOptional()
  dateFrom?: string;

  @ApiProperty({
    required: false,
    description: 'Filter by date to (ISO string)',
    example: '2024-12-31T23:59:59.999Z',
  })
  @IsString()
  @IsOptional()
  dateTo?: string;
}
