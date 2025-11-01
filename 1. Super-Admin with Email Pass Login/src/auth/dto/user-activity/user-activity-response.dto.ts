import { ApiProperty } from '@nestjs/swagger';
import { ActivityType, Role } from '@prisma/client';

export class UserActivityResponseDto {
  @ApiProperty()
  id: string;

  @ApiProperty()
  userId: string;

  @ApiProperty({ required: false })
  email?: string;

  @ApiProperty({ enum: Role, required: false })
  role?: Role;

  @ApiProperty({ enum: ActivityType })
  activityType: ActivityType;

  @ApiProperty({ required: false })
  sessionId?: string;

  @ApiProperty({ required: false })
  ipAddress?: string;

  @ApiProperty({ required: false })
  userAgent?: string;

  @ApiProperty({ required: false })
  deviceType?: string;

  @ApiProperty({ required: false })
  browser?: string;

  @ApiProperty({ required: false })
  os?: string;

  @ApiProperty({ required: false })
  country?: string;

  @ApiProperty({ required: false })
  city?: string;

  @ApiProperty({ required: false })
  loginAt?: Date;

  @ApiProperty({ required: false })
  logoutAt?: Date;

  @ApiProperty({ required: false })
  duration?: number;

  @ApiProperty()
  isSuccessful: boolean;

  @ApiProperty({ required: false })
  failureReason?: string;

  @ApiProperty()
  isSuspicious: boolean;

  @ApiProperty()
  createdAt: Date;

  @ApiProperty()
  updatedAt: Date;

  @ApiProperty({ required: false })
  user?: {
    firstName?: string;
    lastName?: string;
    name?: string;
  };
}

export class UserActivityListResponseDto {
  @ApiProperty({ type: [UserActivityResponseDto] })
  data: UserActivityResponseDto[];

  @ApiProperty()
  total: number;

  @ApiProperty()
  page: number;

  @ApiProperty()
  limit: number;

  @ApiProperty()
  totalPages: number;
}
