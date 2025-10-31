import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../../prisma';
import { ActivityType, Prisma } from '@prisma/client';
import { QueryUserActivityDto } from '../../dto';

@Injectable()
export class UserActivityRepository {
  constructor(private prisma: PrismaService) {}

  /**
   * Create activity log
   */
  /**
   * Create activity log
   * FIXED: Handle optional userId properly for Prisma
   */
  async createActivity(
    data: Partial<Pick<Prisma.UserActivityUncheckedCreateInput, 'userId'>> &
      Omit<
        Prisma.UserActivityUncheckedCreateInput,
        'id' | 'createdAt' | 'updatedAt' | 'userId'
      >,
  ) {
    return this.prisma.userActivity.create({
      data: data as Prisma.UserActivityUncheckedCreateInput,
    });
  }
  /**
   * Update activity (for logout)
   */
  async updateActivity(
    activityId: string,
    data: {
      logoutAt?: Date;
      duration?: number;
    },
  ) {
    return this.prisma.userActivity.update({
      where: { id: activityId },
      data,
    });
  }

  /**
   * Find latest login activity for user
   */
  async findLatestLoginActivity(userId: string, sessionId?: string) {
    return this.prisma.userActivity.findFirst({
      where: {
        userId,
        activityType: ActivityType.LOGIN,
        ...(sessionId && { sessionId }),
        logoutAt: null,
      },
      orderBy: { loginAt: 'desc' },
    });
  }

  /**
   * Find activities with filters, search, sort, pagination
   */
  async findActivities(query: QueryUserActivityDto) {
    const {
      search,
      userId,
      activityType,
      role,
      ipAddress,
      isSuccessful,
      isSuspicious,
      sortBy = 'createdAt',
      sortOrder = 'desc',
      page = 1,
      limit = 10,
      dateFrom,
      dateTo,
    } = query;

    // Build where conditions
    const where: Prisma.UserActivityWhereInput = {};

    if (userId) {
      where.userId = userId;
    }

    if (activityType) {
      where.activityType = activityType;
    }

    if (role) {
      where.role = role;
    }

    if (ipAddress) {
      where.ipAddress = ipAddress;
    }

    if (typeof isSuccessful === 'boolean') {
      where.isSuccessful = isSuccessful;
    }

    if (typeof isSuspicious === 'boolean') {
      where.isSuspicious = isSuspicious;
    }

    // Date range filter
    if (dateFrom || dateTo) {
      where.createdAt = {};
      if (dateFrom) {
        where.createdAt.gte = new Date(dateFrom);
      }
      if (dateTo) {
        where.createdAt.lte = new Date(dateTo);
      }
    }

    // Search conditions
    if (search) {
      where.OR = [
        { email: { contains: search, mode: 'insensitive' } },
        { ipAddress: { contains: search, mode: 'insensitive' } },
        { deviceType: { contains: search, mode: 'insensitive' } },
        { browser: { contains: search, mode: 'insensitive' } },
        { os: { contains: search, mode: 'insensitive' } },
        { country: { contains: search, mode: 'insensitive' } },
        { city: { contains: search, mode: 'insensitive' } },
      ];
    }

    // Build order by
    const orderBy: Prisma.UserActivityOrderByWithRelationInput = {
      [sortBy]: sortOrder,
    };

    // Pagination
    const skip = (page - 1) * limit;

    // Execute queries
    const [total, activities] = await Promise.all([
      this.prisma.userActivity.count({ where }),
      this.prisma.userActivity.findMany({
        where,
        include: {
          user: {
            select: {
              firstName: true,
              lastName: true,
              name: true,
            },
          },
        },
        orderBy,
        skip,
        take: limit,
      }),
    ]);

    return {
      data: activities,
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    };
  }

  /**
   * Get activity statistics for a user
   */
  async getUserActivityStats(userId: string) {
    const [totalLogins, failedLogins, suspiciousActivities, lastLogin] =
      await Promise.all([
        this.prisma.userActivity.count({
          where: {
            userId,
            activityType: ActivityType.LOGIN,
            isSuccessful: true,
          },
        }),
        this.prisma.userActivity.count({
          where: { userId, activityType: ActivityType.FAILED_LOGIN },
        }),
        this.prisma.userActivity.count({
          where: { userId, isSuspicious: true },
        }),
        this.prisma.userActivity.findFirst({
          where: { userId, activityType: ActivityType.LOGIN },
          orderBy: { loginAt: 'desc' },
        }),
      ]);

    return {
      totalLogins,
      failedLogins,
      suspiciousActivities,
      lastLogin: lastLogin?.loginAt,
      lastIpAddress: lastLogin?.ipAddress,
    };
  }
}
