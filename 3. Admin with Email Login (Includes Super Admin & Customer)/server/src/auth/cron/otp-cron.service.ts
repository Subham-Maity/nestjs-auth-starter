import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Cron, CronExpression } from '@nestjs/schedule';
import { PrismaService } from '../../prisma';
import { AccountStatus } from '@prisma/client';

@Injectable()
export class OtpCronService {
  private readonly logger = new Logger(OtpCronService.name);
  private readonly isTestMode: boolean;

  constructor(
    private prisma: PrismaService,
    private configService: ConfigService,
  ) {
    const testMode = this.configService.get('TEST_OTP_PRODUCTION');
    this.isTestMode = testMode?.toLowerCase() === 'false';
    this.logger.log(`OTP Test Mode: ${this.isTestMode}`);
  }

  /**
   * Clean up expired and used OTP records
   * Runs every hour
   */
  @Cron(CronExpression.EVERY_HOUR)
  async cleanupOtpRecords() {
    try {
      const twoHoursAgo = new Date(Date.now() - 2 * 60 * 60 * 1000);

      const result = await this.prisma.otpVerification.deleteMany({
        where: {
          OR: [
            { expiresAt: { lt: new Date() } },
            { isUsed: true, createdAt: { lt: twoHoursAgo } },
            { attempts: { gte: 5 } },
            { lockedUntil: { lt: new Date() } },
          ],
        },
      });

      this.logger.log(`Cleaned up ${result.count} OTP records`);
    } catch (error) {
      this.logger.error('Error during OTP cleanup:', error);
    }
  }

  /**
   * Clean up pending registrations with expired OTPs
   * Runs every 6 hours
   */
  @Cron('0 */6 * * *') // Every 6 hours
  async cleanupPendingRegistrations() {
    try {
      const sixHoursAgo = new Date(Date.now() - 6 * 60 * 60 * 1000);

      // Find pending users with no active OTP
      const pendingUsers = await this.prisma.user.findMany({
        where: {
          accountStatus: AccountStatus.PENDING_VERIFICATION,
          createdAt: {
            lt: sixHoursAgo,
          },
        },
        select: {
          id: true,
          email: true,
          otpsTargeted: {
            where: {
              purpose: 'REGISTRATION',
              isUsed: false,
              expiresAt: {
                gt: new Date(),
              },
            },
          },
        },
      });

      // Delete users with no active registration OTP
      const usersToDelete = pendingUsers
        .filter((user) => user.otpsTargeted.length === 0)
        .map((user) => user.id);

      if (usersToDelete.length > 0) {
        // Delete associated OTPs first (cascade should handle this, but being explicit)
        await this.prisma.otpVerification.deleteMany({
          where: {
            userId: {
              in: usersToDelete,
            },
          },
        });

        // Delete users
        const result = await this.prisma.user.deleteMany({
          where: {
            id: {
              in: usersToDelete,
            },
          },
        });

        this.logger.log(
          `Cleaned up ${result.count} pending registrations with expired OTPs`,
        );
      }
    } catch (error) {
      this.logger.error('Error during pending registration cleanup:', error);
    }
  }

  /**
   * Clean up old unverified user accounts
   * Runs daily at midnight
   */
  @Cron(CronExpression.EVERY_DAY_AT_MIDNIGHT)
  async cleanupUnverifiedUsers() {
    try {
      const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

      // Delete unverified users older than 7 days
      const result = await this.prisma.user.deleteMany({
        where: {
          AND: [
            {
              createdAt: {
                lt: sevenDaysAgo,
              },
            },
            {
              accountStatus: AccountStatus.PENDING_VERIFICATION,
            },
            {
              isEmailVerified: false,
            },
          ],
        },
      });

      this.logger.log(`Cleaned up ${result.count} old unverified user records`);
    } catch (error) {
      this.logger.error('Error during unverified users cleanup:', error);
    }
  }

  /**
   * Get default OTP for test mode
   */
  getDefaultOtp(): string | null {
    return this.isTestMode ? '000000' : null;
  }

  /**
   * Check if SMS should be sent (not in test mode)
   */
  shouldSendSms(): boolean {
    return !this.isTestMode;
  }
}
