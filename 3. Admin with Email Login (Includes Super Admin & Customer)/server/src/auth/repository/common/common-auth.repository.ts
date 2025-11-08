import { BadRequestException, Injectable } from '@nestjs/common';
import { PrismaService } from '../../../prisma';
import { Config } from '../../../common';

@Injectable()
export class CommonAuthRepository {
  constructor(private prisma: PrismaService) {}

  /**
   * Find active OTP by email and purpose
   * Only returns unused, non-expired OTPs
   */
  async findActiveOtpByEmail(email: string, purpose: string) {
    return this.prisma.otpVerification.findFirst({
      where: {
        email,
        purpose,
        isUsed: false,
        expiresAt: { gt: new Date() },
      },
      orderBy: { createdAt: 'desc' },
    });
  }
  /**
   * Check if user is locked out
   * Returns locked OTP record if user is locked, null otherwise
   */
  async checkOtpLockout(email: string, purpose: string) {
    return this.prisma.otpVerification.findFirst({
      where: {
        email,
        purpose,
        lockedUntil: { gt: new Date() }, // Still locked
      },
      orderBy: { lockedUntil: 'desc' },
    });
  }

  /**
   * Create or update OTP for email
   * Properly handles userId, createdById, and purpose
   */
  /**
   * Create or update OTP for email
   * FIXED: Delete old OTPs instead of updating to avoid unique constraint violation
   */
  async createOrUpdateOtpEmail(
    email: string,
    otp: string,
    expiresAt: Date,
    purpose: string,
    userId?: string,
    createdById?: string,
  ) {
    // ✅ Check if user is currently locked out
    const lockedOtp = await this.checkOtpLockout(email, purpose);

    if (lockedOtp) {
      const remainingMinutes = Math.ceil(
        (lockedOtp.lockedUntil!.getTime() - Date.now()) / (1000 * 60),
      );

      throw new BadRequestException(
        `Too many failed attempts. Please try again after ${remainingMinutes} minute(s).`,
      );
    }

    // Delete all old OTPs for this email/purpose (including locked ones that expired)
    return this.prisma.$transaction(async (tx) => {
      await tx.otpVerification.deleteMany({
        where: {
          email,
          purpose,
          OR: [
            { isUsed: false },
            { lockedUntil: { lt: new Date() } }, // Delete expired lockouts
          ],
        },
      });

      return tx.otpVerification.create({
        data: {
          email,
          otp,
          expiresAt,
          purpose,
          userId,
          createdById,
          isUsed: false,
          verified: false,
          attempts: 0,
          maxAttempts: Config.otp.maxAttempts,
          lockedUntil: null, // Not locked initially
        },
      });
    });
  }

  /**
   * Increment OTP attempts
   */
  async incrementOtpAttempts(otpId: string) {
    const otp = await this.prisma.otpVerification.findUnique({
      where: { id: otpId },
    });

    if (!otp) {
      throw new Error('OTP not found');
    }

    const newAttempts = otp.attempts + 1;
    const maxReached = newAttempts >= Config.otp.maxAttempts;

    // If max attempts reached, set lockout time
    const lockedUntil = maxReached
      ? new Date(Date.now() + Config.otp.lockoutMinutes * 60 * 1000)
      : null;

    return this.prisma.otpVerification.update({
      where: { id: otpId },
      data: {
        attempts: { increment: 1 },
        lastAttemptAt: new Date(),
        lockedUntil,
      },
    });
  }

  /**
   * Mark OTP as verified and used
   */
  async markOtpAsVerified(otpId: string, verifiedById: string) {
    const otpRecord = await this.prisma.otpVerification.findUnique({
      where: { id: otpId },
      select: { email: true, purpose: true },
    });

    if (!otpRecord) {
      throw new Error('OTP record not found');
    }

    // Delete old used OTPs
    await this.prisma.otpVerification.deleteMany({
      where: {
        email: otpRecord.email,
        purpose: otpRecord.purpose,
        isUsed: true,
        id: { not: otpId },
      },
    });

    return this.prisma.otpVerification.update({
      where: { id: otpId },
      data: {
        verified: true,
        isUsed: true,
        verifiedAt: new Date(),
        verifiedById,
      },
    });
  }

  /**
   * Delete OTP record by ID
   */
  async deleteOtpRecord(otpId: string) {
    return this.prisma.otpVerification.delete({
      where: { id: otpId },
    });
  }

  /**
   * Delete all OTPs for a user (cleanup on user deletion)
   */
  async deleteUserOtps(userId: string) {
    return this.prisma.otpVerification.deleteMany({
      where: { userId },
    });
  }

  /**
   * Find user by ID
   */
  async findById(id: string) {
    return this.prisma.user.findUnique({ where: { id } });
  }

  /**
   * Update refresh token hash
   */
  async updateRtHash(userId: string, rtHash: string | null) {
    if (!userId) {
      throw new Error('User ID is required for updating refresh token hash');
    }

    await this.prisma.user.update({
      where: { id: userId },
      data: { rtHash },
    });
  }

  /**
   * Find user's default address
   */
  async findUserDefaultAddress(userId: string) {
    return this.prisma.address.findFirst({
      where: {
        userId,
        isDefault: true,
      },
      select: {
        id: true,
        addressLine: true,
        city: true,
        state: true,
        pincode: true,
        isDefault: true,
      },
    });
  }
  /**
   * Clean up expired OTPs and old lockouts
   */
  async cleanupOtpsForEmail(email: string) {
    return this.prisma.otpVerification.deleteMany({
      where: {
        email,
        OR: [
          { isUsed: true },
          { expiresAt: { lt: new Date() } },
          { lockedUntil: { lt: new Date() } }, // ✅ Clean expired lockouts
        ],
      },
    });
  }
  /**
   * Check if user exists by phone or email
   */
  async checkUserExists(phone?: string, email?: string) {
    const whereClause: any = {};

    if (phone && email) {
      whereClause.OR = [{ phone }, { email }];
    } else if (phone) {
      whereClause.phone = phone;
    } else if (email) {
      whereClause.email = email;
    } else {
      return null;
    }

    return this.prisma.user.findFirst({
      where: whereClause,
      select: {
        id: true,
        email: true,
        phone: true,
        role: true,
        isPhoneVerified: true,
        isEmailVerified: true,
        isActive: true,
        accountStatus: true,
        authType: true,
      },
    });
  }
}
