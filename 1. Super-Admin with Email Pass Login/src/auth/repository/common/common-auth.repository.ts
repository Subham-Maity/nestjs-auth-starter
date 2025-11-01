import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../../prisma';

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
   * Find active OTP by phone and purpose
   */
  async findActiveOtpByPhone(phone: string, purpose: string) {
    return this.prisma.otpVerification.findFirst({
      where: {
        phone,
        purpose,
        isUsed: false,
        expiresAt: { gt: new Date() },
      },
      orderBy: { createdAt: 'desc' },
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
    return this.prisma.$transaction(async (tx) => {
      await tx.otpVerification.deleteMany({
        where: { email, purpose, isUsed: false },
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
          maxAttempts: 10,
        },
      });
    });
  }

  /**
   * Create or update OTP for phone
   */
  async createOrUpdateOtpPhone(
    phone: string,
    otp: string,
    expiresAt: Date,
    purpose: string,
    userId?: string,
    createdById?: string,
  ) {
    // Mark any existing unused OTPs for this phone/purpose as used
    await this.prisma.otpVerification.updateMany({
      where: {
        phone,
        purpose,
        isUsed: false,
      },
      data: {
        isUsed: true,
      },
    });

    // Create new OTP
    return this.prisma.otpVerification.create({
      data: {
        phone,
        otp,
        expiresAt,
        purpose,
        userId,
        createdById,
        attempts: 0,
        isUsed: false,
        verified: false,
        lastAttemptAt: new Date(),
      },
    });
  }

  /**
   * Increment OTP attempts
   */
  async incrementOtpAttempts(otpId: string) {
    return this.prisma.otpVerification.update({
      where: { id: otpId },
      data: {
        attempts: { increment: 1 },
        lastAttemptAt: new Date(),
      },
    });
  }

  /**
   * Mark OTP as verified and used
   */
  async markOtpAsVerified(otpId: string, verifiedById: string) {
    // First, get the OTP record to know its email and purpose
    const otpRecord = await this.prisma.otpVerification.findUnique({
      where: { id: otpId },
      select: { email: true, purpose: true },
    });

    if (!otpRecord) {
      throw new Error('OTP record not found');
    }

    // Delete any old used OTPs with same email and purpose
    await this.prisma.otpVerification.deleteMany({
      where: {
        email: otpRecord.email,
        purpose: otpRecord.purpose,
        isUsed: true,
        id: { not: otpId },
      },
    });

    // Now update the current OTP
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
   * Delete expired or used OTPs for email
   */
  async cleanupOtpsForEmail(email: string) {
    return this.prisma.otpVerification.deleteMany({
      where: {
        email,
        OR: [{ isUsed: true }, { expiresAt: { lt: new Date() } }],
      },
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
