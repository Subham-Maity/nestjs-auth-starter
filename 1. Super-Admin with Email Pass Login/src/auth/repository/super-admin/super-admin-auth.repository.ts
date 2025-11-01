import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../../prisma';
import { AccountStatus, AuthType, Role } from '@prisma/client';

@Injectable()
export class SuperAdminAuthRepository {
  constructor(private prisma: PrismaService) {}

  /**
   * Find super admin by email
   */
  async findSuperAdminByEmail(email: string) {
    return this.prisma.user.findUnique({
      where: { email },
    });
  }

  /**
   * Create a new super admin user
   * UPDATED: With accountStatus and isEmailVerified
   */
  async createSuperAdmin(data: {
    email: string;
    password: string;
    firstName: string;
    lastName: string;
    accountStatus?: AccountStatus;
    isActive?: boolean;
    isEmailVerified?: boolean;
  }) {
    return this.prisma.user.create({
      data: {
        email: data.email,
        password: data.password,
        firstName: data.firstName,
        lastName: data.lastName,
        name: `${data.firstName} ${data.lastName}`,
        role: Role.SUPER_ADMIN,
        authType: AuthType.EMAIL,
        accountStatus: data.accountStatus || AccountStatus.PENDING_VERIFICATION,
        isActive: data.isActive ?? false,
        isEmailVerified: data.isEmailVerified ?? false,
      },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        name: true,
        role: true,
        accountStatus: true,
        isActive: true,
        isEmailVerified: true,
        createdAt: true,
        updatedAt: true,
      },
    });
  }

  /**
   * Activate super admin account after email verification
   * NEW METHOD
   */
  async activateSuperAdmin(userId: string) {
    return this.prisma.user.update({
      where: { id: userId },
      data: {
        accountStatus: AccountStatus.ACTIVE,
        isActive: true,
        isEmailVerified: true,
      },
    });
  }

  /**
   * Delete super admin (for cleanup of expired registrations)
   * NEW METHOD
   */
  async deleteSuperAdmin(userId: string) {
    return this.prisma.user.delete({
      where: { id: userId },
    });
  }

  /**
   * Mark email as verified
   */
  async markEmailVerified(email: string) {
    return this.prisma.user.update({
      where: { email },
      data: {
        isEmailVerified: true,
        updatedAt: new Date(),
      },
    });
  }

  /**
   * Update super admin password
   */
  async updateSuperAdminPassword(userId: string, hashedPassword: string) {
    return this.prisma.user.update({
      where: { id: userId },
      data: {
        password: hashedPassword,
        rtHash: null, // Clear refresh token on password change
      },
    });
  }

  /**
   * Update refresh token hash
   */
  async updateRtHash(userId: string, rtHash: string | null) {
    return this.prisma.user.update({
      where: { id: userId },
      data: { rtHash },
    });
  }

  /**
   * Update reset token
   */
  async updateResetToken(
    email: string,
    resetToken: string | null,
    resetTokenExpiresAt: Date | null,
  ) {
    return this.prisma.user.update({
      where: { email },
      data: {
        resetToken,
        resetTokenExpiresAt,
      },
    });
  }

  /**
   * Find user by reset token
   */
  async findUserByResetToken(resetToken: string) {
    return this.prisma.user.findFirst({
      where: {
        resetToken,
        resetTokenExpiresAt: {
          gt: new Date(),
        },
      },
    });
  }
}
