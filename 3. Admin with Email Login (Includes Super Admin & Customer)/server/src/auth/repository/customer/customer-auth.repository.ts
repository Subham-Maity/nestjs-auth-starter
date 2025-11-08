import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../../prisma';
import { AccountStatus, AuthType, Role } from '@prisma/client';

@Injectable()
export class CustomerAuthRepository {
  constructor(private prisma: PrismaService) {}

  /**
   * Find customer by email
   */
  async findCustomerByEmail(email: string) {
    return this.prisma.user.findUnique({
      where: { email },
    });
  }

  /**
   * Find customer by Google ID (email)
   */
  async findCustomerByGoogleEmail(email: string) {
    return this.prisma.user.findFirst({
      where: {
        email,
        authType: AuthType.GOOGLE,
        role: Role.CUSTOMER,
      },
    });
  }

  /**
   * Create a new customer user
   */
  async createCustomer(data: {
    email: string;
    password?: string;
    firstName?: string;
    lastName?: string;
    phone?: string;
    authType?: AuthType;
    accountStatus?: AccountStatus;
    isActive?: boolean;
    isEmailVerified?: boolean;
    img?: string;
  }) {
    return this.prisma.user.create({
      data: {
        email: data.email,
        password: data.password,
        firstName: data.firstName,
        lastName: data.lastName,
        name:
          data.firstName && data.lastName
            ? `${data.firstName} ${data.lastName}`
            : data.firstName || data.email,
        phone: data.phone,
        role: Role.CUSTOMER,
        authType: data.authType || AuthType.EMAIL,
        accountStatus: data.accountStatus || AccountStatus.PENDING_VERIFICATION,
        isActive: data.isActive ?? false,
        isEmailVerified: data.isEmailVerified ?? false,
        img: data.img,
      },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        name: true,
        phone: true,
        role: true,
        authType: true,
        accountStatus: true,
        isActive: true,
        isEmailVerified: true,
        img: true,
        createdAt: true,
        updatedAt: true,
      },
    });
  }

  /**
   * Activate customer account after email verification
   */
  async activateCustomer(userId: string) {
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
   * Delete customer (for cleanup of expired registrations)
   */
  async deleteCustomer(userId: string) {
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
   * Update customer password
   */
  async updateCustomerPassword(userId: string, hashedPassword: string) {
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
        role: Role.CUSTOMER,
      },
    });
  }

  /**
   * Update or create Google user
   */
  async upsertGoogleUser(data: {
    email: string;
    firstName?: string;
    lastName?: string;
    img?: string;
  }) {
    return this.prisma.user.upsert({
      where: { email: data.email },
      update: {
        firstName: data.firstName,
        lastName: data.lastName,
        name:
          data.firstName && data.lastName
            ? `${data.firstName} ${data.lastName}`
            : data.firstName || data.email,
        img: data.img,
        isEmailVerified: true,
        updatedAt: new Date(),
      },
      create: {
        email: data.email,
        firstName: data.firstName,
        lastName: data.lastName,
        name:
          data.firstName && data.lastName
            ? `${data.firstName} ${data.lastName}`
            : data.firstName || data.email,
        img: data.img,
        role: Role.CUSTOMER,
        authType: AuthType.GOOGLE,
        accountStatus: AccountStatus.ACTIVE,
        isActive: true,
        isEmailVerified: true,
      },
    });
  }
}
