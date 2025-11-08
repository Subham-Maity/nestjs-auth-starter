import { SetMetadata } from '@nestjs/common';
import { Role } from '@prisma/client';
import { ROLES_KEY } from '../constant';

/**
 * Decorator to specify required roles for a route
 * @param roles - One or more roles required to access the route
 *
 * @example
 * @Roles(Role.SUPER_ADMIN)
 * async getSuperAdminData() {}
 *
 * @example
 * @Roles(Role.ADMIN, Role.SUPER_ADMIN)
 * async getAdminData() {}
 */
export const Roles = (...roles: Role[]) => SetMetadata(ROLES_KEY, roles);
