import { Role } from '@prisma/client';

export type ReqWithUser = Request & {
  user: {
    id?: string;
    email?: string;
    firstName?: string;
    lastName?: string;
    name?: string;
    phone?: string;
    role?: Role;
    isPhoneVerified?: boolean;
    storeId?: string | null;
    img?: string | null;
    address?: boolean;
    addressId?: string | null;
    deviceToken?: string | null;
  };
};
