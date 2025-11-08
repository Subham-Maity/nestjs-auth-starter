export const Config = {
  // JWT Token Expiration
  jwt: {
    accessToken: {
      expiresIn: '2h',
      expiresInMs: 2 * 60 * 60 * 1000,
    },
    refreshToken: {
      expiresIn: '7d',
      expiresInMs: 7 * 24 * 60 * 60 * 1000,
    },
    resetToken: {
      expiresIn: '15m',
      expiresInMs: 15 * 60 * 1000,
    },
  },

  // OTP Configuration
  otp: {
    expiryMinutes: 5,
    length: 6,
    maxAttempts: 5,
    lockoutMinutes: 20,
  },

  // Cookie Configuration
  cookie: {
    names: {
      accessToken: 'access_token',
      refreshToken: 'refresh_token',
      resetToken: 'reset_token',
    },
    options: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      path: '/',
    },
  },
} as const;

// Helper function to get expiry date
export const getExpiryDate = (minutes: number): Date => {
  const date = new Date();
  date.setMinutes(date.getMinutes() + minutes);
  return date;
};

// Helper function to get token expiry in milliseconds
export const getTokenExpiryMs = (
  type: 'access' | 'refresh' | 'reset',
): number => {
  switch (type) {
    case 'access':
      return Config.jwt.accessToken.expiresInMs;
    case 'refresh':
      return Config.jwt.refreshToken.expiresInMs;
    case 'reset':
      return Config.jwt.resetToken.expiresInMs;
  }
};
