import { type Response } from 'express';

export class CookieUtil {
  static getOptions(type: 'access' | 'refresh' | 'reset') {
    const baseOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict' as const,
      domain: process.env.COOKIE_DOMAIN,
      path: '/', // Explicitly set path
    };

    const maxAge = {
      access: 2 * 60 * 60 * 1000, // 2 hours
      refresh: 7 * 24 * 60 * 60 * 1000, // 7 days
      reset: 15 * 60 * 1000, // 15 minutes
    };

    return { ...baseOptions, maxAge: maxAge[type] };
  }

  /**
   * Get cookie names (for consistency)
   */
  static getCookieNames() {
    return {
      ACCESS_TOKEN: 'access_token',
      REFRESH_TOKEN: 'refresh_token',
      RESET_TOKEN: 'reset_token',
    } as const;
  }

  /**
   * Helper to clear all auth cookies
   */
  static clearAuthCookies(res: Response) {
    const names = this.getCookieNames();
    res.clearCookie(names.ACCESS_TOKEN);
    res.clearCookie(names.REFRESH_TOKEN);
    res.clearCookie(names.RESET_TOKEN);
  }

  /**
   * Helper to set auth tokens (access + refresh)
   */
  static setAuthTokens(
    res: Response,
    accessToken: string,
    refreshToken: string,
  ) {
    const names = this.getCookieNames();
    res.cookie(names.ACCESS_TOKEN, accessToken, this.getOptions('access'));
    res.cookie(names.REFRESH_TOKEN, refreshToken, this.getOptions('refresh'));
  }
}
