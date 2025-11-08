import { type Response } from 'express';
import { Config, getTokenExpiryMs } from '../config/config';

export class CookieUtil {
  static getOptions(type: 'access' | 'refresh' | 'reset') {
    const baseOptions = {
      ...Config.cookie.options,
      sameSite: Config.cookie.options.sameSite as 'strict' | 'lax' | 'none',
      domain: process.env.COOKIE_DOMAIN,
    };

    return { ...baseOptions, maxAge: getTokenExpiryMs(type) };
  }

  /**
   * Get cookie names (for consistency)
   */
  static getCookieNames() {
    return Config.cookie.names;
  }
  /**
   * Helper to clear all auth cookies
   */
  static clearAuthCookies(res: Response) {
    const { accessToken, refreshToken, resetToken } = Config.cookie.names;

    res.clearCookie(accessToken);
    res.clearCookie(refreshToken);
    res.clearCookie(resetToken);
  }

  /**
   * Helper to set auth tokens (access + refresh)
   */
  static setAuthTokens(
    res: Response,
    accessToken: string,
    refreshToken: string,
  ): void {
    const { accessToken: accessName, refreshToken: refreshName } =
      Config.cookie.names;

    res.cookie(accessName, accessToken, this.getOptions('access'));
    res.cookie(refreshName, refreshToken, this.getOptions('refresh'));
  }
  static clearCookie(res: Response, cookieName: string): void {
    res.clearCookie(cookieName);
  }
}
