import { doubleCsrf } from 'csrf-csrf';
import { isProd, isTest, COOKIE_SECRET } from './env.js';

const {
  generateCsrfToken,
  doubleCsrfProtection,
  invalidCsrfTokenError,
} = doubleCsrf({
  getSecret: () => COOKIE_SECRET,
  getSessionIdentifier: (req) => {
    if (isTest) return 'test-session';
    const refreshToken =
      req.signedCookies?.refreshToken;
    if (refreshToken) return refreshToken;
    return req.ip ?? req.socket?.remoteAddress ?? 'anonymous';
  },

  cookieName: isProd ? '__Host-csrf-secret' : 'csrf-secret',
  cookieOptions: {
    path: '/',
    httpOnly: true,
    secure: isProd,
    sameSite: 'Lax',
    signed: false,
  },
  getTokenFromRequest: (req) => req.headers['x-csrf-token'],
  size: 64,
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
});

export {
  generateCsrfToken,
  doubleCsrfProtection,
  invalidCsrfTokenError,
};