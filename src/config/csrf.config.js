import { doubleCsrf } from 'csrf-csrf';
import crypto from 'crypto';
import { isProd, isTest, COOKIE_SECRET } from './env.js';

const SESSION_ID_COOKIE = isProd ? '__Host-sid' : 'sid';

export const ensureSessionId = (req, res, next) => {
  if (!req.cookies[SESSION_ID_COOKIE]) {
    const sid = crypto.randomBytes(32).toString('hex');
    res.cookie(SESSION_ID_COOKIE, sid, {
      httpOnly: true,
      secure:   isProd,
      sameSite: isProd ? 'Strict' : 'Lax',
      path:     '/',
      maxAge:   30 * 24 * 60 * 60 * 1000,
    });
    req.cookies[SESSION_ID_COOKIE] = sid;
  }
  next();
};

const {
  generateCsrfToken,
  doubleCsrfProtection,
  invalidCsrfTokenError,
} = doubleCsrf({
  getSecret: () => COOKIE_SECRET,

  getSessionIdentifier: (req) => {
    if (isTest) return 'test-session';
    return req.cookies[SESSION_ID_COOKIE] ?? 'anonymous';
  },

  cookieName: isProd ? '__Host-csrf-secret' : 'csrf-secret',
  cookieOptions: {
    path:     '/',
    httpOnly: true,
    secure:   isProd,
    sameSite: isProd ? 'Strict' : 'Lax',
    signed:   false,
  },
  getTokenFromRequest: (req) => req.headers['x-csrf-token'],
  size:           64,
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
});

export { generateCsrfToken, doubleCsrfProtection, invalidCsrfTokenError };