import { doubleCsrf } from 'csrf-csrf';
import crypto from 'crypto';
import { isProd, isTest, COOKIE_SECRET, SID_NAME, CSRF_NAME } from './env.js';
import MissingSessionError from '../errors/missing.sid.error.js';

export const ensureSessionId = (req, res, next) => {
  if (!req.cookies[SID_NAME]) {
    const sid = crypto.randomBytes(32).toString('hex');
    res.cookie(SID_NAME, sid, {
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? 'Strict' : 'Lax',
      path: '/',
      maxAge: 30 * 24 * 60 * 60 * 1000,
    });
    req.cookies[SID_NAME] = sid;
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
    const sid = req.cookies[SID_NAME];
    if (!sid) throw new MissingSessionError('Session identifier missing');
    return sid;
  },

  cookieName: CSRF_NAME,
  cookieOptions: {
    path: '/',
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? 'Strict' : 'Lax',
    signed: false,
  },
  getTokenFromRequest: (req) => req.headers['x-csrf-token'],
  size: 64,
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
});

export { generateCsrfToken, doubleCsrfProtection, invalidCsrfTokenError };