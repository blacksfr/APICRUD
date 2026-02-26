import rateLimit, { ipKeyGenerator } from 'express-rate-limit';
import { isProd, isTest } from './env.js';

const RATE_LIMITED_ROUTES = new Set([
  '/api/v1/auth/register',
  '/api/v1/auth/login',
  '/api/v1/auth/refresh',
  '/api/v1/auth/logout',
]);

export default rateLimit({
  windowMs: 15 * 60 * 1000,
  max: isProd || isTest ? 300 : 1000,

  keyGenerator: (req) => ipKeyGenerator(req),

  skip: (req) => RATE_LIMITED_ROUTES.has(req.path),

  message: {
    error:   'TOO_MANY_REQUESTS',
    message: 'Please wait 15 minutes before trying again',
  },
  standardHeaders: true,
  legacyHeaders:   false,
});