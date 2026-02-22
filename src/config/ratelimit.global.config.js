import rateLimit from 'express-rate-limit';
import { isProd, isTest } from './env.js';

export default rateLimit({
  windowMs: 15 * 60 * 1000,
  max: isProd || isTest ? 300 : 1000,
  message: {
    error: 'TOO_MANY_REQUESTS',
    message: 'Please wait 15 minutes before trying again',
  },
  standardHeaders: true,
  legacyHeaders: false,
});