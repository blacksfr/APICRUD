import rateLimit, { ipKeyGenerator } from 'express-rate-limit';
import { isProd, isTest } from './env.js';

const commonConfig = {
  standardHeaders: true,
  legacyHeaders:   false,
  keyGenerator: (req) => ipKeyGenerator(req),
};

const getLimit = (prodLimit, testLimit, devLimit = 1000) => {
  if (isProd) return prodLimit;
  if (isTest) return testLimit;
  return devLimit;
};

export const registerLimiter = rateLimit({
  ...commonConfig,
  windowMs: 60 * 60 * 1000,
  max: getLimit(3, 4),
  message: {
    error:   'TOO_MANY_REQUESTS',
    message: 'Please wait 1 hour before trying to create a new account again.',
  },
});

export const loginLimiter = rateLimit({
  ...commonConfig,
  windowMs: 15 * 60 * 1000,
  max: getLimit(5, 5),
  skipSuccessfulRequests: true,
  message: {
    error:   'TOO_MANY_REQUESTS',
    message: 'Access blocked for 15 minutes for security reasons. Please wait before trying again.',
  },
});

export const refreshLimiter = rateLimit({
  ...commonConfig,
  windowMs: 15 * 60 * 1000,
  max: getLimit(10, 10),
  message: {
    error:   'TOO_MANY_REQUESTS',
    message: 'Please wait 15 minutes before trying again.',
  },
});

export const logoutLimiter = rateLimit({
  ...commonConfig,
  windowMs: 60 * 1000,
  max: getLimit(10, 10),
  message: {
    error:   'TOO_MANY_REQUESTS',
    message: 'Please wait 1 minute.',
  },
});

export const userActionLimiter = rateLimit({
  ...commonConfig,
  windowMs: 60 * 1000,
  max: getLimit(50, 50),
  message: {
    error:   'TOO_MANY_REQUESTS',
    message: 'Too many requests. Please wait 1 minute.',
  },
});