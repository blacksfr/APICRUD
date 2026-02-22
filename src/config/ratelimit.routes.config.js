import rateLimit from 'express-rate-limit';
import { isProd, isTest } from './env.js';

const commonConfig = {
  standardHeaders: true,
  legacyHeaders: false,
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
    error: "Too many registration attempts", 
    message: "Please wait 1 hour before trying to create a new account again." 
  }
});

export const loginLimiter = rateLimit({
  ...commonConfig,
  windowMs: 15 * 60 * 1000,
  max: getLimit(5, 5),
  skipSuccessfulRequests: true,
  message: { 
    error: "Too many login attempts", 
    message: "Access blocked for 15 minutes for security reasons. Please wait 15 minutes before trying again." 
  }
});

export const refreshLimiter = rateLimit({
  ...commonConfig,
  windowMs: 15 * 60 * 1000,
  max: getLimit(10, 10),
  message: { 
    error: "Too many refresh requests", 
    message: "Please wait 15 minutes before trying again." 
  }
});

export const logoutLimiter = rateLimit({
  ...commonConfig,
  windowMs: 1 * 60 * 1000, 
  max: getLimit(10, 10),
  message: { 
    error: "Too many logout requests", 
    message: "Please wait 1 minute."
  }
});

export const userActionLimiter = rateLimit({
  ...commonConfig,
  windowMs: 1 * 60 * 1000,
  max: getLimit(50, 50),
  message: { 
    error: "Too many requests", 
    message: "You performed many actions per minute. Please wait 1 minute." 
  }
});