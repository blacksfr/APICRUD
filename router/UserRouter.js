import express from 'express';
import { rateLimit } from 'express-rate-limit';
import { login, refresh, logout, registerUser, getUserById, updateUserById, deleteUserById } from '../controllers/UserController.js';
import { authenticateToken } from '../middlewares/Auth.js';

const commonConfig = {
  standardHeaders: true,
  legacyHeaders: false,
};

export const registerLimiter = rateLimit({
  ...commonConfig,
  windowMs: 60 * 60 * 1000,
  max: process.env.NODE_ENV === 'production' || process.env.NODE_ENV === 'test' ? 3 : 1000000, 
  message: { 
    error: "Too many registration attempts", 
    message: "Please wait 1 hour before trying to create a new account again." 
  }
});

export const loginLimiter = rateLimit({
  ...commonConfig,
  windowMs: 15 * 60 * 1000,
  max: process.env.NODE_ENV === 'production' || process.env.NODE_ENV === 'test' ? 5 : 1000000,
  skipSuccessfulRequests: true,
  message: { 
    error: "Too many login attempts", 
    message: "Access blocked for 15 minutes for security reasons. Please wait 15 minutes before trying again." 
  }
});

export const refreshLimiter = rateLimit({
  ...commonConfig,
  windowMs: 15 * 60 * 1000,
  max: process.env.NODE_ENV === 'production' || process.env.NODE_ENV === 'test' ? 10 : 1000000,
  message: { 
    error: "Too many refresh requests", 
    message: "Please wait 15 minutes before trying again." 
  }
});

export const logoutLimiter = rateLimit({
  ...commonConfig,
  windowMs: 1 * 60 * 1000, 
  max: process.env.NODE_ENV === 'production' || process.env.NODE_ENV === 'test' ? 10 : 1000000,
  message: { 
    error: "Too many logout requests", 
    message: "Please wait 1 minute."
  }
});

export const userActionLimiter = rateLimit({
  ...commonConfig,
  windowMs: 1 * 60 * 1000,
  max: process.env.NODE_ENV === 'production' || process.env.NODE_ENV === 'test' ? 50 : 1000000,
  message: { 
    error: "Too many requests", 
    message: "You performed many actions per minute. Please wait 1 minute." 
  }
});

const router = express.Router();

router.get('/', (req, res) => {
  res.status(200).json({ status: 'Server is running'});
});
router.post('/users', registerLimiter, registerUser);

router.post('/users/login', loginLimiter, login);

router.post('/users/refresh', refreshLimiter, refresh);

router.post('/users/logout', logoutLimiter, authenticateToken, logout);

router.get('/users/:id', userActionLimiter, authenticateToken, getUserById);
router.put('/users/:id', userActionLimiter, authenticateToken, updateUserById);
router.delete('/users/:id', userActionLimiter, authenticateToken, deleteUserById);

export default router;