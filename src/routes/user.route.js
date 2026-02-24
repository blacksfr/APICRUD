import express from 'express';
import { login, refresh, logout, registerUser, getUserById, getUserByToken, updateUserById, deleteUserById } from '../controllers/user.controller.js';
import { authenticateToken } from '../middlewares/auth.middleware.js';
import { generateCsrfToken } from '../config/csrf.config.js';
import { registerLimiter, loginLimiter, refreshLimiter, logoutLimiter, userActionLimiter } from '../config/ratelimit.routes.config.js'
import { ok } from '../utils/response.util.js';
const router = express.Router();

router.get('/api/v1', (req, res) => {
  const csrfToken = generateCsrfToken(req, res, { overwrite: false });
  ok(res, 'Server is running', { csrfToken });
});

router.post('/api/v1/auth/register', registerLimiter, registerUser);
router.post('/api/v1/auth/login', loginLimiter, login);
router.post('/api/v1/auth/refresh', refreshLimiter, refresh);

router.post('/api/v1/auth/logout', logoutLimiter, authenticateToken, logout);

router.get('/api/v1/users/me', userActionLimiter, authenticateToken, getUserByToken);
router.get('/api/v1/users/:id', userActionLimiter, authenticateToken, getUserById);
router.patch('/api/v1/users/:id', userActionLimiter, authenticateToken, updateUserById);
router.delete('/api/v1/users/:id', userActionLimiter, authenticateToken, deleteUserById);

export default router;