import express from 'express';
import { login, refresh, logout, registerUser, getUserById, updateUserById, deleteUserById } from '../controllers/user.controller.js';
import { authenticateToken } from '../middlewares/auth.middleware.js';
import { generateCsrfToken } from '../config/csrf.config.js';
import { registerLimiter, loginLimiter, refreshLimiter, logoutLimiter, userActionLimiter } from '../config/ratelimit.routes.config.js'
import { ok } from '../utils/response.util.js';
const router = express.Router();

router.get('/', (req, res) => {
  const csrfToken = generateCsrfToken(req, res, { overwrite: false });
  ok(res, 'Server is running', { csrfToken });
});

router.post('/users', registerLimiter, registerUser);
router.post('/users/login', loginLimiter, login);
router.post('/users/refresh', refreshLimiter, refresh);

router.post('/users/logout', logoutLimiter, authenticateToken, logout);

router.get('/users/:id', userActionLimiter, authenticateToken, getUserById);
router.put('/users/:id', userActionLimiter, authenticateToken, updateUserById);
router.delete('/users/:id', userActionLimiter, authenticateToken, deleteUserById);

export default router;