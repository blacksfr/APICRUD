import jwt from 'jsonwebtoken';
import { JWT_SECRET } from '../config/env.js';
import { unauthorized } from '../utils/response.util.js';
import asyncHandler from './async.handler.middleware.js';

export const authenticateToken = asyncHandler(async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return unauthorized(res, 'Access token is missing');
    }
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
    const { id, username } = decoded;
    req.user = {
        id,
        username
    };
    next();
});