import jwt from 'jsonwebtoken';
import { JWT_ACCESS_SECRET } from '../config/env.js';
import { unauthorized } from '../utils/response.util.js';
import asyncHandler from './async.handler.middleware.js';

export const authenticateToken = asyncHandler(async (req, res, next) => {
    let token;
    const authHeader = req.headers['authorization'];

    if (authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.split(' ')[1];
    }
    else if (req.signedCookies && req.signedCookies.accessToken) {
        token = req.signedCookies.accessToken;
    }
    if (!token) {
        return unauthorized(res, 'Access token is missing or invalid');
    }
    const decoded = jwt.verify(token, JWT_ACCESS_SECRET, {
        algorithms: ['HS512']
    });
    req.user = {
        id: decoded.id,
        username: decoded.username
    };
    next();
});