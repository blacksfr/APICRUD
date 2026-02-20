import jwt from 'jsonwebtoken';

export const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ 
            error: "UNAUTHORIZED", 
            message: "Access token is missing" 
        });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });

        req.user = {
            id: decoded.id,
            username: decoded.username
        };
        next();
    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            return res.status(403).json({ 
                error: "FORBIDDEN", 
                message: "Token expired. Please refresh" 
            });
        }
        return res.status(403).json({ 
            error: "FORBIDDEN", 
            message: "Invalid token" 
        });
    }
};