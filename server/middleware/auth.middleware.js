/**
 * middleware/auth.middleware.js
 * General JWT Authorization Middleware for protecting dashboard routes
 */
const TokenService = require('../services/token.service');

const authMiddleware = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: "Unauthorized access" });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = TokenService.verifyToken(token);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(403).json({ message: "Invalid or expired token" });
    }
};

module.exports = authMiddleware;
