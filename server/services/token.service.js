/**
 * services/token.service.js
 * Generates and verifies JWT tokens
 */
const jwt = require('jsonwebtoken');

const TokenService = {
    generateToken(payload) {
        const secret = process.env.JWT_SECRET || 'default_secret';
        // Token expires in 1 hour
        return jwt.sign(payload, secret, { expiresIn: '1h' });
    },

    verifyToken(token) {
        const secret = process.env.JWT_SECRET || 'default_secret';
        return jwt.verify(token, secret);
    }
};

module.exports = TokenService;
