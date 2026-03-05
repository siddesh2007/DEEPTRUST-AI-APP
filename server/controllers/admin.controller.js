/**
 * controllers/admin.controller.js
 * Handles the final step of admin login if all security stages succeed
 */

const TokenService = require('../services/token.service');
const LogService = require('../services/log.service');
const logger = require('../utils/logger');

const AdminController = {
    async login(req, res) {
        try {
            const { username } = req.body;

            // At this point, face, behavior, and captcha middlewares have cleared the user
            logger.info(`Admin ${username} passed all security stages.`);

            // Generate JWT Token
            const token = TokenService.generateToken({ username, role: 'admin' });

            // Mark successful login in cloud logs
            await LogService.logSuccess(username);

            res.status(200).json({
                message: "Authentication successful",
                token: token
            });
        } catch (error) {
            logger.error(`Login error for admin: ${error.message}`);
            res.status(500).json({ message: "Internal server error during final auth step." });
        }
    }
};

module.exports = AdminController;
