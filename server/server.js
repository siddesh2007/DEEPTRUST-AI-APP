/**
 * server.js
 * Entry point for the backend server
 */

require('dotenv').config({ path: '../.env' }); // Load environment variables from parent folder
const app = require('./app');
const logger = require('./utils/logger');

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    logger.info(`Server is running on port ${PORT}`);
});
