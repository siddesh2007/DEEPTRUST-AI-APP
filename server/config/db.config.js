/**
 * config/db.config.js
 * Database configuration
 */

const dbConfig = {
    url: process.env.DB_URL || 'mongodb://localhost:27017/deeptrust',
    options: {
        useNewUrlParser: true,
        useUnifiedTopology: true
    }
};

module.exports = dbConfig;
