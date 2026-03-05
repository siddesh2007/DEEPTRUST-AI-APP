/**
 * app.js
 * Express configuration and middleware setup
 */

const express = require('express');
const cors = require('cors');
const path = require('path');
const adminRoutes = require('./routes/admin.routes');

const app = express();

// Middleware
app.use(express.json());
app.use(cors());

// Serve static frontend files
app.use(express.static(path.join(__dirname, '../client')));

// Routes
app.use('/api/admin', adminRoutes);

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../client/index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ message: 'Internal Server Error' });
});

module.exports = app;
