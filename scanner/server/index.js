require('dotenv').config();
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const winston = require('winston');

const scanRoutes = require('./routes/scan');
const reportRoutes = require('./routes/report');

const app = express();
const PORT = process.env.PORT || 5000;

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.colorize(),
    winston.format.printf(({ timestamp, level, message }) => `[${timestamp}] ${level}: ${message}`)
  ),
  transports: [new winston.transports.Console()]
});

app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use((req, res, next) => { logger.info(`${req.method} ${req.path}`); next(); });

app.get('/health', (req, res) => res.json({ status: 'ok', version: '1.0.0', timestamp: new Date().toISOString() }));
app.use('/api/scan', scanRoutes);
app.use('/api/report', reportRoutes);
app.use((req, res) => res.status(404).json({ error: 'Not found' }));
app.use((err, req, res, next) => { logger.error(err.message); res.status(500).json({ error: err.message }); });

app.listen(PORT, () => {
  logger.info(`🚀 Scanner Server → http://localhost:${PORT}`);
  logger.info(`📋 Health check  → http://localhost:${PORT}/health`);
});
