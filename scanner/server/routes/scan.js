const express = require('express');
const router = express.Router();
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const yaml = require('js-yaml');
const db = require('../firebase-admin');
const ScanEngine = require('../scanner/engine');

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

router.post('/start', upload.single('file'), async (req, res) => {
  try {
    const scanId = uuidv4();
    const { targetUrl, rawCurl, scanType = 'standard', authToken, customHeaders } = req.body;
    let inputData = { targetUrl, rawCurl, scanType, authToken };

    if (customHeaders) {
      try { inputData.customHeaders = JSON.parse(customHeaders); } catch (e) { inputData.customHeaders = {}; }
    }
    if (req.file) {
      const content = req.file.buffer.toString('utf-8');
      try {
        inputData.fileContent = JSON.parse(content);
        inputData.fileType = 'json';
        if (inputData.fileContent.info && inputData.fileContent.item) inputData.fileType = 'postman';
        else if (inputData.fileContent.openapi || inputData.fileContent.swagger) inputData.fileType = 'openapi';
      } catch (e) {
        try {
          inputData.fileContent = yaml.load(content);
          inputData.fileType = 'openapi-yaml';
        } catch {
          inputData.fileContent = content;
          inputData.fileType = 'unknown';
        }
      }
    }

    if (!targetUrl && !req.file && !rawCurl) return res.status(400).json({ error: 'Provide targetUrl, spec file, or raw curl commands' });

    await db.createScan(scanId, {
      scanId, targetUrl: targetUrl || 'From file', scanType,
      status: 'running', progress: 0, totalEndpoints: 0, scannedEndpoints: 0,
      createdAt: new Date().toISOString(),
      activity: [],
      summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    });

    res.json({ scanId, status: 'started' });

    const engine = new ScanEngine(scanId, inputData, db);
    engine.run().catch(err => db.updateScan(scanId, { status: 'error', error: err.message }));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/:scanId', async (req, res) => {
  try {
    const scan = await db.getScan(req.params.scanId);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    const findings = await db.getFindings(req.params.scanId);
    res.json({ ...scan, findings });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.get('/', async (req, res) => {
  try { res.json(await db.getAllScans()); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

module.exports = router;
