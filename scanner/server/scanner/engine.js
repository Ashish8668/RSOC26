const axios = require('axios');
const { parsePostmanCollection, parseOpenAPISpec, crawlEndpoints } = require('./parser');
const { generateAIRemediation } = require('./aiRemediation');
const BOLAScanner = require('./modules/bola');
const AuthScanner = require('./modules/authBypass');
const RateLimitScanner = require('./modules/rateLimit');
const DataExposureScanner = require('./modules/dataExposure');
const InjectionScanner = require('./modules/injection');
const MisconfigScanner = require('./modules/misconfig');
const JWTScanner = require('./modules/jwt');

class ScanEngine {
  constructor(scanId, inputData, db) {
    this.scanId = scanId;
    this.inputData = inputData;
    this.db = db;
    this.findings = [];
    this.axios = axios.create({
      timeout: parseInt(process.env.SCAN_TIMEOUT_MS) || 10000,
      validateStatus: () => true,
      headers: {
        'User-Agent': 'APIGuard-Scanner/1.0',
        ...(inputData.authToken ? { Authorization: `Bearer ${inputData.authToken}` } : {}),
        ...(inputData.customHeaders || {})
      }
    });
  }

  async run() {
    console.log(`[Engine] Starting scan ${this.scanId}`);
    try {
      await this.db.updateScan(this.scanId, { status: 'discovering', progress: 5 });
      const endpoints = await this.discoverEndpoints();
      console.log(`[Engine] Discovered ${endpoints.length} endpoints`);

      await this.db.updateScan(this.scanId, { totalEndpoints: endpoints.length, progress: 15, status: 'scanning' });

      if (endpoints.length === 0) {
        await this.db.updateScan(this.scanId, { status: 'error', error: 'No endpoints discovered. Check the URL is correct and server is running.' });
        return;
      }

      const modules = [
        { name: 'BOLA / IDOR', scanner: BOLAScanner, progress: 30 },
        { name: 'Auth Bypass', scanner: AuthScanner, progress: 44 },
        { name: 'JWT Security', scanner: JWTScanner, progress: 54 },
        { name: 'Rate Limiting', scanner: RateLimitScanner, progress: 64 },
        { name: 'Data Exposure', scanner: DataExposureScanner, progress: 74 },
        { name: 'Injection', scanner: InjectionScanner, progress: 84 },
        { name: 'Misconfiguration', scanner: MisconfigScanner, progress: 94 },
      ];

      for (const mod of modules) {
        await this.db.updateScan(this.scanId, { currentModule: mod.name, progress: mod.progress });
        console.log(`[Engine] Running ${mod.name}...`);
        try {
          const scanner = new mod.scanner(this.axios, this.inputData);
          const newFindings = await scanner.scan(endpoints);

          for (const finding of newFindings) {
            const enriched = { ...finding, scanId: this.scanId };
            try { enriched.aiRemediation = await generateAIRemediation(finding); }
            catch (e) { enriched.aiRemediation = finding.remediation; }
            await this.db.addFinding(this.scanId, enriched);
            this.findings.push(enriched);

            const summary = this.findings.reduce((acc, f) => {
              acc[f.severity] = (acc[f.severity] || 0) + 1; return acc;
            }, { critical: 0, high: 0, medium: 0, low: 0, info: 0 });
            await this.db.updateScan(this.scanId, { summary });
          }
        } catch (e) { console.error(`[Engine] ${mod.name} error:`, e.message); }
      }

      await this.db.updateScan(this.scanId, {
        status: 'completed', progress: 100, completedAt: new Date().toISOString(),
        totalFindings: this.findings.length, scannedEndpoints: endpoints.length, currentModule: null,
        summary: this.findings.reduce((acc, f) => { acc[f.severity] = (acc[f.severity]||0)+1; return acc; }, { critical:0,high:0,medium:0,low:0,info:0 })
      });
      console.log(`[Engine] ✅ Scan complete — ${this.findings.length} findings`);
    } catch (err) {
      console.error(`[Engine] Fatal:`, err.message);
      await this.db.updateScan(this.scanId, { status: 'error', error: err.message, completedAt: new Date().toISOString() });
    }
  }

  async discoverEndpoints() {
    const { targetUrl, fileContent, fileType } = this.inputData;
    if (fileType === 'postman' && fileContent) return parsePostmanCollection(fileContent, targetUrl);
    if ((fileType === 'openapi' || fileType === 'openapi-yaml') && fileContent) return parseOpenAPISpec(fileContent, targetUrl);
    if (targetUrl) return await crawlEndpoints(targetUrl, this.axios);
    return [];
  }
}

module.exports = ScanEngine;
