const axios = require('axios');
const { parsePostmanCollection, parseOpenAPISpec, parseCurlCommands, crawlEndpoints } = require('./parser');
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
    this.activity = [];
    this.axios = axios.create({
      timeout: parseInt(process.env.SCAN_TIMEOUT_MS, 10) || 10000,
      validateStatus: () => true,
      headers: {
        'User-Agent': 'APIGuard-Scanner/1.0',
        ...(inputData.authToken ? { Authorization: `Bearer ${inputData.authToken}` } : {}),
        ...(inputData.customHeaders || {}),
      },
    });
  }

  async run() {
    console.log(`[Engine] Starting scan ${this.scanId}`);
    try {
      await this.pushActivity('info', 'scan', 'Scan started');
      await this.db.updateScan(this.scanId, { status: 'discovering', progress: 5 });
      const endpoints = await this.discoverEndpoints();
      console.log(`[Engine] Discovered ${endpoints.length} endpoints`);
      await this.pushActivity('info', 'discovery', `Discovered ${endpoints.length} endpoint(s)`);
      for (const ep of endpoints.slice(0, 40)) {
        await this.pushActivity('trace', 'endpoint', `${ep.method} ${ep.path || ep.url}`, ep.url);
      }

      await this.db.updateScan(this.scanId, { totalEndpoints: endpoints.length, progress: 15, status: 'scanning' });

      if (endpoints.length === 0) {
        await this.db.updateScan(this.scanId, {
          status: 'error',
          error: 'No endpoints discovered. Check the input URL/spec/curl and server availability.',
        });
        return;
      }

      const modules = this.getModulePlan();
      this.inputData.rateLimitCount = this.getRateLimitCount();

      for (const mod of modules) {
        await this.pushActivity('info', 'module', `Running ${mod.name}`);
        await this.db.updateScan(this.scanId, { currentModule: mod.name, progress: mod.progress });
        console.log(`[Engine] Running ${mod.name}...`);

        try {
          const scanner = new mod.scanner(this.axios, this.inputData);
          const newFindings = await scanner.scan(endpoints);

          for (const finding of newFindings) {
            const enriched = this.normalizeFinding({ ...finding, scanId: this.scanId });
            try {
              enriched.aiRemediation = await generateAIRemediation(enriched);
            } catch {
              enriched.aiRemediation = enriched.remediation;
            }
            enriched.remediation_one_liner = this.oneLineFix(enriched.aiRemediation || enriched.remediation);

            await this.db.addFinding(this.scanId, enriched);
            this.findings.push(enriched);
            await this.pushActivity(
              'finding',
              enriched.type || 'FINDING',
              `${(enriched.severity || 'info').toUpperCase()} ${enriched.title || 'Security finding'}`,
              enriched.endpoint
            );

            const summary = this.findings.reduce((acc, f) => {
              acc[f.severity] = (acc[f.severity] || 0) + 1;
              return acc;
            }, { critical: 0, high: 0, medium: 0, low: 0, info: 0 });
            await this.db.updateScan(this.scanId, { summary });
          }

          await this.pushActivity('info', 'module', `${mod.name} complete (${newFindings.length} finding(s))`);
        } catch (e) {
          console.error(`[Engine] ${mod.name} error:`, e.message);
          await this.pushActivity('error', 'module', `${mod.name} failed: ${e.message}`);
        }
      }

      await this.db.updateScan(this.scanId, {
        status: 'completed',
        progress: 100,
        completedAt: new Date().toISOString(),
        totalFindings: this.findings.length,
        scannedEndpoints: endpoints.length,
        currentModule: null,
        summary: this.findings.reduce((acc, f) => {
          acc[f.severity] = (acc[f.severity] || 0) + 1;
          return acc;
        }, { critical: 0, high: 0, medium: 0, low: 0, info: 0 }),
      });
      await this.pushActivity('info', 'scan', `Scan completed with ${this.findings.length} finding(s)`);
      console.log(`[Engine] Scan complete - ${this.findings.length} findings`);
    } catch (err) {
      console.error('[Engine] Fatal:', err.message);
      await this.db.updateScan(this.scanId, {
        status: 'error',
        error: err.message,
        completedAt: new Date().toISOString(),
      });
      await this.pushActivity('error', 'scan', `Scan failed: ${err.message}`);
    }
  }

  async discoverEndpoints() {
    const { targetUrl, fileContent, fileType, rawCurl } = this.inputData;
    if (rawCurl) return parseCurlCommands(rawCurl, targetUrl);
    if (fileType === 'postman' && fileContent) return parsePostmanCollection(fileContent, targetUrl);
    if ((fileType === 'openapi' || fileType === 'openapi-yaml') && fileContent) return parseOpenAPISpec(fileContent, targetUrl);
    if (targetUrl) return crawlEndpoints(targetUrl, this.axios);
    return [];
  }

  getModulePlan() {
    const modules = [
      { name: 'BOLA / IDOR', scanner: BOLAScanner, progress: 30 },
      { name: 'Auth Bypass', scanner: AuthScanner, progress: 44 },
      { name: 'JWT Security', scanner: JWTScanner, progress: 54 },
      { name: 'Rate Limiting', scanner: RateLimitScanner, progress: 64 },
      { name: 'Data Exposure', scanner: DataExposureScanner, progress: 74 },
      { name: 'Injection', scanner: InjectionScanner, progress: 84 },
      { name: 'Misconfiguration', scanner: MisconfigScanner, progress: 94 },
    ];

    if (this.inputData.scanType === 'quick') {
      return modules.filter(m => ['BOLA / IDOR', 'Auth Bypass', 'Rate Limiting', 'Data Exposure'].includes(m.name));
    }
    return modules;
  }

  getRateLimitCount() {
    if (this.inputData.scanType === 'deep') return 100;
    if (this.inputData.scanType === 'quick') return 50;
    return 75;
  }

  normalizeFinding(finding) {
    const severity = (finding.severity || 'medium').toLowerCase();
    const cvssScore = Number.isFinite(Number(finding.cvss_score))
      ? Number(finding.cvss_score)
      : this.cvssFromSeverity(severity);

    return {
      ...finding,
      severity,
      cvss_score: Math.max(0, Math.min(10, Number(cvssScore.toFixed(1)))),
      confidence: finding.confidence || this.inferConfidence(finding),
      remediation: finding.remediation || 'Apply least privilege, strict validation, and secure defaults for this endpoint.',
      foundAt: new Date().toISOString(),
    };
  }

  inferConfidence(finding) {
    const evidence = JSON.stringify(finding.evidence || {}).toLowerCase();
    if (evidence.includes('"status":200') || evidence.includes('"status":500') || evidence.includes('"blocked"')) return 'Confirmed';
    if ((finding.severity || '').toLowerCase() === 'critical' || (finding.severity || '').toLowerCase() === 'high') return 'Likely';
    return 'Possible';
  }

  cvssFromSeverity(severity) {
    const map = { critical: 9.5, high: 7.8, medium: 5.3, low: 3.1, info: 0.0 };
    return map[severity] ?? 5.0;
  }

  oneLineFix(text) {
    if (!text) return '';
    const lines = String(text).split('\n').map(l => l.trim()).filter(Boolean);
    return lines[0] || '';
  }

  async pushActivity(level, kind, message, endpoint = '') {
    this.activity.push({ at: new Date().toISOString(), level, kind, message, endpoint });
    if (this.activity.length > 120) this.activity = this.activity.slice(-120);
    await this.db.updateScan(this.scanId, { activity: this.activity });
  }
}

module.exports = ScanEngine;
