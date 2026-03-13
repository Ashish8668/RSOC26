const express = require('express');
const router = express.Router();
const db = require('../firebase-admin');

router.get('/:scanId', async (req, res) => {
  try {
    const scan = await db.getScan(req.params.scanId);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    const findings = await db.getFindings(req.params.scanId);

    const weights = { critical: 10, high: 7, medium: 4, low: 2, info: 0.5 };
    const riskScore = Math.min(100, Math.round(findings.reduce((s, f) => s + (weights[f.severity] || 0), 0)));
    const critical = findings.filter(f => f.severity === 'critical').length;
    const high = findings.filter(f => f.severity === 'high').length;
    const riskLevel = critical > 0 ? 'CRITICAL' : high > 2 ? 'HIGH' : high > 0 ? 'MEDIUM-HIGH' : 'MEDIUM';

    const owaspMap = {
      BOLA: 'API1:2023 - Broken Object Level Authorization',
      AUTH_BYPASS: 'API2:2023 - Broken Authentication',
      RATE_LIMIT: 'API4:2023 - Unrestricted Resource Consumption',
      DATA_EXPOSURE: 'API3:2023 - Broken Object Property Level Authorization',
      INJECTION: 'API8:2023 - Security Misconfiguration',
      CORS: 'API8:2023 - Security Misconfiguration',
      MISCONFIG: 'API8:2023 - Security Misconfiguration',
      JWT: 'API2:2023 - Broken Authentication',
    };

    const recommendations = [];
    const types = [...new Set(findings.map(f => f.type))];
    if (types.includes('BOLA')) recommendations.push({ title: 'Implement Object-Level Authorization', description: 'Always validate that the authenticated user owns the requested resource. Never rely on user-supplied IDs alone.', priority: 'critical' });
    if (types.includes('RATE_LIMIT')) recommendations.push({ title: 'Add Rate Limiting', description: 'Use express-rate-limit on all endpoints. Login endpoints should allow max 5 attempts per 15 minutes.', priority: 'high' });
    if (types.includes('AUTH_BYPASS')) recommendations.push({ title: 'Enforce Authentication Middleware', description: 'Add JWT validation middleware to all protected routes. Return 401 for missing tokens, 403 for invalid ones.', priority: 'critical' });
    if (types.includes('DATA_EXPOSURE')) recommendations.push({ title: 'Minimize API Response Data', description: 'Use DTOs/serializers that explicitly whitelist safe fields. Never return password hashes, SSNs, or credit card numbers.', priority: 'high' });
    if (types.includes('INJECTION')) recommendations.push({ title: 'Use Parameterized Queries', description: 'Never concatenate user input into SQL. Use prepared statements: db.query("SELECT * WHERE id = ?", [id])', priority: 'critical' });
    if (types.includes('CORS')) recommendations.push({ title: 'Fix CORS Policy', description: "Replace wildcard (*) with explicit origins: cors({ origin: ['https://yourdomain.com'] })", priority: 'medium' });

    res.json({
      meta: { reportId: req.params.scanId, generatedAt: new Date().toISOString(), target: scan.targetUrl, scanType: scan.scanType },
      executive_summary: {
        total_findings: findings.length, risk_score: riskScore, risk_level: riskLevel,
        critical: findings.filter(f => f.severity === 'critical').length,
        high: findings.filter(f => f.severity === 'high').length,
        medium: findings.filter(f => f.severity === 'medium').length,
        low: findings.filter(f => f.severity === 'low').length,
        info: findings.filter(f => f.severity === 'info').length,
        endpoints_tested: scan.scannedEndpoints || 0,
      },
      findings: findings.map(f => ({ ...f, owasp_category: owaspMap[f.type] || 'API8:2023' })),
      recommendations,
      scan_info: scan
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

module.exports = router;
