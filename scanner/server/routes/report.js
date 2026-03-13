const express = require('express');
const router = express.Router();
const db = require('../firebase-admin');

router.get('/:scanId/html', async (req, res) => {
  try {
    const scan = await db.getScan(req.params.scanId);
    if (!scan) return res.status(404).send('Scan not found');
    const findings = await db.getFindings(req.params.scanId);
    const html = buildSimpleHtmlReport(scan, findings);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
  } catch (err) {
    res.status(500).send(err.message);
  }
});

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

    const confidence = findings.reduce((acc, f) => {
      const key = f.confidence || 'Possible';
      acc[key] = (acc[key] || 0) + 1;
      return acc;
    }, { Confirmed: 0, Likely: 0, Possible: 0 });

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
        confidence,
      },
      findings: findings.map(f => ({
        ...f,
        confidence: f.confidence || 'Possible',
        remediation_one_liner: f.remediation_one_liner || (String(f.aiRemediation || f.remediation || '').split('\n').find(Boolean) || ''),
        owasp_category: owaspMap[f.type] || 'API8:2023'
      })),
      recommendations,
      scan_info: scan
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

module.exports = router;

function buildSimpleHtmlReport(scan, findings) {
  const summary = findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, { critical: 0, high: 0, medium: 0, low: 0, info: 0 });

  const findingRows = findings.map((f, i) => `
    <tr>
      <td>${i + 1}</td>
      <td>${escapeHtml(f.severity || '')}</td>
      <td>${escapeHtml(f.type || '')}</td>
      <td>${escapeHtml(f.method || '')}</td>
      <td>${escapeHtml(f.endpoint || '')}</td>
      <td>${escapeHtml(String(f.cvss_score || ''))}</td>
      <td>${escapeHtml(f.confidence || 'Possible')}</td>
      <td>${escapeHtml((f.remediation_one_liner || f.remediation || '').slice(0, 160))}</td>
    </tr>
  `).join('\n');

  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>API Security Report ${escapeHtml(scan.scanId || '')}</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 24px; color: #111; }
    h1 { margin-bottom: 4px; }
    .meta { color: #555; margin-bottom: 20px; }
    .summary { display: flex; gap: 12px; margin-bottom: 16px; }
    .card { border: 1px solid #ddd; padding: 8px 12px; border-radius: 6px; min-width: 80px; }
    table { width: 100%; border-collapse: collapse; font-size: 12px; }
    th, td { border: 1px solid #ddd; padding: 6px; vertical-align: top; }
    th { background: #f5f5f5; text-align: left; }
  </style>
</head>
<body>
  <h1>API Security Report</h1>
  <div class="meta">Target: ${escapeHtml(scan.targetUrl || '')} | Scan: ${escapeHtml(scan.scanType || 'standard')} | Generated: ${new Date().toISOString()}</div>
  <div class="summary">
    <div class="card">Critical: ${summary.critical || 0}</div>
    <div class="card">High: ${summary.high || 0}</div>
    <div class="card">Medium: ${summary.medium || 0}</div>
    <div class="card">Low: ${summary.low || 0}</div>
    <div class="card">Info: ${summary.info || 0}</div>
  </div>
  <table>
    <thead>
      <tr>
        <th>#</th><th>Severity</th><th>Type</th><th>Method</th><th>Endpoint</th><th>CVSS</th><th>Confidence</th><th>One-line Remediation</th>
      </tr>
    </thead>
    <tbody>
      ${findingRows}
    </tbody>
  </table>
</body>
</html>`;
}

function escapeHtml(value) {
  return String(value || '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}
