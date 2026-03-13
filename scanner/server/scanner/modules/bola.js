class BOLAScanner {
  constructor(axiosInstance) { this.axios = axiosInstance; }

  async scan(endpoints) {
    const findings = [];
    for (const ep of endpoints) {
      if (!['GET','PUT','DELETE','PATCH'].includes(ep.method)) continue;
      try {
        const idMatch = ep.url.match(/\/(\d+)(\/|$|\?|$)/);
        if (!idMatch) continue;
        const origId = idMatch[1];
        const testId = String(parseInt(origId) === 1 ? 2 : 1);
        const testUrl = ep.url.replace(`/${origId}`, `/${testId}`);

        const [origResp, testResp] = await Promise.all([
          this.axios({ method: ep.method, url: ep.url }).catch(() => null),
          this.axios({ method: ep.method, url: testUrl }).catch(() => null),
        ]);
        if (!origResp || !testResp) continue;

        if (origResp.status === 200 && testResp.status === 200) {
          const oStr = JSON.stringify(origResp.data || '');
          const tStr = JSON.stringify(testResp.data || '');
          if (oStr !== tStr && oStr.length > 10 && tStr.length > 10) {
            findings.push({
              type: 'BOLA', severity: 'critical', cvss_score: 9.1, owasp: 'API1:2023',
              title: 'Broken Object Level Authorization (BOLA/IDOR)',
              endpoint: ep.url, method: ep.method,
              description: `Changing ID from ${origId} → ${testId} returns a different user's data. User A can read User B's private information.`,
              evidence: { original_url: ep.url, tested_url: testUrl, original_status: origResp.status, test_status: testResp.status, original_preview: oStr.slice(0,150), test_preview: tStr.slice(0,150) },
              remediation: `Add ownership check before returning data:\nif (resource.userId !== req.user.id) return res.status(403).json({ error: 'Forbidden' });`
            });
            break;
          }
        }

        // Unauthenticated access check
        const unauthResp = await this.axios({ method: ep.method, url: ep.url, headers: { Authorization: '' } }).catch(() => null);
        if (unauthResp?.status === 200 && /admin|private|profile|account/i.test(ep.url)) {
          findings.push({
            type: 'AUTH_BYPASS', severity: 'critical', cvss_score: 9.8, owasp: 'API2:2023',
            title: 'Sensitive Endpoint Accessible Without Authentication',
            endpoint: ep.url, method: ep.method,
            description: `${ep.url} returns 200 with no auth token. Private data is publicly accessible.`,
            evidence: { url: ep.url, status_no_auth: unauthResp.status, preview: JSON.stringify(unauthResp.data).slice(0,200) },
            remediation: `Add auth middleware:\napp.get('${ep.path}', authenticateToken, handler);\nfunction authenticateToken(req,res,next){\n  const token = req.headers.authorization?.split(' ')[1];\n  if(!token) return res.sendStatus(401);\n  jwt.verify(token, SECRET, (err,user) => { if(err) return res.sendStatus(403); req.user=user; next(); });\n}`
          });
        }
      } catch (e) {}
    }
    return findings;
  }
}
module.exports = BOLAScanner;
