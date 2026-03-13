class AuthScanner {
  constructor(axiosInstance) { this.axios = axiosInstance; }

  async scan(endpoints) {
    const findings = [];
    for (const ep of endpoints) {
      try {
        // Test 1: Admin endpoints with no auth
        if (/admin|manage|root/i.test(ep.url)) {
          const resp = await this.axios({ method: 'GET', url: ep.url, headers: { Authorization: '' } }).catch(() => null);
          if (resp?.status === 200) {
            findings.push({
              type: 'AUTH_BYPASS', severity: 'critical', cvss_score: 10.0, owasp: 'API2:2023',
              title: 'Admin Endpoint Requires No Authentication',
              endpoint: ep.url, method: 'GET',
              description: `Admin endpoint ${ep.url} is fully accessible without any token. Anyone can access all admin functionality.`,
              evidence: { url: ep.url, response_status: 200, preview: JSON.stringify(resp.data).slice(0,300) },
              remediation: `Protect admin routes with auth + role check:\nrouter.get('/admin/users', authenticate, requireRole('admin'), handler);\nfunction requireRole(role){\n  return (req,res,next) => req.user?.role===role ? next() : res.sendStatus(403);\n}`
            });
          }
        }

        // Test 2: Invalid JWT accepted
        if (ep.method === 'GET') {
          const algNoneToken = 'eyJhbGciOiJub25lIn0.eyJpZCI6MSwiZW1haWwiOiJhZG1pbkB0ZXN0LmNvbSIsInJvbGUiOiJhZG1pbiJ9.';
          const resp = await this.axios({ method: ep.method, url: ep.url, headers: { Authorization: `Bearer ${algNoneToken}` } }).catch(() => null);
          if (resp?.status === 200 && /user|admin|profile|order/i.test(ep.url)) {
            findings.push({
              type: 'AUTH_BYPASS', severity: 'critical', cvss_score: 9.8, owasp: 'API2:2023',
              title: 'JWT Algorithm "none" Attack Successful',
              endpoint: ep.url, method: ep.method,
              description: 'API accepts JWT with alg:"none" (no signature). Attacker can forge any identity without knowing the secret.',
              evidence: { used_token: algNoneToken.slice(0,40)+'...', response_status: resp.status },
              remediation: `Always specify allowed algorithms:\njwt.verify(token, SECRET, { algorithms: ['HS256'] }, callback);\n// Never accept alg:none`
            });
          }
        }
      } catch (e) {}
    }
    return findings;
  }
}
module.exports = AuthScanner;
