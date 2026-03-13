class MisconfigScanner {
  constructor(axiosInstance) {
    this.axios = axiosInstance;
  }

  async scan(endpoints) {
    const findings = [];
    if (endpoints.length === 0) return findings;

    const target = endpoints[0];
    const resp = await this.axios({
      method: 'GET',
      url: target.url,
      headers: { Origin: 'https://evil.com' },
    }).catch(() => null);
    if (!resp) return findings;

    const headers = resp.headers || {};
    const required = [
      { name: 'x-content-type-options', recommend: 'nosniff', severity: 'medium', cvss: 4.3 },
      { name: 'strict-transport-security', recommend: 'max-age=31536000; includeSubDomains', severity: 'medium', cvss: 5.9 },
      { name: 'x-frame-options', recommend: 'DENY', severity: 'medium', cvss: 4.3 },
      { name: 'content-security-policy', recommend: "default-src 'self'", severity: 'low', cvss: 3.7 },
    ];

    for (const h of required) {
      if (!headers[h.name]) {
        findings.push({
          type: 'MISCONFIG',
          severity: h.severity,
          confidence: 'Confirmed',
          cvss_score: h.cvss,
          owasp: 'API8:2023',
          title: `Missing Security Header: ${h.name}`,
          endpoint: target.url,
          method: 'GET',
          description: `Security header "${h.name}" is missing from responses.`,
          evidence: { missing_header: h.name, recommended_value: h.recommend },
          remediation: `Set ${h.name}: ${h.recommend} (or use helmet with strict policy defaults).`,
        });
      }
    }

    const allowedOrigin = headers['access-control-allow-origin'];
    if (allowedOrigin === '*' || allowedOrigin === 'https://evil.com') {
      findings.push({
        type: 'CORS',
        severity: allowedOrigin === 'https://evil.com' ? 'high' : 'medium',
        confidence: 'Confirmed',
        cvss_score: allowedOrigin === 'https://evil.com' ? 8.1 : 5.4,
        owasp: 'API8:2023',
        title: 'Overly Permissive CORS Policy',
        endpoint: target.url,
        method: 'GET',
        description: `Server allows origin "${allowedOrigin}" for a malicious Origin probe (evil.com).`,
        evidence: {
          request_origin: 'https://evil.com',
          access_control_allow_origin: allowedOrigin || 'missing',
          access_control_allow_credentials: headers['access-control-allow-credentials'] || 'missing',
        },
        replay: {
          request: { method: 'GET', url: target.url, headers: { Origin: 'https://evil.com' } },
          insecure_response: {
            'access-control-allow-origin': allowedOrigin || 'missing',
            'access-control-allow-credentials': headers['access-control-allow-credentials'] || 'missing',
          },
          expected_secure_response: { 'access-control-allow-origin': 'https://your-trusted-app.example' },
        },
        remediation: 'Replace wildcard/reflected origins with a strict allowlist of trusted frontend origins.',
      });
    }

    return findings;
  }
}

module.exports = MisconfigScanner;
