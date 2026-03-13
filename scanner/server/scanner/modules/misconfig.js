class MisconfigScanner {
  constructor(axiosInstance) { this.axios = axiosInstance; }

  async scan(endpoints) {
    const findings = [];
    if (endpoints.length === 0) return findings;

    try {
      const resp = await this.axios({ method: 'GET', url: endpoints[0].url }).catch(() => null);
      if (!resp) return findings;
      const h = resp.headers || {};

      const requiredHeaders = [
        { name: 'x-content-type-options', recommend: 'nosniff', severity: 'medium', cvss: 4.3 },
        { name: 'x-frame-options', recommend: 'DENY', severity: 'medium', cvss: 4.3 },
        { name: 'strict-transport-security', recommend: 'max-age=31536000', severity: 'medium', cvss: 5.9 },
        { name: 'content-security-policy', recommend: "default-src 'self'", severity: 'low', cvss: 3.7 },
      ];

      for (const hdr of requiredHeaders) {
        if (!h[hdr.name]) {
          findings.push({
            type: 'MISCONFIG', severity: hdr.severity, cvss_score: hdr.cvss, owasp: 'API8:2023',
            title: `Missing Security Header: ${hdr.name}`,
            endpoint: endpoints[0].url, method: 'GET',
            description: `Response is missing the "${hdr.name}" header. This can enable clickjacking, MIME sniffing, or downgrade attacks.`,
            evidence: { missing_header: hdr.name, recommended_value: hdr.recommend },
            remediation: `npm install helmet\n\nconst helmet = require('helmet');\napp.use(helmet()); // Adds all security headers at once\n// Or manually: res.setHeader('${hdr.name}', '${hdr.recommend}');`
          });
        }
      }

      // CORS wildcard check
      const origin = h['access-control-allow-origin'];
      if (origin === '*') {
        findings.push({
          type: 'CORS', severity: 'medium', cvss_score: 5.4, owasp: 'API8:2023',
          title: 'CORS Wildcard Allows Any Origin',
          endpoint: endpoints[0].url, method: 'GET',
          description: "Access-Control-Allow-Origin: * allows any website to make cross-origin requests. Credentials may be at risk.",
          evidence: { header: 'Access-Control-Allow-Origin', value: '*' },
          remediation: `// Replace wildcard with explicit origins:\napp.use(cors({\n  origin: ['https://yourdomain.com', 'https://app.yourdomain.com'],\n  credentials: true\n}));`
        });
      }

      // Check if credentials allowed with wildcard
      if (origin === '*' && h['access-control-allow-credentials'] === 'true') {
        findings.push({
          type: 'CORS', severity: 'high', cvss_score: 8.1, owasp: 'API8:2023',
          title: 'CORS: Credentials Allowed With Wildcard Origin',
          endpoint: endpoints[0].url, method: 'GET',
          description: 'Wildcard CORS with credentials:true is rejected by browsers but indicates a dangerous misconfiguration intent.',
          evidence: { 'access-control-allow-origin': origin, 'access-control-allow-credentials': 'true' },
          remediation: `Never combine wildcard with credentials.\nUse specific origins when credentials are needed.`
        });
      }
    } catch (e) {}
    return findings;
  }
}
module.exports = MisconfigScanner;
