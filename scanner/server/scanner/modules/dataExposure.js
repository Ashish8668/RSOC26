class DataExposureScanner {
  constructor(axiosInstance) { this.axios = axiosInstance; }

  async scan(endpoints) {
    const findings = [];
    const patterns = [
      { name: 'Password Hash',  regex: /\$2[aby]\$\d+\$[./A-Za-z0-9]{53}/,        severity: 'critical', cvss: 9.1 },
      { name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/,                         severity: 'critical', cvss: 9.8 },
      { name: 'Private Key',    regex: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/,    severity: 'critical', cvss: 9.8 },
      { name: 'JWT Secret',     regex: /"(jwt_secret|secret|jwtSecret)"\s*:\s*"[^"]{4,}"/i, severity: 'critical', cvss: 9.8 },
      { name: 'Credit Card',    regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|4[0-9]{3}[-\s])/,  severity: 'critical', cvss: 9.1 },
      { name: 'SSN',            regex: /\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b/,           severity: 'critical', cvss: 8.5 },
      { name: 'Email Address',  regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, severity: 'low', cvss: 3.1 },
      { name: 'Stack Trace',    regex: /at [A-Za-z]+ \(.*\.js:\d+:\d+\)/,          severity: 'medium', cvss: 5.3 },
      { name: 'Internal IP',    regex: /\b(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)/, severity: 'low', cvss: 3.1 },
    ];

    for (const ep of endpoints) {
      if (ep.method !== 'GET') continue;
      try {
        const resp = await this.axios({ method: 'GET', url: ep.url }).catch(() => null);
        if (!resp || resp.status !== 200) continue;
        const body = JSON.stringify(resp.data || '');

        for (const p of patterns) {
          if (!p.regex.test(body)) continue;
          const match = body.match(p.regex);
          findings.push({
            type: 'DATA_EXPOSURE', severity: p.severity, cvss_score: p.cvss, owasp: 'API3:2023',
            title: `Sensitive Data Exposed: ${p.name}`,
            endpoint: ep.url, method: 'GET',
            description: `API response contains ${p.name}. This data should never appear in API responses.`,
            evidence: { matched_pattern: p.name, preview: match ? String(match[0]).slice(0,40)+'...' : 'detected', status: resp.status },
            remediation: `Filter sensitive fields from responses:\nconst safeUser = { id: user.id, name: user.name, email: user.email };\n// Never include: password, ssn, credit_card, private keys`
          });
          break;
        }
      } catch (e) {}
    }
    return findings;
  }
}
module.exports = DataExposureScanner;
