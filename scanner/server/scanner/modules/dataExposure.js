class DataExposureScanner {
  constructor(axiosInstance) {
    this.axios = axiosInstance;
  }

  async scan(endpoints) {
    const findings = [];
    const patterns = [
      { name: 'Email Address', regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/, severity: 'low', cvss: 3.1 },
      { name: 'Phone Number', regex: /\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?){2}\d{4}\b/, severity: 'medium', cvss: 4.8 },
      { name: 'SSN', regex: /\b\d{3}-\d{2}-\d{4}\b/, severity: 'critical', cvss: 8.5 },
      { name: 'Credit Card', regex: /\b(?:4\d{3}|5[1-5]\d{2})(?:[-\s]?\d{4}){3}\b/, severity: 'critical', cvss: 9.1 },
      { name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/, severity: 'critical', cvss: 9.8 },
      { name: 'Private Key', regex: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/, severity: 'critical', cvss: 9.8 },
      { name: 'Internal IP', regex: /\b(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)\b/, severity: 'low', cvss: 3.1 },
      { name: 'Password Field', regex: /"(password|pwd|pass|secret|token)"\s*:\s*"[^"]+"/i, severity: 'high', cvss: 7.5 },
    ];

    for (const ep of endpoints.filter(e => e.method === 'GET').slice(0, 25)) {
      try {
        const resp = await this.axios({ method: 'GET', url: ep.url }).catch(() => null);
        if (!resp || resp.status !== 200) continue;

        const body = JSON.stringify(resp.data || '');
        const matched = patterns.find(p => p.regex.test(body));
        if (matched) {
          findings.push({
            type: 'DATA_EXPOSURE',
            severity: matched.severity,
            confidence: 'Confirmed',
            cvss_score: matched.cvss,
            owasp: 'API3:2023',
            title: `Sensitive Data Exposure: ${matched.name}`,
            endpoint: ep.url,
            method: 'GET',
            description: `Response contains ${matched.name}, which should not be returned to clients.`,
            evidence: {
              pattern: matched.name,
              response_status: resp.status,
              preview: String((body.match(matched.regex) || ['detected'])[0]).slice(0, 120),
            },
            remediation: 'Return only whitelisted safe fields via DTO/serializer and remove sensitive attributes from API responses.',
          });
        }

        // Excessive data exposure check: ask for a single field, but API returns many.
        const limitedUrl = this.appendQuery(ep.url, 'fields=id');
        const limitedResp = await this.axios({ method: 'GET', url: limitedUrl }).catch(() => null);
        if (!limitedResp || limitedResp.status !== 200) continue;

        const returnedKeys = this.extractKeys(limitedResp.data);
        if (returnedKeys.length >= 5 && !returnedKeys.every(k => k === 'id')) {
          findings.push({
            type: 'DATA_EXPOSURE',
            severity: 'medium',
            confidence: 'Likely',
            cvss_score: 5.3,
            owasp: 'API3:2023',
            title: 'Excessive Data Returned',
            endpoint: ep.url,
            method: 'GET',
            description: 'Request asked for limited fields (fields=id), but response still returned many properties.',
            evidence: {
              requested_fields: ['id'],
              returned_fields: returnedKeys.slice(0, 20),
              returned_field_count: returnedKeys.length,
            },
            replay: {
              request: { method: 'GET', url: limitedUrl },
              insecure_response: { returned_fields: returnedKeys.slice(0, 20) },
              expected_secure_response: { returned_fields: ['id'] },
            },
            remediation: 'Implement explicit field-level response filtering and honor field projection parameters.',
          });
        }
      } catch {
        // Keep scanning remaining endpoints.
      }
    }

    return findings;
  }

  appendQuery(url, pair) {
    if (url.includes('?')) return `${url}&${pair}`;
    return `${url}?${pair}`;
  }

  extractKeys(data) {
    if (Array.isArray(data) && data[0] && typeof data[0] === 'object') return Object.keys(data[0]);
    if (data && typeof data === 'object') return Object.keys(data);
    return [];
  }
}

module.exports = DataExposureScanner;
