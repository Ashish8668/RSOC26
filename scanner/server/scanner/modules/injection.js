class InjectionScanner {
  constructor(axiosInstance) {
    this.axios = axiosInstance;
  }

  async scan(endpoints) {
    const findings = [];
    const sqlPayloads = ["'", "1=1--", "' OR 1=1--", "' UNION SELECT 1,2,3--"];
    const sqlErrorHints = ['syntax error', 'sqlite', 'mysql', 'sql', 'query failed', 'unterminated', 'ORA-', 'pg_'];

    for (const ep of endpoints.filter(e => e.method === 'GET').slice(0, 20)) {
      try {
        const baseUrl = (ep.url || '').split('?')[0];

        for (const payload of sqlPayloads) {
          const testUrl = `${baseUrl}?q=${encodeURIComponent(payload)}&search=${encodeURIComponent(payload)}&id=${encodeURIComponent(payload)}`;
          const resp = await this.axios({ method: 'GET', url: testUrl }).catch(() => null);
          if (!resp) continue;

          const body = JSON.stringify(resp.data || '').toLowerCase();
          const matched = sqlErrorHints.find(h => body.includes(h));
          if (matched || (resp.status >= 500 && body.includes('query'))) {
            findings.push({
              type: 'INJECTION',
              severity: 'critical',
              confidence: 'Confirmed',
              cvss_score: 9.8,
              owasp: 'API8:2023',
              title: 'SQL Injection Behavior Detected',
              endpoint: ep.url,
              method: 'GET',
              description: `SQL payload (${payload}) triggered database-error behavior.`,
              evidence: {
                payload,
                tested_url: testUrl,
                response_status: resp.status,
                matched_hint: matched || 'server error with query context',
                preview: JSON.stringify(resp.data || '').slice(0, 260),
              },
              replay: {
                request: { method: 'GET', url: testUrl },
                insecure_response: { status: resp.status, hint: matched || 'SQL error traces returned' },
                expected_secure_response: { status: 200, message: 'Safely parameterized query with no SQL error details' },
              },
              remediation: 'Use parameterized queries/prepared statements and never concatenate user input into SQL.',
            });
            break;
          }
        }

        // SSRF probe through common URL-like parameters.
        const ssrfTarget = 'http://169.254.169.254/latest/meta-data/';
        const ssrfUrl = `${baseUrl}?url=${encodeURIComponent(ssrfTarget)}&target=${encodeURIComponent(ssrfTarget)}&redirect=${encodeURIComponent(ssrfTarget)}`;
        const ssrfResp = await this.axios({ method: 'GET', url: ssrfUrl }).catch(() => null);
        if (ssrfResp) {
          const body = JSON.stringify(ssrfResp.data || '').toLowerCase();
          const suspicious = body.includes('meta-data') || body.includes('iam/') || body.includes('169.254.169.254');
          const backendFetchError = ssrfResp.status >= 500 && /econnrefused|timed out|socket|connect/i.test(body);
          if (suspicious || backendFetchError) {
            findings.push({
              type: 'INJECTION',
              severity: suspicious ? 'critical' : 'high',
              confidence: suspicious ? 'Confirmed' : 'Likely',
              cvss_score: suspicious ? 9.1 : 7.5,
              owasp: 'API8:2023',
              title: 'Potential SSRF via URL Parameter',
              endpoint: ep.url,
              method: 'GET',
              description: 'Supplying an internal metadata URL produced behavior consistent with server-side URL fetching.',
              evidence: {
                payload: ssrfTarget,
                tested_url: ssrfUrl,
                response_status: ssrfResp.status,
                preview: JSON.stringify(ssrfResp.data || '').slice(0, 240),
              },
              replay: {
                request: { method: 'GET', url: ssrfUrl },
                insecure_response: { status: ssrfResp.status, preview: JSON.stringify(ssrfResp.data || '').slice(0, 120) },
                expected_secure_response: { status: 400, message: 'Blocked disallowed outbound host' },
              },
              remediation: 'Block private/link-local IP ranges and use strict outbound allowlists for server-side URL fetches.',
            });
          }
        }
      } catch {
        // Continue scanning.
      }
    }
    return findings;
  }
}

module.exports = InjectionScanner;
