class InjectionScanner {
  constructor(axiosInstance) { this.axios = axiosInstance; }

  async scan(endpoints) {
    const findings = [];
    const sqlPayloads = ["'", "' OR '1'='1", "1 OR 1=1", "' UNION SELECT 1,2,3--", "'; DROP TABLE users--"];
    const sqlErrors  = ['syntax error','sqlite','mysql_fetch','ORA-','pg_query','sql','near "',
                        'unterminated quoted','error in your SQL','UNION SELECT'];

    for (const ep of endpoints) {
      try {
        // SQL injection via query params
        const baseUrl = ep.url.split('?')[0];
        for (const payload of sqlPayloads) {
          const testUrl = `${baseUrl}?q=${encodeURIComponent(payload)}&search=${encodeURIComponent(payload)}&id=${encodeURIComponent(payload)}`;
          const resp = await this.axios({ method: 'GET', url: testUrl }).catch(() => null);
          if (!resp) continue;
          const body = JSON.stringify(resp.data || '') + (resp.data?.details || '') + (resp.data?.error || '');
          const matched = sqlErrors.find(e => body.toLowerCase().includes(e.toLowerCase()));

          if (matched || (resp.status === 500 && body.includes('query'))) {
            findings.push({
              type: 'INJECTION', severity: 'critical', cvss_score: 9.8, owasp: 'API8:2023',
              title: 'SQL Injection Vulnerability',
              endpoint: ep.url, method: 'GET',
              description: `Payload "${payload}" caused a SQL error: "${matched}". Attacker can read/modify/delete entire database.`,
              evidence: { payload, triggered_error: matched || 'SQL error in response', test_url: testUrl, status: resp.status, preview: body.slice(0,300) },
              remediation: `Use parameterized queries — NEVER string concatenation:\n// WRONG: \`SELECT * WHERE name LIKE '%\${input}%'\`\n// RIGHT:\nconst results = db.prepare('SELECT * FROM products WHERE name LIKE ?').all(\`%\${input}%\`);`
            });
            break;
          }
        }

        // XSS reflection test on POST bodies
        if (ep.method === 'POST') {
          const xssPayload = '<script>alert(1)</script>';
          const resp = await this.axios({ method: 'POST', url: ep.url, data: { name: xssPayload, search: xssPayload } }).catch(() => null);
          if (resp && JSON.stringify(resp.data || '').includes(xssPayload)) {
            findings.push({
              type: 'INJECTION', severity: 'medium', cvss_score: 6.1, owasp: 'API8:2023',
              title: 'Reflected XSS in API Response',
              endpoint: ep.url, method: 'POST',
              description: 'API reflects user input without sanitization. If consumed by a web client, could execute scripts.',
              evidence: { payload: xssPayload, reflected: true },
              remediation: `Sanitize all user input:\nconst { JSDOM } = require('jsdom');\n// Or use DOMPurify server-side\n// Validate input types strictly`
            });
          }
        }
      } catch (e) {}
    }
    return findings;
  }
}
module.exports = InjectionScanner;
