class RateLimitScanner {
  constructor(axiosInstance) { this.axios = axiosInstance; }

  async scan(endpoints) {
    const findings = [];
    const targets = endpoints.filter(e => e.method === 'POST' && /login|signin|auth|token/i.test(e.url));
    const testTargets = targets.length > 0 ? targets : endpoints.filter(e => e.method === 'GET').slice(0, 2);

    for (const ep of testTargets.slice(0, 3)) {
      const count = parseInt(process.env.RATE_LIMIT_TEST_COUNT) || 30;
      const requests = Array(count).fill(null).map(() =>
        this.axios({ method: ep.method, url: ep.url, data: ep.body || { email: 'test@test.com', password: 'wrong' } }).catch(() => null)
      );
      const results = await Promise.allSettled(requests);
      const statuses = results.map(r => r.value?.status).filter(Boolean);
      const blocked = statuses.filter(s => s === 429 || s === 503).length;
      const succeeded = statuses.filter(s => s < 400 || s === 401).length;

      if (blocked === 0 && succeeded > count * 0.7) {
        const isLogin = /login|signin|auth/i.test(ep.url);
        findings.push({
          type: 'RATE_LIMIT', severity: isLogin ? 'high' : 'medium', cvss_score: isLogin ? 7.5 : 5.3, owasp: 'API4:2023',
          title: isLogin ? 'No Rate Limiting on Login — Brute Force Possible' : 'No Rate Limiting Detected',
          endpoint: ep.url, method: ep.method,
          description: `Sent ${count} rapid requests to ${ep.url}. All ${succeeded} succeeded with no throttling. ${isLogin ? 'Attacker can brute-force passwords.' : 'API is vulnerable to abuse/DoS.'}`,
          evidence: { requests_sent: count, succeeded, blocked, endpoint: ep.url },
          remediation: `npm install express-rate-limit\n\nconst rateLimit = require('express-rate-limit');\nconst limiter = rateLimit({\n  windowMs: 15 * 60 * 1000,\n  max: ${isLogin ? 5 : 100},\n  message: { error: 'Too many requests' }\n});\napp.${ep.method.toLowerCase()}('${ep.path}', limiter, handler);`
        });
      }
    }
    return findings;
  }
}
module.exports = RateLimitScanner;
