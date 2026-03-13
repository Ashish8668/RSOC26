class RateLimitScanner {
  constructor(axiosInstance, inputData = {}) {
    this.axios = axiosInstance;
    this.inputData = inputData;
  }

  async scan(endpoints) {
    const findings = [];
    const loginTargets = endpoints.filter(e => e.method === 'POST' && /login|signin|auth|token/i.test(e.url || ''));
    const generalTargets = endpoints.filter(e => e.method === 'GET').slice(0, 2);
    const targets = [...loginTargets.slice(0, 2), ...generalTargets].slice(0, 3);

    for (const ep of targets) {
      const count = this.getBurstCount();
      const startedAt = Date.now();
      const requests = Array.from({ length: count }, (_, i) =>
        this.axios({
          method: ep.method,
          url: ep.url,
          data: ep.body || { email: `test${i}@example.com`, password: 'WrongPass123!' },
        }).catch(() => null)
      );

      const results = await Promise.allSettled(requests);
      const elapsedMs = Date.now() - startedAt;
      const statuses = results.map(r => r.value?.status).filter(Boolean);
      const throttleStatuses = new Set([429, 503]);
      const throttledIndexes = statuses
        .map((s, idx) => (throttleStatuses.has(s) ? idx + 1 : null))
        .filter(Boolean);

      const blocked = statuses.filter(s => throttleStatuses.has(s)).length;
      const ok = statuses.filter(s => s < 400 || s === 401).length;
      const rps = elapsedMs > 0 ? Number((count / (elapsedMs / 1000)).toFixed(1)) : count;
      const throttleKickIn = throttledIndexes.length > 0 ? throttledIndexes[0] : null;
      const isLogin = /login|signin|auth|token/i.test(ep.url || '');

      if (blocked === 0 && ok >= Math.floor(count * 0.9)) {
        findings.push({
          type: 'RATE_LIMIT',
          severity: isLogin ? 'high' : 'medium',
          confidence: 'Confirmed',
          cvss_score: isLogin ? 7.8 : 5.8,
          owasp: 'API4:2023',
          title: isLogin ? 'No Rate Limit on Authentication Endpoint' : 'No API Rate Limiting Detected',
          endpoint: ep.url,
          method: ep.method,
          description: `${count} rapid requests were accepted with no throttling responses.`,
          evidence: {
            requests_sent: count,
            accepted_or_401: ok,
            blocked,
            measured_rps: rps,
            throttle_kick_in_request: 'none',
          },
          replay: {
            request: { method: ep.method, url: ep.url, burst_requests: count },
            insecure_response: { blocked_requests: blocked, sample_statuses: statuses.slice(0, 10) },
            expected_secure_response: { status: 429, description: `Throttle after threshold at ~${isLogin ? 5 : 100} req/window` },
          },
          remediation: `Apply route-level throttling (e.g., express-rate-limit with ${isLogin ? 'max: 5' : 'max: 100'} per 15 minutes).`,
        });
      } else if (throttleKickIn && throttleKickIn > Math.floor(count * 0.9)) {
        findings.push({
          type: 'RATE_LIMIT',
          severity: 'low',
          confidence: 'Likely',
          cvss_score: 3.7,
          owasp: 'API4:2023',
          title: 'Rate Limiting Exists but Triggers Too Late',
          endpoint: ep.url,
          method: ep.method,
          description: `Throttling started only at request #${throttleKickIn} (~${rps} req/s), which may still permit abuse.`,
          evidence: {
            requests_sent: count,
            blocked,
            measured_rps: rps,
            throttle_kick_in_request: throttleKickIn,
          },
          remediation: 'Lower burst/attempt thresholds and enforce progressive lockout on sensitive endpoints.',
        });
      }
    }
    return findings;
  }

  getBurstCount() {
    const envCount = parseInt(process.env.RATE_LIMIT_TEST_COUNT || '', 10);
    if (Number.isFinite(envCount) && envCount >= 50 && envCount <= 100) return envCount;
    if (Number.isFinite(this.inputData.rateLimitCount)) return this.inputData.rateLimitCount;
    return 75;
  }
}

module.exports = RateLimitScanner;
