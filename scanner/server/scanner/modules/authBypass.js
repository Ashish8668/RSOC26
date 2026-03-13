const jwt = require('jsonwebtoken');

class AuthScanner {
  constructor(axiosInstance) {
    this.axios = axiosInstance;
  }

  async scan(endpoints) {
    const findings = [];
    const protectedCandidates = endpoints.filter(e =>
      /\/admin|\/users|\/user|\/orders|\/account|\/profile|\/private|\/auth/i.test(e.url || '')
    );

    const expiredToken = jwt.sign({ id: 1337, role: 'user' }, 'scanner-expired-secret', {
      algorithm: 'HS256',
      expiresIn: -60,
    });
    const malformedToken = 'this.is.not-a-valid-jwt';
    const algNoneToken = 'eyJhbGciOiJub25lIn0.eyJpZCI6MSwicm9sZSI6ImFkbWluIn0.';
    const confusionToken = jwt.sign({ id: 1, role: 'admin' }, '-----BEGIN PUBLIC KEY-----fake-----END PUBLIC KEY-----', {
      algorithm: 'HS256',
      header: { alg: 'HS256', typ: 'JWT' },
    });

    for (const ep of protectedCandidates.slice(0, 12)) {
      const method = ep.method || 'GET';
      try {
        const noTokenResp = await this.axios({
          method,
          url: ep.url,
          headers: { Authorization: '' },
          data: ep.body || {},
        }).catch(() => null);

        if (noTokenResp && noTokenResp.status === 200) {
          findings.push({
            type: 'AUTH_BYPASS',
            severity: /\/admin/i.test(ep.url || '') ? 'critical' : 'high',
            confidence: 'Confirmed',
            cvss_score: /\/admin/i.test(ep.url || '') ? 9.8 : 8.2,
            owasp: 'API2:2023',
            title: 'Protected Endpoint Accessible Without Token',
            endpoint: ep.url,
            method,
            description: 'Endpoint appears sensitive but responds with 200 when Authorization token is missing.',
            evidence: { test: 'no_token', status: noTokenResp.status, body_preview: JSON.stringify(noTokenResp.data || '').slice(0, 220) },
            replay: {
              request: { method, url: ep.url, headers: { Authorization: '' } },
              insecure_response: { status: noTokenResp.status },
              expected_secure_response: { status: 401, message: 'Missing token' },
            },
            remediation: 'Require authentication middleware on this route and return 401 for missing tokens.',
          });
        }

        await this.checkInvalidToken(findings, ep, method, 'expired_jwt', expiredToken, 'Expired JWT accepted');
        await this.checkInvalidToken(findings, ep, method, 'malformed_jwt', malformedToken, 'Malformed JWT accepted');
        await this.checkInvalidToken(findings, ep, method, 'alg_none', algNoneToken, 'JWT alg:none attack accepted');
        await this.checkInvalidToken(findings, ep, method, 'alg_confusion', confusionToken, 'Potential JWT algorithm confusion accepted');
      } catch {
        // Continue scanning.
      }
    }

    return findings;
  }

  async checkInvalidToken(findings, ep, method, tokenKind, token, title) {
    const resp = await this.axios({
      method,
      url: ep.url,
      headers: { Authorization: `Bearer ${token}` },
      data: ep.body || {},
    }).catch(() => null);

    if (!resp) return;
    const shouldReject = [401, 403].includes(resp.status);
    if (!shouldReject && resp.status < 500) {
      findings.push({
        type: 'JWT',
        severity: tokenKind === 'alg_none' || tokenKind === 'alg_confusion' ? 'critical' : 'high',
        confidence: 'Confirmed',
        cvss_score: tokenKind === 'alg_none' || tokenKind === 'alg_confusion' ? 9.8 : 8.1,
        owasp: 'API2:2023',
        title,
        endpoint: ep.url,
        method,
        description: `Endpoint did not reject ${tokenKind.replace('_', ' ')} token. Expected 401/403 but got ${resp.status}.`,
        evidence: {
          token_type: tokenKind,
          response_status: resp.status,
          response_preview: JSON.stringify(resp.data || '').slice(0, 220),
        },
        replay: {
          request: { method, url: ep.url, headers: { Authorization: `Bearer <${tokenKind}>` } },
          insecure_response: { status: resp.status },
          expected_secure_response: { status: 401, message: 'Invalid token' },
        },
        remediation: 'Strictly validate JWT signature, expiration, and allowed algorithms (e.g., jwt.verify(token, key, { algorithms: ["RS256"] })).',
      });
    }
  }
}

module.exports = AuthScanner;
