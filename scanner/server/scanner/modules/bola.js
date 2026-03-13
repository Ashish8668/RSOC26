class BOLAScanner {
  constructor(axiosInstance, inputData = {}) {
    this.axios = axiosInstance;
    this.inputData = inputData;
  }

  async scan(endpoints) {
    const findings = [];
    const tested = new Set();

    for (const ep of endpoints) {
      if (!['GET', 'PUT', 'PATCH', 'DELETE'].includes(ep.method)) continue;
      const idMatch = (ep.url || '').match(/\/(\d+)(?=\/|$|\?)/);
      if (!idMatch) continue;

      const originalId = Number(idMatch[1]);
      const candidateIds = [originalId + 1, originalId + 2].filter(n => n > 0);
      const key = `${ep.method}:${ep.url}`;
      if (tested.has(key)) continue;
      tested.add(key);

      try {
        const originalResp = await this.axios({ method: ep.method, url: ep.url }).catch(() => null);
        if (!originalResp || originalResp.status !== 200) continue;

        for (const altId of candidateIds) {
          const testUrl = ep.url.replace(`/${originalId}`, `/${altId}`);
          const testResp = await this.axios({ method: ep.method, url: testUrl }).catch(() => null);
          if (!testResp || testResp.status !== 200) continue;

          const originalBody = JSON.stringify(originalResp.data || '');
          const testBody = JSON.stringify(testResp.data || '');
          if (originalBody !== testBody && originalBody.length > 10 && testBody.length > 10) {
            findings.push({
              type: 'BOLA',
              severity: 'critical',
              confidence: 'Confirmed',
              cvss_score: 9.1,
              owasp: 'API1:2023',
              title: 'Broken Object Level Authorization (IDOR/BOLA)',
              endpoint: ep.url,
              method: ep.method,
              description: `ID tampering (${originalId} -> ${altId}) returns a different record under the same auth context.`,
              evidence: {
                original_url: ep.url,
                tested_url: testUrl,
                original_status: originalResp.status,
                test_status: testResp.status,
                original_preview: originalBody.slice(0, 180),
                test_preview: testBody.slice(0, 180),
              },
              replay: {
                request: { method: ep.method, url: testUrl, headers: { Authorization: 'same-as-original' } },
                insecure_response: { status: testResp.status, body_preview: testBody.slice(0, 180) },
                expected_secure_response: { status: 403, message: 'Forbidden for non-owner' },
              },
              remediation: 'Enforce object ownership checks on every resource access (e.g., return 403 when resource.userId !== req.user.id).',
            });
            break;
          }
        }
      } catch {
        // Continue scanning remaining endpoints.
      }
    }

    // Vertical privilege check: user token should not access admin endpoints.
    const token = this.inputData.authToken;
    const adminEndpoints = endpoints.filter(e => /\/admin|\/manage|\/root/i.test(e.url || ''));
    if (token && adminEndpoints.length > 0) {
      for (const ep of adminEndpoints.slice(0, 5)) {
        try {
          const resp = await this.axios({
            method: ep.method || 'GET',
            url: ep.url,
            headers: { Authorization: `Bearer ${token}` },
          }).catch(() => null);

          if (resp && resp.status === 200) {
            findings.push({
              type: 'BOLA',
              severity: 'high',
              confidence: 'Likely',
              cvss_score: 8.6,
              owasp: 'API1:2023',
              title: 'Potential Vertical Privilege Escalation',
              endpoint: ep.url,
              method: ep.method || 'GET',
              description: 'A provided user token can access an admin-like endpoint. Role-based authorization may be missing.',
              evidence: { endpoint: ep.url, response_status: resp.status, preview: JSON.stringify(resp.data || '').slice(0, 220) },
              replay: {
                request: { method: ep.method || 'GET', url: ep.url, headers: { Authorization: 'Bearer <user_token>' } },
                insecure_response: { status: resp.status },
                expected_secure_response: { status: 403, message: 'Admin role required' },
              },
              remediation: 'Apply explicit role checks on privileged routes (e.g., requireRole("admin")).',
            });
          }
        } catch {
          // Keep scanning.
        }
      }
    }

    return findings;
  }
}

module.exports = BOLAScanner;
