class JWTScanner {
  constructor(axiosInstance, inputData) { this.axios = axiosInstance; this.inputData = inputData; }

  async scan(endpoints) {
    const findings = [];
    const token = this.inputData?.authToken;

    // If user provided a token, analyse it
    if (token) {
      try {
        const parts = token.split('.');
        if (parts.length !== 3) return findings;
        const header  = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
        const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());

        if (header.alg === 'none' || header.alg === 'NONE') {
          findings.push({ type:'JWT', severity:'critical', cvss_score:9.8, owasp:'API2:2023',
            title:'JWT Uses Algorithm "none" — No Signature Verification',
            endpoint:'JWT Token', method:'N/A',
            description:'Token signed with alg:none has no signature. Anyone can forge tokens for any user.',
            evidence:{ alg: header.alg, header },
            remediation:`jwt.verify(token, SECRET, { algorithms: ['HS256'] });\n// Reject tokens with alg:none`
          });
        }

        if (!payload.exp) {
          findings.push({ type:'JWT', severity:'high', cvss_score:7.5, owasp:'API2:2023',
            title:'JWT Has No Expiration (exp claim missing)',
            endpoint:'JWT Token', method:'N/A',
            description:'Token never expires. A stolen token grants permanent access.',
            evidence:{ payload_keys: Object.keys(payload) },
            remediation:`jwt.sign(payload, SECRET, { expiresIn: '15m' });\n// Use refresh tokens for longer sessions`
          });
        } else if ((payload.exp - Date.now()/1000) > 30 * 86400) {
          findings.push({ type:'JWT', severity:'medium', cvss_score:5.3, owasp:'API2:2023',
            title:'JWT Expiration Exceeds 30 Days',
            endpoint:'JWT Token', method:'N/A',
            description:`Token expires ${Math.round((payload.exp - Date.now()/1000)/86400)} days from now. Long-lived tokens increase risk window.`,
            evidence:{ exp: new Date(payload.exp*1000).toISOString() },
            remediation:`Use short-lived tokens:\njwt.sign(payload, SECRET, { expiresIn: '15m' });\n// Implement refresh token rotation`
          });
        }

        const sensitiveKeys = ['password','pwd','secret','ssn','credit_card','cvv','pin'];
        const found = sensitiveKeys.filter(k => payload[k] !== undefined);
        if (found.length > 0) {
          findings.push({ type:'JWT', severity:'high', cvss_score:7.5, owasp:'API3:2023',
            title:'Sensitive Data Stored in JWT Payload',
            endpoint:'JWT Token', method:'N/A',
            description:`JWT payload contains sensitive field(s): ${found.join(', ')}. JWT is base64 encoded, NOT encrypted — anyone can read it.`,
            evidence:{ sensitive_fields: found },
            remediation:`Only store non-sensitive identifiers in JWT:\njwt.sign({ id: user.id, role: user.role }, SECRET, { expiresIn: '15m' });\n// Never include passwords, SSNs, or PII`
          });
        }

        // Weak secret test
        const weakSecrets = ['secret','secret123','password','12345','jwt_secret','mysecret'];
        for (const ep of endpoints.filter(e => e.method==='GET').slice(0,2)) {
          const resp = await this.axios({ method:'GET', url: ep.url }).catch(() => null);
          if (resp?.data?.jwt_secret) {
            findings.push({ type:'JWT', severity:'critical', cvss_score:9.8, owasp:'API2:2023',
              title:'JWT Secret Exposed in API Response',
              endpoint: ep.url, method:'GET',
              description:`The API response directly exposes the JWT signing secret: "${resp.data.jwt_secret}". Anyone can forge admin tokens.`,
              evidence:{ exposed_secret: resp.data.jwt_secret, endpoint: ep.url },
              remediation:`Never expose secrets in responses. Store secrets in environment variables only:\nprocess.env.JWT_SECRET`
            });
          }
        }
      } catch (e) {}
    }
    return findings;
  }
}
module.exports = JWTScanner;
