const https = require('https');

async function generateAIRemediation(finding) {
  if (process.env.ANTHROPIC_API_KEY) return callAnthropic(finding);
  return finding.remediation || 'Apply security best practices for this vulnerability type.';
}

function callAnthropic(finding) {
  const prompt = `You are a senior API security engineer. A vulnerability was found:\nType: ${finding.type}\nSeverity: ${finding.severity}\nTitle: ${finding.title}\nEndpoint: ${finding.endpoint}\nDescription: ${finding.description}\n\nProvide a concise 3-4 line fix with a Node.js/Express code snippet. Be specific.`;
  const body = JSON.stringify({ model: 'claude-haiku-4-5-20251001', max_tokens: 300, messages: [{ role: 'user', content: prompt }] });

  return new Promise((resolve) => {
    const req = https.request({
      hostname: 'api.anthropic.com', path: '/v1/messages', method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01', 'Content-Length': Buffer.byteLength(body) }
    }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try { resolve(JSON.parse(data).content?.[0]?.text || finding.remediation); }
        catch { resolve(finding.remediation); }
      });
    });
    req.on('error', () => resolve(finding.remediation));
    req.setTimeout(8000, () => { req.destroy(); resolve(finding.remediation); });
    req.write(body); req.end();
  });
}

module.exports = { generateAIRemediation };
