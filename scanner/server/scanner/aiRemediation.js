const https = require('https');

async function generateAIRemediation(finding) {
  if (process.env.GROQ_API_KEY) return callGroq(finding);
  return finding.remediation || 'Apply security best practices for this vulnerability type.';
}

function callGroq(finding) {
  const prompt = [
    'You are a senior API security engineer.',
    `Type: ${finding.type}`,
    `Severity: ${finding.severity}`,
    `Title: ${finding.title}`,
    `Endpoint: ${finding.endpoint}`,
    `Description: ${finding.description}`,
    'Return a concise remediation with one practical Node.js/Express fix snippet.',
  ].join('\n');

  const apiUrl = process.env.GROQ_API_URL || 'https://api.groq.com/openai/v1/chat/completions';
  const model = process.env.GROQ_MODEL || 'llama-3.3-70b-versatile';
  const url = new URL(apiUrl);
  const body = JSON.stringify({
    model,
    temperature: 0.2,
    max_tokens: 300,
    messages: [{ role: 'user', content: prompt }],
  });

  return new Promise((resolve) => {
    const req = https.request({
      hostname: url.hostname,
      path: `${url.pathname}${url.search || ''}`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${process.env.GROQ_API_KEY}`,
        'Content-Length': Buffer.byteLength(body),
      },
    }, (res) => {
      let data = '';
      res.on('data', c => { data += c; });
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          const text = parsed?.choices?.[0]?.message?.content;
          resolve(text || finding.remediation);
        } catch {
          resolve(finding.remediation);
        }
      });
    });

    req.on('error', () => resolve(finding.remediation));
    req.setTimeout(8000, () => { req.destroy(); resolve(finding.remediation); });
    req.write(body);
    req.end();
  });
}

module.exports = { generateAIRemediation };
