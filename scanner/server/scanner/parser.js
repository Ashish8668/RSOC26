function parsePostmanCollection(collection, baseUrl) {
  const endpoints = [];
  function extractItems(items) {
    if (!items) return;
    for (const item of items) {
      if (item.item) { extractItems(item.item); continue; }
      if (!item.request) continue;
      const req = item.request;
      let url = typeof req.url === 'string' ? req.url : (req.url?.raw || '');
      url = url.replace(/{{[^}]+}}/g, baseUrl || '').split('?')[0];
      if (url.startsWith('/')) url = (baseUrl || '') + url;
      const pathParams = (url.match(/:([a-zA-Z_]\w*)/g) || []).map(p => p.slice(1));
      let body = null;
      if (req.body?.mode === 'raw' && req.body.raw) {
        try { body = JSON.parse(req.body.raw); } catch { body = req.body.raw; }
      }
      if (url && req.method) endpoints.push({ method: req.method.toUpperCase(), url, path: extractPath(url), name: item.name, pathParams, body, headers: {} });
    }
  }
  extractItems(collection.item);
  return endpoints;
}

function parseOpenAPISpec(spec, baseUrl) {
  const endpoints = [];
  let base = baseUrl || (spec.servers?.[0]?.url) || (spec.host ? `https://${spec.host}${spec.basePath||''}` : '');
  for (const [path, pathObj] of Object.entries(spec.paths || {})) {
    for (const method of ['get','post','put','patch','delete','options']) {
      if (!pathObj[method]) continue;
      const op = pathObj[method];
      const pathParams = (path.match(/{([^}]+)}/g) || []).map(p => p.slice(1,-1));
      let body = null;
      if (op.requestBody?.content?.['application/json']?.example) body = op.requestBody.content['application/json'].example;
      endpoints.push({ method: method.toUpperCase(), url: `${base}${path}`, path, name: op.summary || `${method.toUpperCase()} ${path}`, pathParams, body, headers: {} });
    }
  }
  return endpoints;
}

function parseCurlCommands(rawInput, baseUrl) {
  const endpoints = [];
  if (!rawInput || typeof rawInput !== 'string') return endpoints;

  const commands = normalizeCurlCommands(rawInput);
  for (const cmd of commands) {
    const parsed = parseSingleCurl(cmd, baseUrl);
    if (parsed) endpoints.push(parsed);
  }
  return endpoints;
}

function normalizeCurlCommands(rawInput) {
  const lines = rawInput.split(/\r?\n/);
  const commands = [];
  let buffer = '';

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    if (trimmed.startsWith('curl ') && buffer) {
      commands.push(buffer.trim());
      buffer = trimmed;
      continue;
    }

    buffer = buffer ? `${buffer} ${trimmed}` : trimmed;
    if (!trimmed.endsWith('\\')) {
      commands.push(buffer.replace(/\\\s*/g, ' ').trim());
      buffer = '';
    }
  }

  if (buffer) commands.push(buffer.replace(/\\\s*/g, ' ').trim());
  return commands.filter(c => c.startsWith('curl '));
}

function parseSingleCurl(cmd, baseUrl) {
  let method = 'GET';
  const methodMatch = cmd.match(/(?:-X|--request)\s+([A-Za-z]+)/i);
  if (methodMatch) method = methodMatch[1].toUpperCase();

  const urlMatch = cmd.match(/(["'])(https?:\/\/[^"']+)\1|(?<![A-Za-z0-9])(https?:\/\/[^\s"']+)/i);
  let url = urlMatch ? (urlMatch[2] || urlMatch[3]) : '';

  if (!url) {
    const relativeMatch = cmd.match(/(["'])(\/[^"']+)\1|(\s\/[^\s"']+)/);
    if (relativeMatch) {
      const rel = (relativeMatch[2] || relativeMatch[3] || '').trim();
      if (rel.startsWith('/') && baseUrl) url = `${baseUrl.replace(/\/$/, '')}${rel}`;
    }
  }
  if (!url) return null;

  const headers = {};
  const headerRegex = /(?:-H|--header)\s+(?:"([^"]+)"|'([^']+)')/g;
  let headerMatch;
  while ((headerMatch = headerRegex.exec(cmd)) !== null) {
    const raw = headerMatch[1] || headerMatch[2];
    const idx = raw.indexOf(':');
    if (idx > 0) headers[raw.slice(0, idx).trim()] = raw.slice(idx + 1).trim();
  }

  let body = null;
  const dataMatch = cmd.match(/(?:--data-raw|--data-binary|--data|-d)\s+(?:"([^"]*)"|'([^']*)')/);
  if (dataMatch) {
    const rawBody = dataMatch[1] || dataMatch[2] || '';
    try { body = JSON.parse(rawBody); } catch { body = rawBody; }
    if (!methodMatch) method = 'POST';
  }

  const path = extractPath(url).split('?')[0];
  const pathParams = (path.match(/:([a-zA-Z_]\w*)/g) || []).map(p => p.slice(1));
  return {
    method,
    url: url.split(' ')[0],
    path,
    name: `curl ${method} ${path}`,
    pathParams,
    body,
    headers
  };
}

async function crawlEndpoints(baseUrl, axiosInstance) {
  const base = baseUrl.replace(/\/$/, '');
  const paths = [
    { method:'POST', path:'/api/auth/login' }, { method:'POST', path:'/api/login' }, { method:'POST', path:'/login' },
    { method:'GET', path:'/api/users' }, { method:'GET', path:'/api/users/1' }, { method:'GET', path:'/api/users/2' },
    { method:'GET', path:'/api/users/me' }, { method:'GET', path:'/api/admin/users' }, { method:'GET', path:'/admin' },
    { method:'GET', path:'/api/products' }, { method:'GET', path:'/api/orders' }, { method:'GET', path:'/api/orders/1' },
    { method:'GET', path:'/api/orders/2' }, { method:'GET', path:'/api' }, { method:'GET', path:'/health' },
    { method:'GET', path:'/swagger.json' }, { method:'GET', path:'/openapi.json' }, { method:'GET', path:'/api-docs' },
  ];
  const results = await Promise.allSettled(paths.map(async ({ method, path }) => {
    try {
      const resp = await axiosInstance({ method, url: `${base}${path}` });
      if (resp.status !== 404 && resp.status !== 502) return { method, url: `${base}${path}`, path, name: `${method} ${path}`, pathParams:[], body:null, headers:{} };
    } catch { return null; }
    return null;
  }));
  return results.filter(r => r.status==='fulfilled' && r.value).map(r => r.value);
}

function extractPath(url) {
  try { return new URL(url).pathname; } catch { return (url || '').split('?')[0]; }
}

module.exports = { parsePostmanCollection, parseOpenAPISpec, parseCurlCommands, crawlEndpoints };
