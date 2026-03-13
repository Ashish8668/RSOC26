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
  try { return new URL(url).pathname; } catch { return url; }
}

module.exports = { parsePostmanCollection, parseOpenAPISpec, crawlEndpoints };
