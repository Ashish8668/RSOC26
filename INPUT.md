# Input Demo Guide (Clean Version)

Use this file for the two extra scanner inputs:
- `Raw curl`
- `Upload Spec`

## Quick Risk Mapping (Important)
- `http://localhost:3001` = **Vulnerable API** -> usually **more High/Critical risk**
- `http://localhost:3002` = **Safe API** -> usually **lower risk**, stricter `401/403/429`

So in demo:
1. same scanner input type use karo,
2. first vulnerable target scan karo,
3. then safe target scan karo,
4. compare risk summary.

---

## 1) Raw curl Input

## How to use
1. Open scanner UI: `http://localhost:3000`
2. Go to `Raw curl` tab
3. Paste one block below
4. Click `Start Security Scan`

## Example 1 (Vulnerable target - high risk expected)
```bash
curl -X GET http://localhost:3001/api/users/1
curl -X GET http://localhost:3001/api/admin/users
```
What to say:
- This should trigger auth/authorization issues (BOLA/admin access risk).

## Example 2 (Safe target - lower risk expected)
```bash
curl -X GET http://localhost:3002/api/users/1
curl -X GET http://localhost:3002/api/admin/users
```
What to say:
- Same business endpoints, but safe API should enforce proper access controls.

---

## 2) Upload Spec Input

## How to use
1. Go to `Upload Spec` tab
2. Upload `.json` or `.yaml`
3. Click `Start Security Scan`

## Example 1 (Vulnerable JSON spec)
Create file `vuln-spec.json` and upload:
```json
{
  "openapi": "3.0.0",
  "info": { "title": "Vulnerable API", "version": "1.0.0" },
  "servers": [{ "url": "http://localhost:3001" }],
  "paths": {
    "/api/users/1": { "get": { "summary": "User 1" } },
    "/api/users/2": { "get": { "summary": "User 2" } },
    "/api/admin/users": { "get": { "summary": "Admin users" } }
  }
}
```
Expected:
- More severe findings (authorization/auth exposure).

## Example 2 (Safe YAML spec)
Create file `safe-spec.yaml` and upload:
```yaml
openapi: 3.0.0
info:
  title: Safe API
  version: 1.0.0
servers:
  - url: http://localhost:3002
paths:
  /api/users/1:
    get:
      summary: User 1
  /api/admin/users:
    get:
      summary: Admin users
  /api/products:
    get:
      summary: Product search
```
Expected:
- Lower risk summary compared to vulnerable scan.

---

## One-Line Demo Script
- "Same scanner, same input mode, different targets. Vulnerable API shows high risk; safe API shows reduced risk because controls are enforced."
