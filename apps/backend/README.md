# CT Monitor Backend

Backend service that proxies SSLMate Certificate Search API requests for the CT Viewer frontend.

## Configuration

Set the following environment variables before running the server:

- `PORT` (optional, default `3000`)
- `SSL_MATE_API_KEY` (required)
- `SSL_MATE_BASE_URL` (optional, default `https://ctsearch.api.sslmate.com/v1`)

## Scripts

- `npm run build` – compile TypeScript to JavaScript
- `npm start` – start the compiled server

## API

- `GET /health` → `{ "status": "ok" }`
- `GET /api/certs?query=example.com&limit=50`
  - Proxies SSLMate search, enforces a maximum limit of 100 certificates, and normalizes the response.
