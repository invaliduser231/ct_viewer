import 'dotenv/config';
import axios from 'axios';
import cors from 'cors';
import express, { Request, Response } from 'express';
import rateLimit from 'express-rate-limit';

interface CertificateDto {
  id: string;
  domain: string;
  altNames: string[];
  issuer: string;
  notBefore: string;
  notAfter: string;
  loggedAt: string;
  status: 'valid' | 'expired' | 'revoked';
  serial: string;
  sha256: string | null;
  logName: string;
}

interface SslmateCertificate {
  id?: string;
  dns_names?: string[];
  common_name?: string;
  issuer?: string | { name?: string; common_name?: string };
  not_before?: string;
  not_after?: string;
  entry_timestamp?: string;
  serial_number?: string;
  fingerprint_sha256?: string | null;
  log?: { name?: string };
  logged_at?: string;
  notBefore?: string;
  notAfter?: string;
  serial?: string;
  sha256?: string | null;
  log_name?: string;
  updated_at?: string;
}

interface SslmateResponse {
  certificates?: SslmateCertificate[];
  data?: SslmateCertificate[];
  total_count?: number;
}

const PORT = Number(process.env.PORT) || 3000;
const SSL_MATE_BASE_URL = process.env.SSL_MATE_BASE_URL || 'https://ctsearch.api.sslmate.com/v1';
const SSL_MATE_API_KEY = process.env.SSL_MATE_API_KEY;
const REQUEST_TIMEOUT_MS = 8000;
const MAX_LIMIT = 100;

const app = express();

app.set('trust proxy', true);
app.use(cors());
app.use(express.json());

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    const forwarded = (req.headers['x-forwarded-for'] as string | undefined)?.split(',')[0].trim();
    return forwarded || req.ip || 'unknown';
  },
});

app.use(limiter);

app.get('/health', (_req: Request, res: Response) => {
  res.json({ status: 'ok' });
});

app.get('/api/certs', async (req: Request, res: Response) => {
  const rawQuery = Array.isArray(req.query.query) ? req.query.query[0] : req.query.query;
  const query = typeof rawQuery === 'string' ? rawQuery.trim() : '';

  if (!query) {
    return res.status(400).json({ error: 'bad_request', message: 'query parameter is required' });
  }

  const rawLimit = Array.isArray(req.query.limit) ? req.query.limit[0] : req.query.limit;
  const parsedLimit = rawLimit ? Number(rawLimit) : Number.NaN;
  const limit = Number.isInteger(parsedLimit) && parsedLimit > 0 ? Math.min(parsedLimit, MAX_LIMIT) : MAX_LIMIT;

  if (!SSL_MATE_API_KEY) {
    console.error('SSLMate API key is not configured.');
    return res.status(500).json({
      error: 'configuration_error',
      message: 'Certificate search is not configured',
    });
  }

  try {
    const url = new URL('/certificates', SSL_MATE_BASE_URL);
    url.searchParams.set('query', query);
    url.searchParams.set('limit', limit.toString());

    const response = await axios.get<SslmateResponse>(url.toString(), {
      headers: {
        Authorization: `Bearer ${SSL_MATE_API_KEY}`,
      },
      timeout: REQUEST_TIMEOUT_MS,
    });

    const certificates = (response.data.certificates || response.data.data || []).slice(0, limit);
    const mapped = certificates.map(mapCertificateDto);
    const count = typeof response.data.total_count === 'number' ? response.data.total_count : mapped.length;

    res.json({ query, count, certificates: mapped });
  } catch (error) {
    console.error('Failed to query SSLMate CT search API', error);
    res.status(502).json({
      error: 'upstream_error',
      message: 'Failed to query transparency provider',
    });
  }
});

function mapCertificateDto(cert: SslmateCertificate): CertificateDto {
  const domainCandidate = cert.common_name || cert.dns_names?.[0] || '';
  const altNames = Array.isArray(cert.dns_names) ? cert.dns_names : [];
  const issuer = typeof cert.issuer === 'string'
    ? cert.issuer
    : cert.issuer?.name || cert.issuer?.common_name || 'unknown';
  const notBefore = cert.not_before || cert.notBefore || '';
  const notAfter = cert.not_after || cert.notAfter || '';
  const loggedAt = cert.entry_timestamp || cert.logged_at || cert.updated_at || '';
  const serial = cert.serial_number || cert.serial || '';
  const sha256 = cert.fingerprint_sha256 || cert.sha256 || null;
  const logName = cert.log?.name || cert.log_name || 'unknown';

  return {
    id: cert.id || sha256 || `${domainCandidate}-${notAfter}`,
    domain: domainCandidate || altNames[0] || 'unknown',
    altNames,
    issuer,
    notBefore,
    notAfter,
    loggedAt,
    status: computeCertificateStatus(notAfter),
    serial,
    sha256,
    logName,
  };
}

function computeCertificateStatus(notAfter: string): CertificateDto['status'] {
  const expiry = new Date(notAfter);
  if (notAfter && !Number.isNaN(expiry.getTime()) && expiry.getTime() < Date.now()) {
    return 'expired';
  }

  return 'valid';
}

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
