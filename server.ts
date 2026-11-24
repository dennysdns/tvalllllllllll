import 'dotenv/config';
import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import express from 'express';
import type { NextFunction, Request, Response } from 'express';

interface AdminAuthRecord {
  salt: string;
  hash: string;
  updatedAt: number;
}

interface TokenPayload {
  sub: 'admin';
  iat: number;
  exp: number;
}

interface GeoInfo {
  country: string;
  countryCode: string;
  region: string;
  city: string;
  isp: string;
  lat: number | null;
  lon: number | null;
}

interface VisitorEntry extends GeoInfo {
  id: string;
  timestamp: string;
  dateKey: string;
  ip: string;
  path: string;
}

interface SponsorBanner {
  id: string;
  name: string;
  imageUrl: string;
  linkUrl: string;
  active: boolean;
  fileName?: string;
  createdAt: string;
}

const PORT = Number(process.env.PORT) || 3000;
const AUTH_DIR = path.resolve(process.cwd(), '.data');
const AUTH_FILE = path.resolve(AUTH_DIR, 'admin-auth.json');
const ANALYTICS_FILE = path.resolve(AUTH_DIR, 'visitor-analytics.json');
const SPONSORS_DIR = path.resolve(process.cwd(), 'patrocinadores');
const SPONSORS_META_FILE = path.resolve(SPONSORS_DIR, 'banners.json');
const MAX_VISITOR_RECORDS = 25000;
const MAX_SPONSOR_UPLOAD_BYTES = 5 * 1024 * 1024;
const TOKEN_TTL_MS = 8 * 60 * 60 * 1000;
const SESSION_SECRET =
  process.env.SESSION_SECRET?.trim() || crypto.randomBytes(32).toString('hex');

const geoCache = new Map<string, { info: GeoInfo; expiresAt: number }>();
const recentHitDedup = new Map<string, number>();

const loginAttempts = new Map<string, { count: number; resetAt: number }>();
let minValidIssuedAt = 0;

function readAuthRecord(): AdminAuthRecord | null {
  try {
    if (!fs.existsSync(AUTH_FILE)) return null;
    const raw = fs.readFileSync(AUTH_FILE, 'utf8');
    const parsed = JSON.parse(raw) as Partial<AdminAuthRecord>;
    if (
      typeof parsed.salt === 'string' &&
      typeof parsed.hash === 'string' &&
      typeof parsed.updatedAt === 'number'
    ) {
      return {
        salt: parsed.salt,
        hash: parsed.hash,
        updatedAt: parsed.updatedAt,
      };
    }
    return null;
  } catch {
    return null;
  }
}

function writeAuthRecord(record: AdminAuthRecord): void {
  fs.mkdirSync(AUTH_DIR, { recursive: true });
  fs.writeFileSync(AUTH_FILE, JSON.stringify(record), { mode: 0o600 });
}

function getEnvPassword(): string | null {
  const value = process.env.ADMIN_PASSWORD?.trim();
  return value ? value : null;
}

function hashPasswordScrypt(password: string): AdminAuthRecord {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash, updatedAt: Date.now() };
}

function verifyPasswordScrypt(password: string, record: AdminAuthRecord): boolean {
  try {
    const derived = crypto.scryptSync(password, record.salt, 64);
    const expected = Buffer.from(record.hash, 'hex');
    return derived.length === expected.length && crypto.timingSafeEqual(derived, expected);
  } catch {
    return false;
  }
}

function verifyEnvPassword(password: string, expected: string): boolean {
  const a = crypto.createHash('sha256').update(password).digest();
  const b = crypto.createHash('sha256').update(expected).digest();
  return crypto.timingSafeEqual(a, b);
}

function signToken(): string {
  const payload: TokenPayload = {
    sub: 'admin',
    iat: Date.now(),
    exp: Date.now() + TOKEN_TTL_MS,
  };
  const payloadB64 = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const sig = crypto
    .createHmac('sha256', SESSION_SECRET)
    .update(payloadB64)
    .digest('base64url');
  return `${payloadB64}.${sig}`;
}

function verifyToken(token: string | undefined | null): TokenPayload | null {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [payloadB64, sigB64] = parts;
  if (!payloadB64 || !sigB64) return null;

  const expectedSig = crypto
    .createHmac('sha256', SESSION_SECRET)
    .update(payloadB64)
    .digest('base64url');

  const sigBuf = Buffer.from(sigB64, 'utf8');
  const expBuf = Buffer.from(expectedSig, 'utf8');
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
    return null;
  }

  try {
    const parsed = JSON.parse(
      Buffer.from(payloadB64, 'base64url').toString('utf8')
    ) as Partial<TokenPayload>;
    if (
      parsed.sub !== 'admin' ||
      typeof parsed.iat !== 'number' ||
      typeof parsed.exp !== 'number'
    ) {
      return null;
    }
    if (parsed.exp <= Date.now()) return null;
    if (parsed.iat < minValidIssuedAt) return null;

    const record = readAuthRecord();
    if (!getEnvPassword() && record && parsed.iat < record.updatedAt) {
      return null;
    }
    return { sub: 'admin', iat: parsed.iat, exp: parsed.exp };
  } catch {
    return null;
  }
}

function extractBearer(req: Request): string | null {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) return null;
  return header.slice(7).trim() || null;
}

function checkRateLimit(ip: string): { allowed: boolean; retryAfterSec: number } {
  const now = Date.now();
  const entry = loginAttempts.get(ip);
  if (!entry || entry.resetAt <= now) {
    return { allowed: true, retryAfterSec: 0 };
  }
  if (entry.count >= 10) {
    return {
      allowed: false,
      retryAfterSec: Math.max(1, Math.ceil((entry.resetAt - now) / 1000)),
    };
  }
  return { allowed: true, retryAfterSec: 0 };
}

function recordFailedAttempt(ip: string): void {
  const now = Date.now();
  const existing = loginAttempts.get(ip);
  if (!existing || existing.resetAt <= now) {
    loginAttempts.set(ip, { count: 1, resetAt: now + 5 * 60 * 1000 });
    return;
  }
  existing.count += 1;
}

function clearAttempts(ip: string): void {
  loginAttempts.delete(ip);
}

function requireAdminAuth(req: Request, res: Response, next: NextFunction): void {
  const token = extractBearer(req);
  const verified = verifyToken(token);
  if (!verified) {
    res.status(401).json({ error: 'Sessão inválida ou expirada.' });
    return;
  }
  next();
}

function getSaoPauloDateKey(date: Date): string {
  return new Intl.DateTimeFormat('en-CA', {
    timeZone: 'America/Sao_Paulo',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  }).format(date);
}

function normalizeClientIp(raw: string): string {
  const trimmed = raw.trim();
  if (trimmed.startsWith('::ffff:')) {
    return trimmed.slice(7);
  }
  return trimmed;
}

function extractClientIp(req: Request): string {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.trim()) {
    const parts = forwarded.split(',');
    for (const part of parts) {
      const candidate = normalizeClientIp(part);
      if (net.isIP(candidate) !== 0) {
        return candidate;
      }
    }
  }
  const direct = normalizeClientIp(req.ip || req.socket.remoteAddress || '');
  return net.isIP(direct) !== 0 ? direct : '0.0.0.0';
}

function isPrivateOrLoopbackIp(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const octets = ip.split('.').map(Number);
    if (octets.length !== 4) return true;
    const [a, b] = octets;
    if (a === 10 || a === 127 || a === 0) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    return false;
  }
  const lower = ip.toLowerCase();
  if (lower === '::1' || lower === '::') return true;
  if (lower.startsWith('fc') || lower.startsWith('fd') || lower.startsWith('fe80')) {
    return true;
  }
  return false;
}

async function resolveIpGeolocation(ip: string): Promise<GeoInfo> {
  if (net.isIP(ip) === 0 || isPrivateOrLoopbackIp(ip)) {
    return {
      country: 'Acesso Local',
      countryCode: 'LOCAL',
      region: 'Rede Local / Preview',
      city: 'Localhost',
      isp: 'Rede Privada',
      lat: null,
      lon: null,
    };
  }

  const now = Date.now();
  const cached = geoCache.get(ip);
  if (cached && cached.expiresAt > now) {
    return cached.info;
  }

  const fallback: GeoInfo = {
    country: 'Não identificado',
    countryCode: '--',
    region: '-',
    city: '-',
    isp: '-',
    lat: null,
    lon: null,
  };

  try {
    const response = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`, {
      signal: AbortSignal.timeout(2500),
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) return fallback;
    const data = (await response.json()) as {
      success?: boolean;
      country?: string;
      country_code?: string;
      region?: string;
      city?: string;
      latitude?: number;
      longitude?: number;
      connection?: { isp?: string };
    };
    if (!data || data.success === false) return fallback;
    const info: GeoInfo = {
      country: typeof data.country === 'string' && data.country ? data.country : 'Desconhecido',
      countryCode:
        typeof data.country_code === 'string' && data.country_code
          ? data.country_code
          : '--',
      region: typeof data.region === 'string' && data.region ? data.region : '-',
      city: typeof data.city === 'string' && data.city ? data.city : '-',
      isp:
        typeof data.connection?.isp === 'string' && data.connection.isp
          ? data.connection.isp
          : '-',
      lat: typeof data.latitude === 'number' ? data.latitude : null,
      lon: typeof data.longitude === 'number' ? data.longitude : null,
    };
    if (geoCache.size > 5000) geoCache.clear();
    geoCache.set(ip, { info, expiresAt: now + 24 * 60 * 60 * 1000 });
    return info;
  } catch {
    return fallback;
  }
}

function readVisitorEntries(): VisitorEntry[] {
  try {
    if (!fs.existsSync(ANALYTICS_FILE)) return [];
    const raw = fs.readFileSync(ANALYTICS_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as VisitorEntry[]) : [];
  } catch {
    return [];
  }
}

function writeVisitorEntries(entries: VisitorEntry[]): void {
  fs.mkdirSync(AUTH_DIR, { recursive: true });
  const trimmed =
    entries.length > MAX_VISITOR_RECORDS
      ? entries.slice(entries.length - MAX_VISITOR_RECORDS)
      : entries;
  fs.writeFileSync(ANALYTICS_FILE, JSON.stringify(trimmed), { mode: 0o600 });
}

function sanitizeVisitPath(raw: unknown): string {
  if (typeof raw !== 'string') return '/';
  const cleaned = raw.replace(/[\r\n\t\x00-\x1f]/g, '').trim();
  if (!cleaned.startsWith('/')) return '/';
  return cleaned.slice(0, 120);
}

const ALLOWED_IMAGE_EXTENSIONS = new Set(['.png', '.jpg', '.jpeg', '.webp', '.gif']);

function ensureSponsorsDir(): void {
  fs.mkdirSync(SPONSORS_DIR, { recursive: true });
}

function readSponsorBanners(): SponsorBanner[] {
  ensureSponsorsDir();
  try {
    if (!fs.existsSync(SPONSORS_META_FILE)) return [];
    const raw = fs.readFileSync(SPONSORS_META_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as SponsorBanner[]) : [];
  } catch {
    return [];
  }
}

function writeSponsorBanners(banners: SponsorBanner[]): void {
  ensureSponsorsDir();
  fs.writeFileSync(SPONSORS_META_FILE, JSON.stringify(banners, null, 2));
}

function listSponsorFolderFiles(): string[] {
  ensureSponsorsDir();
  try {
    return fs
      .readdirSync(SPONSORS_DIR, { withFileTypes: true })
      .filter(
        (d) =>
          d.isFile() &&
          ALLOWED_IMAGE_EXTENSIONS.has(path.extname(d.name).toLowerCase())
      )
      .map((d) => d.name)
      .sort();
  } catch {
    return [];
  }
}

function detectImageExtension(buf: Buffer): string | null {
  if (buf.length < 12) return null;
  // PNG
  if (
    buf[0] === 0x89 &&
    buf[1] === 0x50 &&
    buf[2] === 0x4e &&
    buf[3] === 0x47
  ) {
    return 'png';
  }
  // JPEG
  if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) {
    return 'jpg';
  }
  // GIF
  if (buf[0] === 0x47 && buf[1] === 0x49 && buf[2] === 0x46 && buf[3] === 0x38) {
    return 'gif';
  }
  // WEBP
  if (
    buf.subarray(0, 4).toString('ascii') === 'RIFF' &&
    buf.subarray(8, 12).toString('ascii') === 'WEBP'
  ) {
    return 'webp';
  }
  return null;
}

function isSafeSponsorImageUrl(url: string): boolean {
  const trimmed = url.trim();
  if (!trimmed) return false;
  if (trimmed.startsWith('/patrocinadores/') && !trimmed.includes('..')) return true;
  if (trimmed.startsWith('/uploads/') && !trimmed.includes('..')) return true;
  try {
    const parsed = new URL(trimmed);
    return parsed.protocol === 'https:' || parsed.protocol === 'http:';
  } catch {
    return false;
  }
}

function sanitizeOptionalHttpUrl(raw: unknown): string {
  if (typeof raw !== 'string') return '';
  const trimmed = raw.trim();
  if (!trimmed) return '';
  const normalized = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  try {
    const parsed = new URL(normalized);
    if (parsed.protocol === 'https:' || parsed.protocol === 'http:') {
      return parsed.toString();
    }
    return '';
  } catch {
    return '';
  }
}

async function startServer() {
  ensureSponsorsDir();
  const app = express();
  app.set('trust proxy', 1);
  app.use(express.json({ limit: '8mb' }));

  const sponsorsStatic = express.static(SPONSORS_DIR, {
    fallthrough: true,
    index: false,
    redirect: false,
  });
  app.use('/patrocinadores', (req, res, next) => {
    if (req.path === '/' || req.path === '') {
      next();
      return;
    }
    if (path.extname(req.path).toLowerCase() === '.json') {
      res.status(404).end();
      return;
    }
    sponsorsStatic(req, res, next);
  });

  app.use('/api/admin', (_req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    next();
  });

  app.get('/api/admin/status', (req, res) => {
    const envPassword = getEnvPassword();
    const record = readAuthRecord();
    const configured = Boolean(envPassword || record);
    const token = extractBearer(req);
    const authenticated = configured && verifyToken(token) !== null;
    res.json({
      configured,
      envManaged: Boolean(envPassword),
      authenticated,
    });
  });

  app.post('/api/admin/setup', (req, res) => {
    const envPassword = getEnvPassword();
    const existing = readAuthRecord();
    if (envPassword || existing) {
      res.status(409).json({
        error: 'A senha do Painel de Controle já está configurada.',
      });
      return;
    }

    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    if (password.length < 6 || password.length > 128) {
      res.status(400).json({
        error: 'A senha deve ter entre 6 e 128 caracteres.',
      });
      return;
    }

    const record = hashPasswordScrypt(password);
    writeAuthRecord(record);
    minValidIssuedAt = record.updatedAt;
    const token = signToken();
    res.status(201).json({ token, configured: true, envManaged: false });
  });

  app.post('/api/admin/login', (req, res) => {
    const ip = req.ip || 'unknown';
    const rate = checkRateLimit(ip);
    if (!rate.allowed) {
      res.status(429).json({
        error: `Muitas tentativas. Aguarde ${rate.retryAfterSec}s para tentar novamente.`,
      });
      return;
    }

    const envPassword = getEnvPassword();
    const record = readAuthRecord();
    if (!envPassword && !record) {
      res.status(400).json({ error: 'Configure a senha inicial antes de entrar.' });
      return;
    }

    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    if (!password) {
      res.status(400).json({ error: 'Informe a senha.' });
      return;
    }

    const ok = envPassword
      ? verifyEnvPassword(password, envPassword)
      : record
        ? verifyPasswordScrypt(password, record)
        : false;

    if (!ok) {
      recordFailedAttempt(ip);
      res.status(401).json({ error: 'Senha incorreta.' });
      return;
    }

    clearAttempts(ip);
    const token = signToken();
    res.json({ token, envManaged: Boolean(envPassword) });
  });

  app.post('/api/admin/change-password', requireAdminAuth, (req, res) => {
    if (getEnvPassword()) {
      res.status(400).json({
        error: 'A senha é gerenciada pela variável ADMIN_PASSWORD no servidor.',
      });
      return;
    }

    const record = readAuthRecord();
    if (!record) {
      res.status(400).json({ error: 'Nenhuma senha salva encontrada.' });
      return;
    }

    const currentPassword =
      typeof req.body?.currentPassword === 'string' ? req.body.currentPassword : '';
    const newPassword =
      typeof req.body?.newPassword === 'string' ? req.body.newPassword : '';

    if (!verifyPasswordScrypt(currentPassword, record)) {
      res.status(401).json({ error: 'A senha atual está incorreta.' });
      return;
    }

    if (newPassword.length < 6 || newPassword.length > 128) {
      res.status(400).json({
        error: 'A nova senha deve ter entre 6 e 128 caracteres.',
      });
      return;
    }

    const nextRecord = hashPasswordScrypt(newPassword);
    writeAuthRecord(nextRecord);
    minValidIssuedAt = nextRecord.updatedAt;
    const token = signToken();
    res.json({ token });
  });

  app.post('/api/admin/logout', (_req, res) => {
    res.json({ ok: true });
  });

  // Silent visitor ingestion: stores IP + geolocation on server, exposes nothing publicly
  app.post('/api/analytics/visit', async (req, res) => {
    try {
      const visitPath = sanitizeVisitPath(req.body?.path);
      if (visitPath.startsWith('/admin')) {
        res.status(204).end();
        return;
      }

      const ip = extractClientIp(req);
      const nowMs = Date.now();
      const dedupKey = `${ip}|${visitPath}`;
      const lastHit = recentHitDedup.get(dedupKey);
      if (lastHit && nowMs - lastHit < 10_000) {
        res.status(204).end();
        return;
      }
      if (recentHitDedup.size > 10_000) recentHitDedup.clear();
      recentHitDedup.set(dedupKey, nowMs);

      const geo = await resolveIpGeolocation(ip);
      const nowDate = new Date(nowMs);
      const entry: VisitorEntry = {
        id: `${nowMs}-${crypto.randomBytes(3).toString('hex')}`,
        timestamp: nowDate.toISOString(),
        dateKey: getSaoPauloDateKey(nowDate),
        ip,
        path: visitPath,
        ...geo,
      };

      const entries = readVisitorEntries();
      entries.push(entry);
      writeVisitorEntries(entries);
    } catch {
      // swallow analytics write failure silently
    }
    res.status(204).end();
  });

  // Strictly admin-only visitor geolocation & period summary
  app.get('/api/analytics/summary', requireAdminAuth, (_req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    const entries = readVisitorEntries();
    const now = new Date();
    const todayKey = getSaoPauloDateKey(now);
    const monthPrefix = todayKey.slice(0, 7);
    const yearPrefix = todayKey.slice(0, 4);

    const last7Keys = new Set<string>();
    const last14Keys: string[] = [];
    for (let i = 13; i >= 0; i--) {
      const d = new Date(now.getTime() - i * 86_400_000);
      const key = getSaoPauloDateKey(d);
      last14Keys.push(key);
      if (i < 7) last7Keys.add(key);
    }

    const dailyIps = new Set<string>();
    let dailyVisits = 0;
    const weeklyIps = new Set<string>();
    let weeklyVisits = 0;
    const monthlyIps = new Set<string>();
    let monthlyVisits = 0;
    const annualIps = new Set<string>();
    let annualVisits = 0;

    const dayBuckets = new Map<string, { ips: Set<string>; visits: number }>();
    for (const k of last14Keys) {
      dayBuckets.set(k, { ips: new Set<string>(), visits: 0 });
    }

    const locationMap = new Map<
      string,
      {
        city: string;
        region: string;
        country: string;
        countryCode: string;
        ips: Set<string>;
        visits: number;
        lat: number | null;
        lon: number | null;
      }
    >();

    for (const entry of entries) {
      if (entry.dateKey === todayKey) {
        dailyVisits += 1;
        dailyIps.add(entry.ip);
      }
      if (last7Keys.has(entry.dateKey)) {
        weeklyVisits += 1;
        weeklyIps.add(entry.ip);
      }
      if (entry.dateKey.startsWith(monthPrefix)) {
        monthlyVisits += 1;
        monthlyIps.add(entry.ip);
      }
      if (entry.dateKey.startsWith(yearPrefix)) {
        annualVisits += 1;
        annualIps.add(entry.ip);
      }

      const bucket = dayBuckets.get(entry.dateKey);
      if (bucket) {
        bucket.visits += 1;
        bucket.ips.add(entry.ip);
      }

      const locKey = `${entry.city}|${entry.region}|${entry.country}`;
      let loc = locationMap.get(locKey);
      if (!loc) {
        loc = {
          city: entry.city,
          region: entry.region,
          country: entry.country,
          countryCode: entry.countryCode,
          ips: new Set<string>(),
          visits: 0,
          lat: entry.lat,
          lon: entry.lon,
        };
        locationMap.set(locKey, loc);
      }
      loc.visits += 1;
      loc.ips.add(entry.ip);
    }

    const dailySeries = last14Keys.map((dateKey) => {
      const bucket = dayBuckets.get(dateKey)!;
      const [, m, d] = dateKey.split('-');
      return {
        date: dateKey,
        label: `${d}/${m}`,
        people: bucket.ips.size,
        visits: bucket.visits,
      };
    });

    const topLocations = Array.from(locationMap.values())
      .map((loc) => ({
        city: loc.city,
        region: loc.region,
        country: loc.country,
        countryCode: loc.countryCode,
        people: loc.ips.size,
        visits: loc.visits,
        lat: loc.lat,
        lon: loc.lon,
      }))
      .sort((a, b) => b.visits - a.visits || b.people - a.people)
      .slice(0, 25);

    const recentVisits = entries.slice(-60).reverse();

    res.json({
      periods: {
        daily: { people: dailyIps.size, visits: dailyVisits, label: todayKey },
        weekly: { people: weeklyIps.size, visits: weeklyVisits, label: 'Últimos 7 dias' },
        monthly: { people: monthlyIps.size, visits: monthlyVisits, label: monthPrefix },
        annual: { people: annualIps.size, visits: annualVisits, label: yearPrefix },
      },
      totalRecorded: entries.length,
      dailySeries,
      topLocations,
      recentVisits,
    });
  });

  app.delete('/api/analytics/reset', requireAdminAuth, (_req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    writeVisitorEntries([]);
    res.json({ ok: true });
  });

  // Public sponsor banners list for Home page bottom section
  app.get('/api/sponsors', (_req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.json({ banners: readSponsorBanners() });
  });

  // Admin-only list of files inside root /patrocinadores folder
  app.get('/api/sponsors/files', requireAdminAuth, (_req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.json({ files: listSponsorFolderFiles() });
  });

  // Admin-only upload of sponsor banner image into root /patrocinadores folder
  app.post('/api/sponsors/upload', requireAdminAuth, (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    const rawName = typeof req.body?.filename === 'string' ? req.body.filename : 'banner';
    const dataUrl = typeof req.body?.dataUrl === 'string' ? req.body.dataUrl : '';

    const match = dataUrl.match(/^data:image\/(png|jpeg|jpg|webp|gif);base64,([A-Za-z0-9+/=]+)$/i);
    if (!match) {
      res.status(400).json({ error: 'Formato de imagem inválido. Envie PNG, JPG, WEBP ou GIF.' });
      return;
    }

    const buf = Buffer.from(match[2], 'base64');
    if (buf.length === 0 || buf.length > MAX_SPONSOR_UPLOAD_BYTES) {
      res.status(400).json({ error: 'A imagem deve ter no máximo 5 MB.' });
      return;
    }

    const ext = detectImageExtension(buf);
    if (!ext) {
      res.status(400).json({ error: 'Arquivo não reconhecido como imagem válida.' });
      return;
    }

    const baseStem = path
      .basename(rawName, path.extname(rawName))
      .toLowerCase()
      .replace(/[^a-z0-9_-]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 40) || 'banner';

    const safeFileName = `${baseStem}-${Date.now()}-${crypto.randomBytes(3).toString('hex')}.${ext}`;
    const targetPath = path.resolve(SPONSORS_DIR, safeFileName);
    if (!targetPath.startsWith(SPONSORS_DIR + path.sep)) {
      res.status(400).json({ error: 'Nome de arquivo inválido.' });
      return;
    }

    ensureSponsorsDir();
    fs.writeFileSync(targetPath, buf);

    res.status(201).json({
      fileName: safeFileName,
      imageUrl: `/patrocinadores/${safeFileName}`,
    });
  });

  // Admin-only create sponsor banner entry (1 banner per client, clickable URL required)
  app.post('/api/sponsors', requireAdminAuth, (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
    const imageUrl = typeof req.body?.imageUrl === 'string' ? req.body.imageUrl.trim() : '';
    const linkUrl = sanitizeOptionalHttpUrl(req.body?.linkUrl);
    const active = req.body?.active !== false;
    const fileName =
      typeof req.body?.fileName === 'string' ? path.basename(req.body.fileName) : undefined;

    if (!name || name.length > 100) {
      res.status(400).json({ error: 'Informe um nome válido para o cliente.' });
      return;
    }
    if (!linkUrl) {
      res.status(400).json({ error: 'Informe o site do cliente (ex: https://cliente.com.br).' });
      return;
    }
    if (!isSafeSponsorImageUrl(imageUrl)) {
      res.status(400).json({ error: 'Informe uma imagem ou URL válida para o banner.' });
      return;
    }

    const banners = readSponsorBanners();
    const duplicate = banners.find(
      (b) => b.name.trim().toLowerCase() === name.toLowerCase()
    );
    if (duplicate) {
      res.status(409).json({
        error: 'Este cliente já possui um banner cadastrado. Edite o banner existente ou informe outro cliente.',
      });
      return;
    }

    const banner: SponsorBanner = {
      id: `sp-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`,
      name,
      imageUrl,
      linkUrl,
      active,
      ...(fileName ? { fileName } : {}),
      createdAt: new Date().toISOString(),
    };
    banners.push(banner);
    writeSponsorBanners(banners);
    res.status(201).json({ banner });
  });

  // Admin-only update sponsor banner entry
  app.put('/api/sponsors/:id', requireAdminAuth, (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    const id = req.params.id;
    const banners = readSponsorBanners();
    const idx = banners.findIndex((b) => b.id === id);
    if (idx === -1) {
      res.status(404).json({ error: 'Banner não encontrado.' });
      return;
    }

    const current = banners[idx];
    const nextName =
      typeof req.body?.name === 'string' ? req.body.name.trim() : current.name;
    const nextImageUrl =
      typeof req.body?.imageUrl === 'string' ? req.body.imageUrl.trim() : current.imageUrl;
    const nextLinkUrl =
      req.body?.linkUrl !== undefined
        ? sanitizeOptionalHttpUrl(req.body.linkUrl)
        : current.linkUrl;
    const nextActive =
      typeof req.body?.active === 'boolean' ? req.body.active : current.active;

    if (!nextName || nextName.length > 100) {
      res.status(400).json({ error: 'Nome do cliente inválido.' });
      return;
    }
    if (!nextLinkUrl) {
      res.status(400).json({ error: 'Informe o site do cliente (ex: https://cliente.com.br).' });
      return;
    }
    if (!isSafeSponsorImageUrl(nextImageUrl)) {
      res.status(400).json({ error: 'Imagem ou URL inválida.' });
      return;
    }
    const duplicate = banners.find(
      (b) => b.id !== id && b.name.trim().toLowerCase() === nextName.toLowerCase()
    );
    if (duplicate) {
      res.status(409).json({
        error: 'Outro banner já está cadastrado para este cliente.',
      });
      return;
    }

    const updated: SponsorBanner = {
      ...current,
      name: nextName,
      imageUrl: nextImageUrl,
      linkUrl: nextLinkUrl,
      active: nextActive,
    };
    banners[idx] = updated;
    writeSponsorBanners(banners);
    res.json({ banner: updated });
  });

  // Admin-only delete sponsor banner entry (and unreferenced uploaded file in /patrocinadores)
  app.delete('/api/sponsors/:id', requireAdminAuth, (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    const id = req.params.id;
    const banners = readSponsorBanners();
    const target = banners.find((b) => b.id === id);
    if (!target) {
      res.status(404).json({ error: 'Banner não encontrado.' });
      return;
    }

    const remaining = banners.filter((b) => b.id !== id);
    writeSponsorBanners(remaining);

    if (target.imageUrl.startsWith('/patrocinadores/')) {
      const stillUsed = remaining.some((b) => b.imageUrl === target.imageUrl);
      if (!stillUsed) {
        const relFile = path.basename(target.imageUrl.slice('/patrocinadores/'.length));
        const filePath = path.resolve(SPONSORS_DIR, relFile);
        if (
          filePath.startsWith(SPONSORS_DIR + path.sep) &&
          path.extname(filePath).toLowerCase() !== '.json' &&
          fs.existsSync(filePath)
        ) {
          try {
            fs.unlinkSync(filePath);
          } catch {
            // ignore unlink error
          }
        }
      }
    }

    res.json({ ok: true });
  });

  if (process.env.NODE_ENV === 'production') {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.resolve(distDir, 'index.html'));
    });
  } else {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`TV Alegria server running on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
