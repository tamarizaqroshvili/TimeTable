import { get, put } from '@vercel/blob';
import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

const BLOB_PATH = 'timetable/latest.json';
const SESSION_LIFETIME_MS = 8 * 60 * 60 * 1000;
const MAX_BODY_BYTES = 4 * 1024 * 1024;
const JSON_HEADERS = {
  'content-type': 'application/json; charset=utf-8',
  'cache-control': 'no-store, max-age=0',
  'x-content-type-options': 'nosniff',
};

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...JSON_HEADERS, ...headers },
  });
}

function editCode() {
  return String(process.env.TIMETABLE_EDIT_CODE || '');
}

function isConfigured() {
  return Boolean(process.env.BLOB_READ_WRITE_TOKEN && editCode());
}

function safeEqual(left, right) {
  const leftHash = createHash('sha256').update(String(left)).digest();
  const rightHash = createHash('sha256').update(String(right)).digest();
  return timingSafeEqual(leftHash, rightHash);
}

function sessionSignature(payload) {
  return createHmac('sha256', editCode()).update(payload).digest('base64url');
}

function createSessionToken() {
  const expiresAt = Date.now() + SESSION_LIFETIME_MS;
  const payload = Buffer.from(JSON.stringify({ purpose: 'timetable-edit', expiresAt })).toString('base64url');
  return { token: `${payload}.${sessionSignature(payload)}`, expiresAt };
}

function verifySessionToken(token) {
  if (!token || !editCode()) return false;
  const [payload, signature, extra] = String(token).split('.');
  if (!payload || !signature || extra) return false;
  if (!safeEqual(signature, sessionSignature(payload))) return false;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    return data.purpose === 'timetable-edit' && Number(data.expiresAt) > Date.now();
  } catch {
    return false;
  }
}

function bearerToken(request) {
  const value = request.headers.get('authorization') || '';
  return value.startsWith('Bearer ') ? value.slice(7).trim() : '';
}

function validSnapshot(data) {
  return data && Array.isArray(data.records) && Array.isArray(data.rooms) &&
    data.records.length <= 20000 && data.rooms.length <= 5000;
}

async function currentBlob() {
  return get(BLOB_PATH, { access: 'private' });
}

function isWriteConflict(error) {
  return error?.status === 409 || error?.status === 412 || error?.statusCode === 409 || error?.statusCode === 412 ||
    /precondition|ifmatch|etag|already.?exists/i.test(String(error?.name || '') + String(error?.message || ''));
}

export default {
  async fetch(request) {
    try {
      if (request.method === 'GET') {
        if (!isConfigured()) {
          return json({ configured: false, error: 'service_not_configured' }, 503);
        }
        const latest = await currentBlob();
        if (!latest) return json({ configured: true, exists: false }, 404);
        return new Response(latest.stream, {
          status: 200,
          headers: {
            ...JSON_HEADERS,
            etag: latest.blob.etag,
            'x-timetable-published-at': latest.blob.uploadedAt?.toISOString?.() || '',
          },
        });
      }

      if (request.method !== 'POST') {
        return json({ error: 'method_not_allowed' }, 405, { allow: 'GET, POST' });
      }

      if (!isConfigured()) {
        return json({ configured: false, error: 'service_not_configured' }, 503);
      }

      const rawBody = await request.text();
      if (Buffer.byteLength(rawBody, 'utf8') > MAX_BODY_BYTES) {
        return json({ error: 'payload_too_large' }, 413);
      }

      let body;
      try {
        body = JSON.parse(rawBody || '{}');
      } catch {
        return json({ error: 'invalid_json' }, 400);
      }

      if (body.action === 'unlock') {
        if (!safeEqual(body.code || '', editCode())) {
          return json({ error: 'invalid_credentials' }, 401);
        }
        const session = createSessionToken();
        return json({ ok: true, ...session });
      }

      if (body.action !== 'publish') {
        return json({ error: 'unknown_action' }, 400);
      }

      if (!verifySessionToken(bearerToken(request))) {
        return json({ error: 'unauthorized' }, 401);
      }
      if (!validSnapshot(body)) {
        return json({ error: 'invalid_schedule' }, 400);
      }

      const latest = await currentBlob();
      const latestEtag = latest?.blob?.etag || '';
      const baseEtag = String(body.baseEtag || '');
      if (latestEtag !== baseEtag) {
        return json({ error: 'version_conflict', latestEtag }, 409);
      }

      const publishedAt = new Date().toISOString();
      const snapshot = JSON.stringify({
        version: 5,
        publishedAt,
        records: body.records,
        rooms: body.rooms,
      });
      if (Buffer.byteLength(snapshot, 'utf8') > MAX_BODY_BYTES) {
        return json({ error: 'payload_too_large' }, 413);
      }

      const putOptions = {
        access: 'private',
        contentType: 'application/json; charset=utf-8',
        allowOverwrite: Boolean(latest),
      };
      if (latestEtag) putOptions.ifMatch = latestEtag;
      await put(BLOB_PATH, snapshot, putOptions);
      const saved = await currentBlob();

      return json({
        ok: true,
        etag: saved?.blob?.etag || '',
        publishedAt,
        recordCount: body.records.length,
        roomCount: body.rooms.length,
      });
    } catch (error) {
      if (isWriteConflict(error)) {
        return json({ error: 'version_conflict' }, 409);
      }
      console.error('Timetable API error', error);
      return json({ error: 'server_error' }, 500);
    }
  },
};
