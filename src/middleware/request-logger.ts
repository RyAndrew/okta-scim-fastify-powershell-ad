// ---------------------------------------------------------------------------
// Round-trip HTTP request/response logger
//
// Strategy:
//   onRequest  → INSERT row with method, url, ip (body not yet parsed)
//   onSend     → UPDATE row with request_body (now parsed) + capture response payload
//   onResponse → UPDATE row with final status code + duration_ms
// ---------------------------------------------------------------------------

import { FastifyInstance } from 'fastify';
import type { Knex } from 'knex';

interface RequestMeta {
  rowId: number;
  startTime: number;
  responseBody: string | null;
}

export function registerRequestLogger(server: FastifyInstance, db: Knex): void {
  const meta = new Map<string, RequestMeta>();

  // ── 1. onRequest ─────────────────────────────────────────────────────────
  server.addHook('onRequest', async (request) => {
    const startTime = Date.now();
    const rawUrl = request.url;
    const qs = rawUrl.includes('?') ? rawUrl.split('?').slice(1).join('?') : null;

    try {
      const [rowId] = await db('incoming_requests').insert({
        method: request.method,
        url: rawUrl,
        query_string: qs,
        ip: request.ip,
      });
      meta.set(request.id, { rowId, startTime, responseBody: null });
    } catch (err) {
      server.log.error({ err }, '[request-logger] Failed to insert incoming_requests row');
    }
  });

  // ── 2. onSend ────────────────────────────────────────────────────────────
  server.addHook('onSend', async (request, _reply, payload) => {
    const entry = meta.get(request.id);
    if (!entry) return payload;

    let requestBodyStr: string | null = null;
    if (request.body !== undefined && request.body !== null) {
      try {
        requestBodyStr =
          typeof request.body === 'string'
            ? request.body
            : JSON.stringify(request.body);
      } catch {
        // ignore serialisation errors
      }
    }

    let responseBodyStr: string | null = null;
    if (typeof payload === 'string') {
      responseBodyStr = payload;
    } else if (Buffer.isBuffer(payload)) {
      responseBodyStr = payload.toString('utf8');
    }

    entry.responseBody = responseBodyStr;

    if (requestBodyStr) {
      db('incoming_requests')
        .where({ id: entry.rowId })
        .update({ request_body: requestBodyStr.substring(0, 65_535) })
        .catch((e: Error) =>
          server.log.error({ err: e }, '[request-logger] Failed to update request_body'),
        );
    }

    return payload;
  });

  // ── 3. onResponse ────────────────────────────────────────────────────────
  server.addHook('onResponse', async (request, reply) => {
    const entry = meta.get(request.id);
    if (!entry) return;

    const durationMs = Date.now() - entry.startTime;

    db('incoming_requests')
      .where({ id: entry.rowId })
      .update({
        response_status: reply.statusCode,
        response_body: entry.responseBody
          ? entry.responseBody.substring(0, 65_535)
          : null,
        duration_ms: durationMs,
      })
      .catch((e: Error) =>
        server.log.error({ err: e }, '[request-logger] Failed to update response fields'),
      );

    meta.delete(request.id);
  });
}
