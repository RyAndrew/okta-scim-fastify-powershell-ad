// ---------------------------------------------------------------------------
// Fastify server — entry point
// ---------------------------------------------------------------------------

import fs from 'fs';
import Fastify, { FastifyReply, FastifyRequest } from 'fastify';
import { config } from './config';
import { initDb } from './db';
import authPlugin from './plugins/auth';
import { registerRequestLogger } from './middleware/request-logger';
import { scimUsersRoutes } from './routes/scim/users';

// ---------------------------------------------------------------------------
// SCIM discovery payloads (RFC 7644 §4)
// These endpoints are intentionally unauthenticated — Okta probes them
// during provisioning setup before credentials are configured.
// ---------------------------------------------------------------------------

const SERVICE_PROVIDER_CONFIG = {
  schemas: ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],
  patch: { supported: true },
  bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
  filter: { supported: true, maxResults: 200 },
  changePassword: { supported: false },
  sort: { supported: false },
  etag: { supported: false },
  authenticationSchemes: [
    {
      type: 'httpbasic',
      name: 'HTTP Basic',
      description: 'HTTP Basic authentication — username is ignored, password must equal the configured API_KEY',
    },
  ],
  meta: {
    resourceType: 'ServiceProviderConfig',
    location: '/scim/v2/ServiceProviderConfig',
  },
};

async function handleServiceProviderConfig(
  _request: FastifyRequest,
  reply: FastifyReply,
): Promise<void> {
  await reply
    .status(200)
    .header('Content-Type', 'application/scim+json')
    .send(SERVICE_PROVIDER_CONFIG);
}

// ---------------------------------------------------------------------------

async function start(): Promise<void> {
  const server = Fastify({
    https: {
      key: fs.readFileSync(config.ssl.keyPath),
      cert: fs.readFileSync(config.ssl.certPath),
    },
    logger: {
      level: process.env.LOG_LEVEL ?? 'info',
    },
  });

  // ── Database ──────────────────────────────────────────────────────────────
  await initDb();
  server.log.info('Database initialised');

  // ── Round-trip request/response logger ───────────────────────────────────
  registerRequestLogger(server);

  // ── Plugins ───────────────────────────────────────────────────────────────
  await server.register(authPlugin);

  // ── SCIM discovery routes (unauthenticated) ───────────────────────────────
  // RFC 7644 uses the singular form; Okta probes the plural form as well.
  server.get('/scim/v2/ServiceProviderConfig', handleServiceProviderConfig);
  server.get('/scim/v2/ServiceProviderConfigs', handleServiceProviderConfig);

  // ── Authenticated SCIM routes ─────────────────────────────────────────────
  await server.register(scimUsersRoutes, { prefix: '/scim/v2/Users' });

  // Health check — unauthenticated, used by load balancers and monitoring
  server.get('/health', async (_request, reply) => {
    return reply.status(200).send({ status: 'ok', service: 'scim-ad-bridge' });
  });

  // ── Start ─────────────────────────────────────────────────────────────────
  try {
    await server.listen({ port: config.port, host: '0.0.0.0' });
  } catch (err) {
    server.log.error(err);
    process.exit(1);
  }
}

start();
