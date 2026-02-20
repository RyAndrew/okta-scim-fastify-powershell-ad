// ---------------------------------------------------------------------------
// Fastify server — entry point
// ---------------------------------------------------------------------------

import fs from 'fs';
import Fastify, { FastifyReply, FastifyRequest } from 'fastify';
import { createAuthPlugin, createScimUsersPlugin } from 'scim-fastify-core';
import { config } from './config';
import { db, initDb } from './db';
import { registerRequestLogger } from './middleware/request-logger';
import { PowerShellAdBackend } from './backend';

// ---------------------------------------------------------------------------
// SCIM discovery (RFC 7644 §4)
// Intentionally unauthenticated — Okta probes these during setup.
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
      description:
        'HTTP Basic authentication — username is ignored, password must equal the configured API_KEY',
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
    logger: { level: process.env.LOG_LEVEL ?? 'info' },
  });

  await initDb();
  server.log.info('Database initialised');

  registerRequestLogger(server, db);

  await server.register(createAuthPlugin(config.apiKey));

  server.get('/scim/v2/ServiceProviderConfig', handleServiceProviderConfig);
  server.get('/scim/v2/ServiceProviderConfigs', handleServiceProviderConfig);

  const backend = new PowerShellAdBackend(db, config);
  await server.register(createScimUsersPlugin(backend), { prefix: '/scim/v2/Users' });

  server.get('/health', async (_request, reply) => {
    return reply.status(200).send({ status: 'ok', service: 'scim-ad-bridge' });
  });

  try {
    await server.listen({ port: config.port, host: '0.0.0.0' });
  } catch (err) {
    server.log.error(err);
    process.exit(1);
  }
}

start();
