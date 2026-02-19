// ---------------------------------------------------------------------------
// HTTP Basic authentication plugin
//
// Validates the Authorization: Basic <base64(username:password)> header on
// every protected route.  The password field is compared against API_KEY.
// The username field is accepted but not validated — configure any value in
// the Okta SCIM app's "Basic Auth Username" field.
//
// Decorates the FastifyInstance with an `authenticate` hook that routes
// attach via:  server.addHook('onRequest', server.authenticate)
// ---------------------------------------------------------------------------

import { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';
import { config } from '../config';

// ---------------------------------------------------------------------------
// TypeScript augmentation
// ---------------------------------------------------------------------------

declare module 'fastify' {
  interface FastifyInstance {
    authenticate: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
  }
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

async function authPlugin(server: FastifyInstance): Promise<void> {
  server.decorate(
    'authenticate',
    async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
      const authHeader = request.headers['authorization'] ?? '';

      if (!authHeader.startsWith('Basic ')) {
        return reply
          .status(401)
          .header('WWW-Authenticate', 'Basic realm="scim-ad-bridge"')
          .send({
            schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
            status: 401,
            detail: 'Authorization header with Basic credentials is required.',
          });
      }

      const decoded = Buffer.from(authHeader.slice(6), 'base64').toString('utf8');
      // username:password — split only on the first colon so passwords
      // containing colons are handled correctly
      const colonIndex = decoded.indexOf(':');
      const password = colonIndex === -1 ? decoded : decoded.slice(colonIndex + 1);

      if (password !== config.apiKey) {
        return reply
          .status(401)
          .header('WWW-Authenticate', 'Basic realm="scim-ad-bridge"')
          .send({
            schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
            status: 401,
            detail: 'Invalid credentials.',
          });
      }
    },
  );
}

export default fp(authPlugin, { name: 'auth' });
