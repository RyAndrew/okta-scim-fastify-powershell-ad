import 'dotenv/config';

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required environment variable: ${name}`);
  return value;
}

export const config = {
  port: Number(process.env.PORT) || 3000,

  ad: {
    domain: requireEnv('AD_DOMAIN'),
    server: process.env.AD_SERVER ?? null,
    baseOu: requireEnv('AD_BASE_OU'),
    defaultPassword: requireEnv('AD_DEFAULT_PASSWORD'),
  },

  apiKey: requireEnv('API_KEY'),

  ssl: {
    certPath: requireEnv('SSL_CERT_PATH'),
    keyPath: requireEnv('SSL_KEY_PATH'),
  },
} as const;
