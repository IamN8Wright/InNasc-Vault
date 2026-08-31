import cors from 'cors';
import express, { type NextFunction, type Request, type Response } from 'express';
import helmet from 'helmet';
import { ZodError } from 'zod';

import { config } from './config.js';
import { cryptoReady } from './crypto.js';
import { closeDatabase } from './db.js';
import { router } from './routes.js';

await cryptoReady();

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', false);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'none'"],
      frameAncestors: ["'none'"],
      baseUri: ["'none'"],
    },
  },
  crossOriginResourcePolicy: { policy: 'same-site' },
}));
app.use(cors({
  origin(origin, callback) {
    if (!origin || config.allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('Origin not allowed.'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'X-CSRF-Token'],
  maxAge: 600,
}));
app.use(express.json({ limit: '256kb', strict: true }));
app.use('/api', router);

app.use((_request, response) => response.status(404).json({ error: 'Not found.' }));

app.use((error: unknown, _request: Request, response: Response, _next: NextFunction) => {
  if (error instanceof ZodError) {
    return response.status(400).json({
      error: error.issues[0]?.message ?? 'Please check the information you entered.',
      code: 'VALIDATION_ERROR',
      fields: error.flatten().fieldErrors,
    });
  }
  const typed = error as { status?: number; code?: string; message?: string };
  const status = typed.status && typed.status >= 400 && typed.status < 600 ? typed.status : 500;
  if (status >= 500) console.error(error);
  return response.status(status).json({
    error: status >= 500 ? 'The local vault encountered an unexpected error.' : typed.message ?? 'Request failed.',
    code: typed.code,
  });
});

const server = app.listen(config.port, config.host, () => {
  console.log(`InNasc Vault local API: http://localhost:${config.port}`);
  console.log(`Encrypted database: ${config.databasePath}`);
});

// Keep the local background process alive even in launchers that detach socket handles.
const keepAlive = setInterval(() => undefined, 60_000);

function shutdown(signal: string) {
  console.log(`Stopping InNasc Vault local API (${signal})…`);
  clearInterval(keepAlive);
  server.close(() => {
    closeDatabase();
    process.exit(0);
  });
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
