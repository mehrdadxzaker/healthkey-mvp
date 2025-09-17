import Fastify from 'fastify';
import pino from 'pino';
import { PORT } from './config.js';
import healthRoutes from './routes/health.js';
import txRoutes from './routes/tx.js';

const logger = pino({ level: 'info' });
const app = Fastify({ logger });

app.register(healthRoutes);
app.register(txRoutes, { prefix: '/' });

app.listen({ port: PORT, host: '0.0.0.0' })
  .then(() => app.log.info(`LinkTx API listening on :${PORT}`))
  .catch((err) => {
    app.log.error(err);
    process.exit(1);
  });
