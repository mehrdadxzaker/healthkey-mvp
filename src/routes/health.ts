import { FastifyInstance } from 'fastify';

export default async function healthRoutes(app: FastifyInstance) {
  app.get('/health', async () => {
    return { ok: true, service: 'linktx-mvp' };
  });
}
