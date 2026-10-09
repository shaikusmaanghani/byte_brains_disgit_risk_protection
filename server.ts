import express from 'express';
import { createServer as createViteServer } from 'vite';
import { apiRouter } from './server/api';
import path from 'path';

async function startServer() {
  const app = express();
  const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

  // JSON and URL-encoded body parsers
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true, limit: '10mb' }));

  // Mount API router
  app.use('/api', apiRouter);

  // Serve static assets if exists
  app.use(express.static(path.resolve(process.cwd(), 'public')));

  if (process.env.NODE_ENV === 'production') {
    // In production, serve built dist files
    const distPath = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  } else {
    // In development mode, mount Vite middleware
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        host: '0.0.0.0',
        port: PORT,
      },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`🛡️ SentinelShield SOC server running at http://0.0.0.0:${PORT}`);
    console.log(`📡 REST API endpoints mounted at http://0.0.0.0:${PORT}/api`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start SentinelShield server:', err);
  process.exit(1);
});
