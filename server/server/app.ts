import express from 'express';
import { apiRouter } from './api';

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Existing API endpoints: /api/findings, /api/profile, etc.
app.use('/api', apiRouter);

// Return JSON for unknown API endpoints instead of an HTML page.
app.use('/api', (_req, res) => {
  res.status(404).json({ error: 'API endpoint not found' });
});

export default app;