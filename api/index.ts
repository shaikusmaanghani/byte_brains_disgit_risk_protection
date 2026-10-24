import express from 'express';
import { apiRouter } from '../server/api.js';
import { db } from '../server/db.js';

export const config = { maxDuration: 60 };

const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

await db.initialize();
app.use('/api', apiRouter);

export default app;