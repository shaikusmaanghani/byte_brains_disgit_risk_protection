   import express from 'express';
   import mongoose from 'mongoose';
   import { apiRouter } from '../server/api';

   const app = express();
   app.use(express.json({ limit: '10mb' }));
   app.use(express.urlencoded({ extended: true, limit: '10mb' }));

   const uri = process.env.MONGODB_URI;
   if (uri && mongoose.connection.readyState === 0) {
     mongoose.connect(uri).catch((err) => console.error('DB error:', err));
   }

   app.use('/api', apiRouter);

   export default app;