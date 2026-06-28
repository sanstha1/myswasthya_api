require('dotenv').config();
const app = require('./app');
const { connectDatabase } = require('./config/database');

const PORT = process.env.PORT || 3000;

async function startServer() {
  try {
   
    await connectDatabase();

    const server = app.listen(PORT, '0.0.0.0', () => {
      console.log(`[SERVER] MySwasthya backend running on port ${PORT}`);
      console.log(`[SERVER] Environment: ${process.env.NODE_ENV || 'development'}`);

      
      const required = ['JWT_SECRET', 'ENCRYPTION_KEY', 'HMAC_SECRET', 'MONGODB_URI'];
      const missing = required.filter((key) => !process.env[key]);
      if (missing.length > 0) {
        console.error(`[SECURITY WARNING] Missing required environment variables: ${missing.join(', ')}`);
      }
    });

   
    process.on('SIGTERM', () => {
      console.log('[SERVER] SIGTERM received - shutting down gracefully');
      server.close(() => {
        console.log('[SERVER] Server closed');
        process.exit(0);
      });
    });

    process.on('SIGINT', () => {
      console.log('[SERVER] SIGINT received - shutting down gracefully');
      server.close(() => {
        console.log('[SERVER] Server closed');
        process.exit(0);
      });
    });

  } catch (err) {
    console.error('[SERVER] Fatal error during startup:', err.message);
    process.exit(1);
  }
}

startServer();