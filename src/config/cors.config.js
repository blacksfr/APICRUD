import { isProd, isTest, PORT } from "./env.js";

const whitelist = isProd
  ? ['https://api-crud-blacksfritching.vercel.app', 'https://frontend-blacksfritching.vercel.app']
  : [
      `http://localhost:${PORT || 3000}`,
      'http://localhost:5173',
      'http://127.0.0.1:5173',
    ];

export default {
  origin: (origin, callback) => {
    if (!origin || whitelist.includes(origin) || isTest) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-Refresh-Token'],
  exposedHeaders: ['X-Request-Id'],
  credentials: true,
  maxAge: 86400,
};