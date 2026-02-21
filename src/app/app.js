import express from 'express';
import helmet from 'helmet';
import timeout from 'connect-timeout';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import cors from 'cors';
import lusca from 'lusca';
import csrf from 'csurf';
import router from '../router/user.route.js';

const app = express();

const isProd = process.env.NODE_ENV === 'production';
const isTest = process.env.NODE_ENV === 'test' || process.env.NODE_ENV === 'development';

app.set('trust proxy', 1);

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: isProd || isTest ? 300 : 1000,
  message: {
    error: "TOO_MANY_REQUESTS",
    message: "Please wait 15 minutes before trying again"
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const csrfProtection = csrf({
  cookie: {
    key: '_csrf',
    path: '/',
    httpOnly: true,
    secure: isProd,
    sameSite: 'Lax', 
    signed: true
  }
});

const whitelist = isProd 
  ? ['https://api-crud-blacksfritching.vercel.app'] 
  : [`http://localhost:${process.env.PORT || 3000}`, 'http://localhost:5173', 
      'http://127.0.0.1:5173'];

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin || whitelist.indexOf(origin) !== -1 || isTest) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
  credentials: true,
  maxAge: 86400
};

app.use(timeout('30s'));
app.use(helmet()); 
app.use(cors(corsOptions));
app.use(limiter);

app.use(express.json({ limit: '1mb' }));
app.use(cookieParser(process.env.COOKIE_SECRET));

app.use(lusca({
  xframe: 'SAMEORIGIN',
  hsts: isProd ? { maxAge: 31536000, includeSubDomains: true, preload: true } : false,
  xssProtection: true,
  nosniff: true,
  referrerPolicy: 'same-origin',
  csp: {
    policy: {
      'default-src': "'self'",
      'frame-ancestors': "'none'",
      'connect-src': (isProd 
      ? ["'self'", "https://api-crud-blacksfritching.vercel.app"] 
      : ["'self'", "http://localhost:*"]
    ).join(' ')}
  }
}));

app.use(csrfProtection);

app.use((req, res, next) => {
  if (typeof req.csrfToken === 'function') {
    const token = req.csrfToken();
    res.cookie('X-CSRF-Token', token, {
      httpOnly: false,
      secure: isProd,
      sameSite: 'Lax'
    });
  }
  next();
});

app.use((req, res, next) => {
  if (!req.timedout) next();
});

app.use(router);

app.use((req, res) => {
  res.status(404).json({
    error: "NOT_FOUND",
    message: `The route [${req.method}] ${req.url} does not exist`
  });
});

app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({
      error: "FORBIDDEN",
      message: "Form tampered with or invalid CSRF token"
    });
  }

  if (err.timeout || req.timedout) {
    return res.status(503).json({ 
      error: "SERVICE_UNAVAILABLE", 
      message: "The server took too long to respond"
    });
  }

  if (err.type === 'entity.too.large') {
    return res.status(413).json({ 
      error: "PAYLOAD_TOO_LARGE", 
      message: "Maximum limit is 1MB"
    });
  }

  console.error(`[SERVER_ERROR]: ${err.message}`);
  if (!isProd) console.error(err.stack);

  res.status(500).json({ 
    error: "INTERNAL_SERVER_ERROR", 
    message: "An unexpected error occurred" 
  });
});

export default app;