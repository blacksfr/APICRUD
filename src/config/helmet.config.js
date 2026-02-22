import { isProd } from "./env.js";

export default {
  frameguard: { action: 'sameorigin' },
  hsts: isProd
    ? { maxAge: 31536000, includeSubDomains: true, preload: true }
    : false,
  noSniff: true,
  xssFilter: true,
  referrerPolicy: { policy: 'same-origin' },
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      frameAncestors: ["'none'"],
      connectSrc: isProd
        ? ["'self'", 'https://api-crud-blacksfritching.vercel.app']
        : ["'self'", 'http://localhost:*'],
      scriptSrc: ["'self'"],
      objectSrc: ["'none'"],
    },
  },
};