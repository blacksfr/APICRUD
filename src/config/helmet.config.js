import { isProd } from "./env.js";

export default {
  frameguard: { action: 'sameorigin' },
  hsts: isProd
    ? { maxAge: 31536000, includeSubDomains: true, preload: true }
    : false,
  noSniff: true,
  hidePoweredBy: true,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  xssFilter: false,
  crossOriginEmbedderPolicy: false,
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  crossOriginResourcePolicy: { policy: isProd ? 'same-site' : 'cross-origin' },
  permittedCrossDomainPolicies: { permittedPolicies: 'none' },
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      frameAncestors: ["'none'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'blob:'],
      fontSrc: ["'self'"],
      connectSrc: isProd
        ? ["'self'", 'https://api-crud-blacksfritching.vercel.app','https://frontend-blacksfritching.vercel.app']
        : ["'self'", 'http://localhost:*'],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
    },
  },
};