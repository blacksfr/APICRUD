export const isProd = process.env.NODE_ENV === 'production';
export const isTest = process.env.NODE_ENV === 'test';
export const isDev = process.env.NODE_ENV === 'development';

export const PORT = process.env.PORT || 3000;
export const DB_NAME = process.env.DB_NAME;
export const MONGO_URI = process.env.MONGO_DB_KEY;
export const COOKIE_SECRET = process.env.COOKIE_SECRET;
export const JWT_ACCESS_SECRET = process.env.JWT_ACCESS_SECRET;
export const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;
export const ENCRYPTION_SECRET = process.env.ENCRYPTION_SECRET;