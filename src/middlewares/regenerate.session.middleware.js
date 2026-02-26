import crypto from 'crypto';
import { isProd, SID_NAME } from '../config/env.js';

export const regenerateSessionId = (req, res) => {
  const newSid = crypto.randomBytes(32).toString('hex');

  res.cookie(SID_NAME, newSid, {
    httpOnly: true,
    secure:   isProd,
    sameSite: isProd ? 'Strict' : 'Lax',
    path:     '/',
    maxAge:   30 * 24 * 60 * 60 * 1000
  });

  req.cookies[SID_NAME] = newSid;
  
  return newSid;
};