import { z } from 'zod';
import { calculateEntropy } from '../utils/password.security.util.js';
import EncryptionUtils from '../utils/encrypt.util.js';

const USERNAME_LIMITS  = { min: 6,  max: 20  };
const PASSWORD_LIMITS  = { min: 10, max: 128 };
const EMAIL_MAX_LENGTH = 254;

const strictUsername = z
  .string()
  .trim()
  .min(USERNAME_LIMITS.min, `Username must be at least ${USERNAME_LIMITS.min} characters`)
  .max(USERNAME_LIMITS.max, `Username cannot exceed ${USERNAME_LIMITS.max} characters`)
  .toLowerCase()
  .refine((u) => /^[a-zA-Z0-9._]+$/.test(u), {
    message: 'Username may only contain letters, numbers, dots, or underscores',
  })
  .refine((u) => !u.startsWith('.') && !u.endsWith('.'), {
    message: 'Username cannot start or end with a dot',
  })
  .refine((u) => !u.includes('..'), {
    message: 'Username cannot contain consecutive dots',
  });

const strictPassword = z
  .string()
  .min(PASSWORD_LIMITS.min, `Password must be at least ${PASSWORD_LIMITS.min} characters`)
  .max(PASSWORD_LIMITS.max, `Password cannot exceed ${PASSWORD_LIMITS.max} characters`)
  .refine((p) => /^\S+$/.test(p),        { message: 'Password must not contain spaces' })
  .refine((p) => /[A-Z]/.test(p),         { message: 'Password must contain at least one uppercase letter' })
  .refine((p) => /[a-z]/.test(p),         { message: 'Password must contain at least one lowercase letter' })
  .refine((p) => /[0-9]/.test(p),         { message: 'Password must contain at least one digit' })
  .refine((p) => /[^a-zA-Z0-9]/.test(p), { message: 'Password must contain at least one special character (e.g. @, #, $)' })
  .refine((p) => calculateEntropy(p) >= 64, {
    message: 'Password strength is too low — use a longer or more complex passphrase (min. 64 bits of entropy)',
  });

const enterpriseEmail = z
  .string()
  .trim()
  .toLowerCase()
  .max(EMAIL_MAX_LENGTH, `Email cannot exceed ${EMAIL_MAX_LENGTH} characters`)
  .refine((e) => /^\S+$/.test(e), { message: 'Email must not contain spaces' })
  .pipe(z.email({ message: 'Invalid email address' }))
  .transform((validEmail) => ({
    encrypted: EncryptionUtils.encrypt(validEmail),
    hmac:      EncryptionUtils.hmac(validEmail),
  }));

const loginEmail = z
  .string()
  .trim()
  .toLowerCase()
  .max(EMAIL_MAX_LENGTH, `Email cannot exceed ${EMAIL_MAX_LENGTH} characters`)
  .refine((e) => /^\S+$/.test(e), { message: 'Email must not contain spaces' })
  .pipe(z.email({ message: 'Invalid email address' }))
  .transform((validEmail) => ({
    hmac: EncryptionUtils.hmac(validEmail),
  }));

export const UserSchema = z
  .object({
    username: strictUsername,
    email:    enterpriseEmail,
    password: strictPassword,
  })
  .strict();

export const LoginSchema = z
  .object({
    email:    loginEmail, 
    password: z
      .string()
      .min(PASSWORD_LIMITS.min)
      .max(PASSWORD_LIMITS.max)
      .refine((p) => /^\S+$/.test(p), { message: 'Password must not contain spaces' }),
  })
  .strict();