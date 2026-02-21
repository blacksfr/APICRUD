import { z } from 'zod';
import { calculateEntropy } from '../utils/password.security.util.js';

const USERNAME_LIMITS = { min: 6, max: 20 };
const PASSWORD_LIMITS = { min: 10, max: 128 };

export const UserSchema = z.object({
  username: z
    .string()
    .trim()
    .min(USERNAME_LIMITS.min, `Username must be at least ${USERNAME_LIMITS.min} characters long`)
    .max(USERNAME_LIMITS.max, `Username cannot exceed ${USERNAME_LIMITS.max} characters`)
    .toLowerCase()
    .regex(/^[a-zA-Z0-9._]+$/, "Only letters, numbers, dots, or underscores are allowed")
    .refine(u => !u.startsWith('.') && !u.endsWith('.'), "Username cannot start or end with a dot")
    .refine(u => !u.includes('..'), "Username cannot contain consecutive dots"),

  password: z
    .string()
    .min(PASSWORD_LIMITS.min, `Password must be at least ${PASSWORD_LIMITS.min} characters long`)
    .max(PASSWORD_LIMITS.max, `Password cannot exceed ${PASSWORD_LIMITS.max} characters`)
    .regex(/^\S+$/, "Password cannot contain spaces")
    .regex(/[A-Z]/, "Password must contain at least one uppercase letter")
    .regex(/[a-z]/, "Password must contain at least one lowercase letter")
    .regex(/[0-9]/, "Password must contain at least one number")
    .regex(/[^a-zA-Z0-9]/, "Password must contain at least one special character (e.g., @, #, $)")
    .refine(p => calculateEntropy(p) >= 64, {
      message: "Password strength is too low. Please use a more complex or longer phrase (min. 64 bits of entropy)"
    })
}).strict();

export const LoginSchema = z.object({
  username: z
    .string()
    .trim()
    .min(USERNAME_LIMITS.min)
    .max(USERNAME_LIMITS.max)
    .regex(/^\S+$/),

  password: z
    .string()
    .min(PASSWORD_LIMITS.min)
    .max(PASSWORD_LIMITS.max)
    .regex(/^\S+$/)
}).strict();