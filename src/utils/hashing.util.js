import argon2 from 'argon2';
import InvalidPasswordFormatHashingError from '../errors/invalid.password.format.hashing.error.js';

const ARGON2_REGEX = /^\$argon2(id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$/;

const ARGON2_OPTIONS = {
  type:        argon2.argon2id,
  memoryCost:  2 ** 16,
  timeCost:    3,
  parallelism: 1,
};

const DUMMY_HASH = await argon2.hash('__dummy_password__', ARGON2_OPTIONS);

const HashingUtils = {

  async hashPassword(password) {
    if (!password || typeof password !== 'string') {
      throw new InvalidPasswordFormatHashingError(
        'Invalid password format for hashing',
      );
    }

    return argon2.hash(password, ARGON2_OPTIONS);
  },

  async comparePassword(password, hash) {
    if (
      !password || typeof password !== 'string' ||
      !hash    || typeof hash     !== 'string'
    ) {
      console.warn('[SECURITY_WARN] Invalid input types for password comparison');
      return false;
    }

    if (!ARGON2_REGEX.test(hash)) {
      console.warn('[SECURITY_WARN] Hash does not match Argon2 format');
      return false;
    }

    try {
      return await argon2.verify(hash, password);
    } catch (error) {
      console.error('[HashingUtils] argon2.verify error:', error);
      return false;
    }
  },

  async dummyCompare() {
    try {
      await argon2.verify(DUMMY_HASH, '__dummy_password__');
    } catch {
    }
    return false;
  },
};

export default HashingUtils;