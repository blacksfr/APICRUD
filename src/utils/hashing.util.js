import argon2 from 'argon2';
import InvalidPasswordFormatHashingError from '../errors/invalid.password.format.hashing.error.js';
import logger from '../config/logger.config.js';

const ARGON2_REGEX = /^\$argon2(id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$/;

const ARGON2_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 2 ** 16,
  timeCost: 3,
  parallelism: 1,
};

const DUMMY_HASH = await argon2.hash('__dummy_password__', ARGON2_OPTIONS);

const HashingUtils = {

  async hashPassword(password) {
    if (!password || typeof password !== 'string') {
      logger.warn(
        { event: 'hash_invalid_input' },
        '[HashingUtils] Invalid input for password hashing',
      );
      throw new InvalidPasswordFormatHashingError('Invalid password format for hashing');
    }

    return argon2.hash(password, ARGON2_OPTIONS);
  },

  async comparePassword(password, hash) {
    if (
      !password || typeof password !== 'string' ||
      !hash || typeof hash !== 'string'
    ) {
      logger.warn(
        { event: 'hash_compare_invalid_input' },
        '[HashingUtils] Invalid input types for password comparison',
      );
      return false;
    }

    if (!ARGON2_REGEX.test(hash)) {
      logger.warn(
        { event: 'hash_format_mismatch' },
        '[HashingUtils] Hash does not match Argon2 format',
      );
      return false;
    }

    try {
      return await argon2.verify(hash, password);
    } catch (err) {
      logger.error(
        { event: 'hash_verify_failed', err },
        '[HashingUtils] argon2.verify error',
      );
      return false;
    }
  },

  async dummyCompare() {
    try {
      await argon2.verify(DUMMY_HASH, '__dummy_password__');
    } catch {
      // intentionally swallowed — timing-safe dummy path
    }
    return false;
  },
};

export default HashingUtils;