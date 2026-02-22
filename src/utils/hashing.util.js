import argon2 from 'argon2';
import InvalidPasswordFormatHashingError from '../errors/invalid.password.format.hashing.error.js';
const ARGON2_REGEX = /^\$argon2(id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$/;

export const HashingUtils = {

    async hashPassword(password) {
        if (!password || typeof password !== 'string') {
            throw new InvalidPasswordFormatHashingError("Invalid password format for hashing");
        }
            return await argon2.hash(password, {
                type: argon2.argon2id,
                memoryCost: 2 ** 16,
                timeCost: 3,
                parallelism: 1
            });
    },

    async comparePassword(password, hash) {
        if (!password || !hash || typeof password !== 'string' || typeof hash !== 'string') {
            console.warn("[SECURITY_WARN]: Invalid password or hash format for comparison.");
            return false;
        }

        if (!ARGON2_REGEX.test(hash)) {
            console.warn(`[SECURITY_WARN]: Hash format is not Argon2: ${hash}`);
            return false;
        }

        try {
            return await argon2.verify(hash, password);
        } catch (error) {
            console.error("Argon2 Compare Error:", error);
            return false;
        }
    }
};