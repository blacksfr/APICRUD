import argon2 from 'argon2';

export const HashingUtils = {

    async hashPassword(password) {
        if (!password || typeof password !== 'string') {
            throw new Error("Invalid password format for hashing");
        }
        try {
            return await argon2.hash(password, {
                type: argon2.argon2id,
                memoryCost: 2 ** 16,
                timeCost: 3,
                parallelism: 1
            });
        } catch (error) {
            console.error("Argon2 Hash Error:", error);
            throw error;
        }
    },

    async comparePassword(password, hash) {
        if (!password || !hash || typeof password !== 'string' || typeof hash !== 'string') {
            console.warn("[SECURITY_WARN]: Invalid password or hash format for comparison.");
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