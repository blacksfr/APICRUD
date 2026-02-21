import bcrypt from 'bcrypt';
import { createHash } from 'node:crypto';

const preHash = (password) => {
    return createHash('sha256').update(password).digest('hex');
};

export const HashingUtils = {

    async hashPassword(password) {
        if (!password || typeof password !== 'string') {
            throw new Error("Invalid password format for hashing");
        }
        try {
            const passwordToHash = preHash(password);
            const saltRounds = 12;
            return await bcrypt.hash(passwordToHash, saltRounds);
        } catch (error) {
            console.error("Bcrypt Hash Error:", error);
            throw error;
        }
    },

    async comparePassword(password, hash) {
        if (!password || !hash || typeof password !== 'string' || typeof hash !== 'string') {
            console.warn("[SECURITY_WARN]: Invalid password or hash format for comparison.");
            return false;
        }

        if (!hash.startsWith('$2')) {
            return false;
        }
        try {
            const passwordToCompare = preHash(password);
            return await bcrypt.compare(passwordToCompare, hash);
        } catch (error) {
            console.error("Bcrypt Compare Error:", error);
            return false;
        }
    }
};