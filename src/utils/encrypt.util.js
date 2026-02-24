import crypto from 'crypto';
import EncryptionError from '../errors/encrypt.error.js';
import DecryptionError from '../errors/decrypt.error.js';
import { ENCRYPTION_SECRET } from '../config/env.js';

const ALGORITHM = 'aes-256-gcm';
const KEY = crypto.scryptSync(ENCRYPTION_SECRET, 'salt', 32);
const IV_LENGTH = 12;
const TAG_LENGTH = 16;

const CIPHERTEXT_REGEX = /^[0-9a-f]+:[0-9a-f]{32}:[0-9a-f]+$/i;

const EncryptionUtils = {
    encrypt(text) {
        if (!text || typeof text !== 'string') throw new EncryptionError('Invalid input for encryption');
        try {
            const iv = crypto.randomBytes(IV_LENGTH);
            const cipher = crypto.createCipheriv(ALGORITHM, KEY, iv, {
                authTagLength: TAG_LENGTH,
            });

            let encrypted = cipher.update(text, 'utf8', 'hex');
            encrypted += cipher.final('hex');
            const authTag = cipher.getAuthTag().toString('hex');

            return `${iv.toString('hex')}:${authTag}:${encrypted}`;
        } catch (error) {
            if (error instanceof EncryptionError) throw error;
            throw new EncryptionError();
        }
    },

    decrypt(ciphertext) {
        if (!ciphertext || typeof ciphertext !== 'string') throw new DecryptionError('Invalid input for decryption');
        try {
            const [ivHex, authTagHex, encrypted] = ciphertext.split(':');

            if (!ivHex || !authTagHex || !encrypted) return null;

            const iv = Buffer.from(ivHex, 'hex');
            const authTag = Buffer.from(authTagHex, 'hex');

            const decipher = crypto.createDecipheriv(ALGORITHM, KEY, iv, {
                authTagLength: TAG_LENGTH,
            });
            decipher.setAuthTag(authTag);

            let decrypted = decipher.update(encrypted, 'hex', 'utf8');
            decrypted += decipher.final('utf8');

            return decrypted;
        } catch (error) {
            if (error instanceof DecryptionError) throw error;
            throw new DecryptionError();
        }
    },

    isEncrypted(value) {
        return typeof value === 'string' && CIPHERTEXT_REGEX.test(value);
    },

    hmac(text) {
        if (!text || typeof text !== 'string') throw new EncryptionError('Invalid input for HMAC');
        return crypto
            .createHmac('sha256', KEY)
            .update(text.toLowerCase().trim())
            .digest('hex');
    },
};

export default EncryptionUtils;