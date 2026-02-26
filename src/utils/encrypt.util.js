import crypto from 'crypto';
import EncryptionError from '../errors/encrypt.error.js';
import DecryptionError from '../errors/decrypt.error.js';
import { ENCRYPTION_SECRET } from '../config/env.js';
import logger from '../config/logger.config.js';

const ALGORITHM = 'aes-256-gcm';
const KEY = crypto.scryptSync(ENCRYPTION_SECRET, 'salt', 32);
const IV_LENGTH = 12;
const TAG_LENGTH = 16;

const CIPHERTEXT_REGEX = /^[0-9a-f]+:[0-9a-f]{32}:[0-9a-f]+$/i;

const EncryptionUtils = {

    encrypt(text) {
        if (!text || typeof text !== 'string') {
            logger.warn(
                { event: 'encrypt_invalid_input' },
                '[EncryptionUtils] Invalid input for encryption',
            );
            throw new EncryptionError('Invalid input for encryption');
        }

        try {
            const iv = crypto.randomBytes(IV_LENGTH);
            const cipher = crypto.createCipheriv(ALGORITHM, KEY, iv, {
                authTagLength: TAG_LENGTH,
            });

            let encrypted = cipher.update(text, 'utf8', 'hex');
            encrypted += cipher.final('hex');
            const authTag = cipher.getAuthTag().toString('hex');

            return `${iv.toString('hex')}:${authTag}:${encrypted}`;
        } catch (err) {
            if (err instanceof EncryptionError) throw err;
            logger.error(
                { event: 'encrypt_failed', err },
                '[EncryptionUtils] Encryption failed',
            );
            throw new EncryptionError();
        }
    },

    decrypt(ciphertext) {
        if (!ciphertext || typeof ciphertext !== 'string') {
            logger.warn(
                { event: 'decrypt_invalid_input' },
                '[EncryptionUtils] Invalid input for decryption',
            );
            throw new DecryptionError('Invalid input for decryption');
        }

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
        } catch (err) {
            if (err instanceof DecryptionError) throw err;
            logger.error(
                { event: 'decrypt_failed', err },
                '[EncryptionUtils] Decryption failed',
            );
            throw new DecryptionError();
        }
    },

    isEncrypted(value) {
        return typeof value === 'string' && CIPHERTEXT_REGEX.test(value);
    },

    hmac(text) {
        if (!text || typeof text !== 'string') {
            logger.warn(
                { event: 'hmac_invalid_input' },
                '[EncryptionUtils] Invalid input for HMAC',
            );
            throw new EncryptionError('Invalid input for HMAC');
        }

        return crypto
            .createHmac('sha256', KEY)
            .update(text.toLowerCase().trim())
            .digest('hex');
    },
};

export default EncryptionUtils;