import { z } from 'zod';
import { ObjectId } from 'mongodb';
import EncryptionUtils from '../utils/encrypt.util.js';
import InvalidIDFormatError from '../errors/validation.error.js';

const ObjectIdSchema = z
  .union([
    z.instanceof(ObjectId),
    z.string().refine((val) => ObjectId.isValid(val), {
      message: 'Invalid ObjectId format',
    }),
  ])
  .transform((val) => val.toString());

const encryptedEmailField = z
  .string()
  .transform((ciphertext) => {
    const decrypted = EncryptionUtils.decrypt(ciphertext);
    if (!decrypted) {
      throw new Error('Failed to decrypt email — data may be corrupted or key mismatch');
    }
    return decrypted;
  });

export const UserDbOutputSchema = z
  .object({
    _id:       ObjectIdSchema,
    username:  z.string(),
    email:     z.string(),
    emailHmac: z.string(),
    password:  z.string(),
    isDeleted: z.boolean(),
    createdAt: z.date(),
    updatedAt: z.date(),
  })
  .strict();

export const UserDbOutputPublicSchema = z
  .object({
    _id:       ObjectIdSchema,
    username:  z.string(),
    email:     encryptedEmailField,
    createdAt: z.date(),
    updatedAt: z.date(),
  })
  .transform(({ _id, ...rest }) => ({
    id: _id,
    ...rest,
  }));

export const MongoIdSchema = z
  .object({
    id: z
      .string()
      .trim()
      .refine(
        (val) => {
          if (!ObjectId.isValid(val)) throw new InvalidIDFormatError();
          return true;
        },
        { message: 'Invalid ObjectId format' },
      ),
  })
  .strict();