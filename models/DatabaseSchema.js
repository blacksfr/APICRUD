import { z } from 'zod';
import { ObjectId } from 'mongodb';
import { InvalidIDFormatError } from '../errors/ValidationError.js';

const ObjectIdSchema = z
  .custom(val => val instanceof ObjectId || typeof val === 'string')
  .transform(val => val.toString());

export const UserDbOutputSchema = z.object({
  _id: ObjectIdSchema,
  username: z.string(),
  password: z.string(),
  isDeleted: z.boolean(),
  createdAt: z.date(),
  updatedAt: z.date(),
});

const sensitiveFields = ['password', 'isDeleted'];

const omitObj = sensitiveFields.reduce((acc, field) => {
  acc[field] = true;
  return acc;
}, {});

export const UserDbOutputSchemaPublic = UserDbOutputSchema
  .omit(omitObj)
  .transform(({ _id, ...rest }) => ({
    id: _id,
    ...rest,
  }));

export const MongoIdSchema = z.object({
  id: z.string()
    .trim()
    .refine((val) => {
      if (!ObjectId.isValid(val)) {
        throw new InvalidIDFormatError();
      }
      return true;
    })
}).strict();

