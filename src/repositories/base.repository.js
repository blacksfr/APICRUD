import { ObjectId } from 'mongodb';
import MongoDBConnection from '../connections/mongodb.connection.js';
import InvalidIDFormatError from '../errors/validation.error.js';
import DecryptionError from '../errors/decrypt.error.js';
import EncryptionError from '../errors/encrypt.error.js';

const unwrapZodCause = (error) => {
  if (error?.issues?.[0]?.input !== undefined) return error;
  const cause = error?.cause ?? error?.issues?.[0]?.cause;
  return cause ?? error;
};

const IMMUTABLE_FIELDS = ['_id', 'isDeleted', 'createdAt', 'updatedAt', 'deletedAt'];

const REDACT_CREDENTIALS = { password: 0 };

const toObjectId = (id) => {
  if (!ObjectId.isValid(id)) throw new InvalidIDFormatError();
  return new ObjectId(id);
};

const sanitizeFilter = (filter) =>
  Object.fromEntries(
    Object.entries(filter).filter(([, v]) =>
      typeof v === 'string' ||
      typeof v === 'number' ||
      typeof v === 'boolean',
    ),
  );

const stripImmutable = (data) => {
  const clean = { ...data };
  for (const field of IMMUTABLE_FIELDS) delete clean[field];
  return clean;
};
export default class BaseRepository {
  #outputSchema;
  #outputSchemaPublic;

  constructor(collectionName, outputSchema, outputSchemaPublic, dbName = null) {
    this.collectionName = collectionName;
    this.#outputSchema = outputSchema;
    this.#outputSchemaPublic = outputSchemaPublic;
    this.dbName = dbName;
  }

  async #getCollection() {
    const db = await MongoDBConnection.getConnection(this.dbName);
    return db.collection(this.collectionName);
  }

  #sanitizePublic(doc) {
    if (!doc) return null;
    try {
      return this.#outputSchemaPublic.parse(doc);
    } catch (error) {
      const cause = unwrapZodCause(error);
      if (cause instanceof DecryptionError) throw cause;
      if (cause instanceof EncryptionError) throw cause;
      console.error('[BaseRepository] Public sanitisation failed:', error);
      throw new Error('INTERNAL_SERVER_ERROR');
    }
  }

  #sanitizeInternal(doc) {
    if (!doc) return null;
    try {
      return this.#outputSchema.parse(doc);
    } catch (error) {
      const cause = unwrapZodCause(error);
      if (cause instanceof DecryptionError) throw cause;
      if (cause instanceof EncryptionError) throw cause;
      console.error('[BaseRepository] Internal sanitisation failed:', error);
      throw new Error('INTERNAL_SERVER_ERROR');
    }
  }

  async create(data) {
    const col = await this.#getCollection();

    const doc = {
      ...stripImmutable(data),
      isDeleted: false,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const { insertedId } = await col.insertOne(doc);

    return this.#sanitizePublic({ _id: insertedId, ...doc });
  }

  async updateById(id, data) {
    const col = await this.#getCollection();

    const result = await col.findOneAndUpdate(
      { _id: toObjectId(id), isDeleted: { $ne: true } },
      {
        $set: {
          ...stripImmutable(data),
          updatedAt: new Date(),
        },
      },
      { returnDocument: 'after', projection: REDACT_CREDENTIALS },
    );

    return this.#sanitizePublic(result);
  }

  async deleteById(id) {
    const col = await this.#getCollection();

    const { modifiedCount } = await col.updateOne(
      { _id: toObjectId(id), isDeleted: { $ne: true } },
      {
        $set: {
          isDeleted: true,
          deletedAt: new Date(),
          updatedAt: new Date(),
        },
      },
    );

    return modifiedCount > 0;
  }

  async findById(id) {
    const col = await this.#getCollection();

    const doc = await col.findOne(
      { _id: toObjectId(id), isDeleted: { $ne: true } },
      { projection: REDACT_CREDENTIALS },
    );

    return this.#sanitizePublic(doc);
  }

  async findOne(filter) {
    const col = await this.#getCollection();

    const doc = await col.findOne(
      { ...sanitizeFilter(filter), isDeleted: { $ne: true } },
      { projection: REDACT_CREDENTIALS },
    );

    return this.#sanitizePublic(doc);
  }

  async findForLogin(filter) {
    const col = await this.#getCollection();

    const doc = await col.findOne({
      ...sanitizeFilter(filter),
      isDeleted: { $ne: true },
    });

    return this.#sanitizeInternal(doc);
  }

  async exists(filter) {
    const col = await this.#getCollection();

    const count = await col.countDocuments(
      { ...sanitizeFilter(filter), isDeleted: { $ne: true } },
      { limit: 1 },
    );

    return count > 0;
  }
  async existsById(id) {
    const col = await this.#getCollection();
    const count = await col.countDocuments(
      { _id: toObjectId(id), isDeleted: { $ne: true } },
      { limit: 1 },
    );
    return count > 0;
  }
}