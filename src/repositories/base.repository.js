import { ObjectId } from 'mongodb';
import MongoDBConnection from '../connections/mongodb.connection.js';
import InvalidIDFormatError from '../errors/validation.error.js';
import DecryptionError from '../errors/decrypt.error.js';
import EncryptionError from '../errors/encrypt.error.js';
import logger from '../config/logger.config.js';

const unwrapZodCause = (err) => {
  if (err?.issues?.[0]?.input !== undefined) return err;
  const cause = err?.cause ?? err?.issues?.[0]?.cause;
  return cause ?? err;
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
    } catch (err) {
      const cause = unwrapZodCause(err);
      if (cause instanceof DecryptionError) throw cause;
      if (cause instanceof EncryptionError) throw cause;
      logger.error(
        { event: 'sanitization_failed', collection: this.collectionName, err },
        '[BaseRepository] Public sanitization failed',
      );
      throw new Error('INTERNAL_SERVER_ERROR');
    }
  }

  #sanitizeInternal(doc) {
    if (!doc) return null;
    try {
      return this.#outputSchema.parse(doc);
    } catch (err) {
      const cause = unwrapZodCause(err);
      if (cause instanceof DecryptionError) throw cause;
      if (cause instanceof EncryptionError) throw cause;
      logger.error(
        { event: 'sanitization_failed', collection: this.collectionName, err },
        '[BaseRepository] Internal sanitization failed',
      );
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

    logger.debug(
      { event: 'document_created', collection: this.collectionName, id: insertedId },
      '[BaseRepository] Document created',
    );

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

    if (!result) {
      logger.warn(
        { event: 'document_update_not_found', collection: this.collectionName, id },
        '[BaseRepository] Update target not found',
      );
    } else {
      logger.debug(
        { event: 'document_updated', collection: this.collectionName, id },
        '[BaseRepository] Document updated',
      );
    }

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

    const deleted = modifiedCount > 0;

    if (deleted) {
      logger.debug(
        { event: 'document_soft_deleted', collection: this.collectionName, id },
        '[BaseRepository] Document soft-deleted',
      );
    } else {
      logger.warn(
        { event: 'document_delete_not_found', collection: this.collectionName, id },
        '[BaseRepository] Delete target not found or already deleted',
      );
    }

    return deleted;
  }

  async findById(id) {
    const col = await this.#getCollection();

    const doc = await col.findOne(
      { _id: toObjectId(id), isDeleted: { $ne: true } },
      { projection: REDACT_CREDENTIALS },
    );

    if (!doc) {
      logger.debug(
        { event: 'document_not_found', collection: this.collectionName, id },
        '[BaseRepository] Document not found by id',
      );
    }

    return this.#sanitizePublic(doc);
  }

  async findOne(filter) {
    const col = await this.#getCollection();

    const doc = await col.findOne(
      { ...sanitizeFilter(filter), isDeleted: { $ne: true } },
      { projection: REDACT_CREDENTIALS },
    );

    if (!doc) {
      logger.debug(
        { event: 'document_not_found', collection: this.collectionName },
        '[BaseRepository] Document not found by filter',
      );
    }

    return this.#sanitizePublic(doc);
  }

  async findForLogin(filter) {
    const col = await this.#getCollection();

    const doc = await col.findOne({
      ...sanitizeFilter(filter),
      isDeleted: { $ne: true },
    });

    logger.debug(
      { event: 'login_lookup', collection: this.collectionName, found: !!doc },
      '[BaseRepository] Login lookup completed',
    );

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