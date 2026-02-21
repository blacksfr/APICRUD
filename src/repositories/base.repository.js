import { ObjectId } from 'mongodb';
import MongoDBConnection from '../connections/mongodb.connection.js';
import { InvalidIDFormatError } from '../middlewares/errors/validation.error.js';

export default class BaseRepository {
  #collection = null;
  #outputSchema = null;
  #outputSchemaPublic = null;

  constructor(collectionName, outputSchema, outputSchemaPublic, dbName = null) {
    this.collectionName = collectionName;
    this.#outputSchema = outputSchema;        
    this.#outputSchemaPublic = outputSchemaPublic; 
    this.dbName = dbName;
  }

  async #getCollection() {
    if (this.#collection) return this.#collection;
    const db = await MongoDBConnection.getConnection(this.dbName);
    this.#collection = db.collection(this.collectionName);
    return this.#collection;
  }

  #sanitizePublic(doc) {
    if (!doc) return null;
    try {
      return this.#outputSchemaPublic.parse(doc);
    } catch (error) {
      console.error('Sanitization Output DB Error:', error);
      throw new Error("xxx INTERNAL_SERVER_ERROR xxx");
    }
  }

  #sanitizeInternal(doc) {
    if (!doc) return null;
    return this.#outputSchema.parse(doc);
  }

  async create(data) {
    const col = await this.#getCollection();

    const { _id, isDeleted, createdAt, updatedAt, deletedAt, ...cleanData } = data;

    const doc = {
      ...cleanData,
      isDeleted: false,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const result = await col.insertOne(doc);
    return this.#sanitizePublic({ _id: result.insertedId, ...doc });
  }

  async findById(id) {
    if (!ObjectId.isValid(id)) throw new InvalidIDFormatError();

    const col = await this.#getCollection();
    const doc = await col.findOne(
      { _id: new ObjectId(id), isDeleted: { $ne: true } }
    );
    return this.#sanitizePublic(doc);
  }

  async findOne(filter) {
    const col = await this.#getCollection();
    const doc = await col.findOne(
      { ...filter, isDeleted: { $ne: true } }
    );
    return this.#sanitizePublic(doc);
  }

  async updateById(id, data) {
    if (!ObjectId.isValid(id)) throw new InvalidIDFormatError();

    const col = await this.#getCollection();
    const { _id, isDeleted, createdAt, updatedAt, deletedAt, ...safeData } = data;

    const result = await col.findOneAndUpdate(
      { _id: new ObjectId(id), isDeleted: { $ne: true } },
      {
        $set: {
          ...safeData,
          updatedAt: new Date(),
        }
      },
      { returnDocument: 'after' }
    );
    return this.#sanitizePublic(result);
  }

  async deleteById(id) {
    if (!ObjectId.isValid(id)) throw new InvalidIDFormatError();
    const col = await this.#getCollection();

    const result = await col.updateOne(
      { _id: new ObjectId(id), isDeleted: { $ne: true } },
      {
        $set: {
          isDeleted: true,
          deletedAt: new Date(),
          updatedAt: new Date(),
        }
      }
    );
    return result.modifiedCount > 0;
  }

  async findForLogin(filter) {
    const col = await this.#getCollection();
    const doc = await col.findOne({ ...filter, isDeleted: { $ne: true } });
    return this.#sanitizeInternal(doc);
  }
}

