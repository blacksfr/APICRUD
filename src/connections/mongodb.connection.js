import { MongoClient, ServerApiVersion } from "mongodb";
import { MONGO_URI, DB_NAME } from "../config/env.js";

export default class MongoDBConnection {
  static #client = null;
  static #connectionPromise = null;
  static #dbCache = new Map();

  static #options = {
    serverApi: {
      version: ServerApiVersion.v1,
      strict: true,
      deprecationErrors: true,
    },
    maxPoolSize: 10,
    minPoolSize: 0,
    serverSelectionTimeoutMS: 5000,
    connectTimeoutMS: 10000,
  };

  static async getConnection(dbName = null) {
    const targetDb = dbName || DB_NAME;

    if (this.#client && this.#dbCache.has(targetDb)) {
      return this.#dbCache.get(targetDb);
    }

    if (this.#connectionPromise) {
      await this.#connectionPromise;
      return this.#getAndCacheDb(targetDb);
    }

    this.#connectionPromise = (async () => {
      try {
        const tempClient = new MongoClient(MONGO_URI, this.#options);

        tempClient.on('error', (err) => {
          console.error("[MongoDB] Runtime Error:", err.message);
          this.#reset();
        });

        tempClient.on('close', () => this.#reset());

        await tempClient.connect();
        await tempClient.db(targetDb).command({ ping: 1 });

        this.#client = tempClient;
        console.log(`[MongoDB] New Connection Established for [${targetDb}].`);
      } catch (err) {
        this.#reset();
        console.error("[MongoDB] Connection Error:", err.message);
        throw err;
      } finally {
        this.#connectionPromise = null;
      }
    })();

    await this.#connectionPromise;
    if (!this.#client) throw new Error("[MongoDB] Failed to establish connection.");
    return this.#getAndCacheDb(targetDb);
  }

  static async killConnection() {
    if (this.#client) {
      try {
        await this.#client.close();
        console.log("[MongoDB] Connection closed gracefully.");
      } catch (err) {
        console.error("[MongoDB] Error during disconnection:", err.message);
      } finally {
        this.#reset();
      }
    }
  }

  static #getAndCacheDb(name) {
    if (!this.#client) throw new Error("[MongoDB] Client not initialized.");
    const db = this.#client.db(name);
    this.#dbCache.set(name, db);
    return db;
  }

  static #reset() {
    this.#client = null;
    this.#connectionPromise = null;
    this.#dbCache.clear();
  }
}