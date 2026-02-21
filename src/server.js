import app from './app/app.js';
import MongoDBConnection from './connections/mongodb.connection.js';

const startServer = async () => {
  try {
    await MongoDBConnection.getConnection();
    console.log("Successfully connected to MongoDB");
  } catch (err) {
    console.error("CRITICAL INITIALIZATION FAILURE:", err.message);
  }
};

await startServer();

export default app;