import path from 'path';
import dotenv from 'dotenv';
import { fileURLToPath } from 'node:url';
import app from './app/app.js';
import MongoDBConnection from './connections/mongodb.connection.js';

if (process.env.NODE_ENV !== 'production') {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = path.dirname(__filename);
  dotenv.config({ path: path.join(__dirname, '.env') });
}

const startServer = async () => {
  try {
    await MongoDBConnection.getConnection();
    console.log("Conectado ao MongoDB com sucesso.");

    if (process.env.NODE_ENV !== 'production' && process.env.NODE_ENV !== 'test') {
      const PORT = process.env.PORT || 3000;
      app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
        console.log(`http://localhost:${PORT}/users`);
      });
    }
  } catch (err) {
    console.error("FALHA CRÍTICA NA INICIALIZAÇÃO:", err.message);
    if (process.env.NODE_ENV !== 'production') {
      process.exit(1);
    }
  }
};

await startServer();

export default app;