import BaseRepository from './BaseRepository.js';
import { UserDbOutputSchema, UserDbOutputSchemaPublic } from '../models/DatabaseSchema.js';

class UserRepository extends BaseRepository {
  constructor() {
    super('users', UserDbOutputSchema, UserDbOutputSchemaPublic);
  }
}

export default new UserRepository();