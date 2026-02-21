import BaseRepository from './base.repository.js';
import { UserDbOutputSchema, UserDbOutputPublicSchema } from '../models/database.model.js';

class UserRepository extends BaseRepository {
  constructor() {
    super('users', UserDbOutputSchema, UserDbOutputPublicSchema);
  }
}

export default new UserRepository();