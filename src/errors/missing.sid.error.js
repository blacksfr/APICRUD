export default class MissingSessionError extends Error {
  constructor() {
    super('Session identifier missing');
    this.name = 'MissingSessionError';
  }
}