export default class DecryptionError extends Error {
  constructor(message = 'Failed to decrypt data') {
    super(message);
    this.name = 'DecryptionError';
  }
}