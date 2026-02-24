export default class EncryptionError extends Error {
  constructor(message = 'Failed to encrypt data') {
    super(message);
    this.name = 'EncryptionError';
  }
}