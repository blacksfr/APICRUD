export default class InvalidPasswordFormatHashingError extends Error {
    constructor(message) {
        super(message = "Invalid password format for hashing");
        this.name = "InvalidPasswordFormatHashingError";
        this.message = message;
    }
}