export default class InvalidIDFormatError extends Error {
    constructor(message) {
        super(message = "Invalid ID format");
        this.name = "InvalidIDFormatError";
        this.message = message;
        this.statusCode = 400;
    }
}