export class InvalidIDFormatError extends Error {
    constructor(message) {
        super(message);
        this.name = "InvalidIDFormatError";
        this.message = message || "Invalid ID format";
        this.statusCode = 400;
    }
}