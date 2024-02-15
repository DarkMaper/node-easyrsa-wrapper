export class PrivateKeyIsEncryptedError extends Error {
    constructor(message?: string) {
        super(message);
        this.name = 'PrivateKeyIsEncryptedError';
    }
}
