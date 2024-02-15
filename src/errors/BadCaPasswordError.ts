export class BadCaPasswordError extends Error {
    constructor(message?: string) {
        super(message);
        this.name = 'BadCaPasswordError';
    }
}
