export class CaAlreadyExistsError extends Error {
    constructor(message?: string) {
        super(message);
        this.name = 'CaAlreadyExistsError';
    }
}
