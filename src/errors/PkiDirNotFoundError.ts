export class PkiDirNotFoundError extends Error {
    constructor(message?: string) {
        super(message);
        this.name = 'PkiDirNotFoundError';
    }
}
