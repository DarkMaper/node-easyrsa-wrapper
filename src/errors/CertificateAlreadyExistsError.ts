export class CertificateAlreadyExistsError extends Error {
    constructor(message?: string) {
        super(message);
        this.name = 'CertificateAlreadyExistsError';
    }
}
