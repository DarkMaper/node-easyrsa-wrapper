export class CertificateNotFoundError extends Error {
    constructor(message?: string) {
        super(message);
        this.name = 'CertificateNotFoundError';
    }
}
