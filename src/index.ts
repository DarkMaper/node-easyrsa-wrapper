import path, { isAbsolute, join } from 'node:path';
import { readFile, readFileSync, writeFileSync } from 'node:fs';
import { execFile, spawn } from 'node:child_process';
import { defaults, pick } from 'lodash';
import ejs from 'ejs';
import { escapeShell } from './utils';
import {
    BadCaPasswordError,
    CaAlreadyExistsError,
    CaNotFoundError,
    CertificateAlreadyExistsError,
    CertificateNotFoundError,
    PkiDirNotFoundError,
    PrivateKeyIsEncryptedError,
} from './errors';

const Digest = ['md5', 'sha1', 'sha256', 'sha224', 'sha384', 'sha512'] as const;
export type IDigest = (typeof Digest)[number];

const Curve = [
    'secp112r1',
    'secp112r2',
    'secp128r1',
    'secp128r2',
    'secp160k1',
    'secp160r1',
    'secp160r2',
    'secp192k1',
    'secp224k1',
    'secp224r1',
    'secp256k1',
    'secp384r1',
    'secp521r1',
    'prime192v1',
    'prime192v2',
    'prime192v3',
    'prime239v1',
    'prime239v2',
    'prime239v3',
    'prime256v1',
    'sect113r1',
    'sect113r2',
    'sect131r1',
    'sect131r2',
    'sect163k1',
    'sect163r1',
    'sect163r2',
    'sect193r1',
    'sect193r2',
    'sect233k1',
    'sect233r1',
    'sect239k1',
    'sect283k1',
    'sect283r1',
    'sect409k1',
    'sect409r1',
    'sect571k1',
    'sect571r1',
    'c2pnb163v1',
    'c2pnb163v2',
    'c2pnb163v3',
    'c2pnb176v1',
    'c2tnb191v1',
    'c2tnb191v2',
    'c2tnb191v3',
    'c2pnb208w1',
    'c2tnb239v1',
    'c2tnb239v2',
    'c2tnb239v3',
    'c2pnb272w1',
    'c2pnb304w1',
    'c2tnb359v1',
    'c2pnb368w1',
    'c2tnb431r1',
    'wap-wsg-idm-ecid-wtls1',
    'wap-wsg-idm-ecid-wtls3',
    'wap-wsg-idm-ecid-wtls4',
    'wap-wsg-idm-ecid-wtls5',
    'wap-wsg-idm-ecid-wtls6',
    'wap-wsg-idm-ecid-wtls7',
    'wap-wsg-idm-ecid-wtls8',
    'wap-wsg-idm-ecid-wtls9',
    'wap-wsg-idm-ecid-wtls10',
    'wap-wsg-idm-ecid-wtls11',
    'wap-wsg-idm-ecid-wtls12',
    'Oakley-EC2N-3',
    'Oakley-EC2N-4',
    'brainpoolP160r1',
    'brainpoolP160t1',
    'brainpoolP192r1',
    'brainpoolP192t1',
    'brainpoolP224r1',
    'brainpoolP224t1',
    'brainpoolP256r1',
    'brainpoolP256t1',
    'brainpoolP320r1',
    'brainpoolP320t1',
    'brainpoolP384r1',
    'brainpoolP384t1',
    'brainpoolP512r1',
    'brainpoolP512t1',
    'SM2',
] as const;
export type ICurve = (typeof Curve)[number];

export type Algorithm = 'rsa' | 'ec';

export interface EasyRSAArgs {
    pki: string;
    days: number;
    certDays: number;
    digest: IDigest;
    algo: Algorithm;
    keySize: number;
    curve: ICurve;
}

export interface CertificateOptions {
    commonName?: string;
    password?: string;
    caPassword?: string;
}

export interface CreateCert extends CertificateOptions {
    name: string;
}

const RevokeReason = [
    'unspecified',
    'keyCompromise',
    'CACompromise',
    'affiliationChanged',
    'superseded',
    'cessationOfOperation',
    'certificateHold',
] as const;

export type IRevokeReason = (typeof RevokeReason)[number];

export default class EasyRSA {
    easyrsaDir: string;
    options: EasyRSAArgs;

    constructor(args: Partial<EasyRSAArgs> = {}) {
        if (args.digest && !Digest.includes(args.digest))
            throw new Error('Digest not valid');

        if (args.curve && !Curve.includes(args.curve))
            throw new Error('Curve not valid');

        this.easyrsaDir = path.join(__dirname, '..', 'easyrsa');
        const values: EasyRSAArgs = {
            pki: path.join(this.easyrsaDir, 'pki'),
            algo: 'rsa',
            digest: 'sha256',
            keySize: 2048,
            days: 3650,
            certDays: 825,
            curve: 'sect571r1',
        };

        let pkiPath = undefined;

        if (args.pki) {
            pkiPath = isAbsolute(args.pki)
                ? args.pki
                : join(process.cwd(), args.pki);
        }

        this.options = defaults(
            pick({ ...args, pki: pkiPath }, ...Object.keys(values)),
            values,
        );

        this.updateVarsFile();
    }

    private easyrsa(args: string): Promise<string> {
        return new Promise((res, rej) => {
            const easyrsaBin = join(this.easyrsaDir, 'easyrsa');
            const argsToArray = [...args.split(' ')];
            const easyrsa = spawn(easyrsaBin, argsToArray, {
                cwd: this.easyrsaDir,
                shell: true,
            });

            let stdout = '';
            let stderr = '';

            easyrsa.stdout.setEncoding('utf8');
            easyrsa.stdout.on('data', (data) => {
                stdout += data;
            });

            easyrsa.stderr.setEncoding('utf8');
            easyrsa.stderr.on('data', (data) => {
                stderr += data;
            });

            easyrsa.on('close', (code) => {
                if (code) {
                    if (
                        stdout.includes(
                            'Unable to create a CA as you already seem to have one set up.',
                        )
                    ) {
                        return rej(new CaAlreadyExistsError());
                    }
                    if (
                        stdout.includes(
                            'EASYRSA_PKI does not exist (perhaps you need to run init-pki)?',
                        )
                    ) {
                        return rej(new PkiDirNotFoundError());
                    }

                    if (
                        stderr.includes('Could not read CA private key from') &&
                        stderr.includes('maybe wrong password')
                    ) {
                        return rej(new BadCaPasswordError());
                    }

                    if (stdout.includes('Missing expected CA file')) {
                        return rej(new CaNotFoundError('CA file not exists'));
                    }

                    if (stdout.includes('Conflicting certificate exists at')) {
                        return rej(new CertificateAlreadyExistsError());
                    }
                    if (
                        stdout.includes(
                            'Unable to revoke as no certificate was found',
                        ) ||
                        stdout.includes('Missing certificate file')
                    ) {
                        return rej(new CertificateNotFoundError());
                    }
                    return rej(stderr);
                }
                return res(stdout);
            });
        });
    }

    private isPrivateKeyEncrypted(path: string): Promise<boolean> {
        return new Promise((res, rej) => {
            readFile(path, { encoding: 'utf8' }, (error, data) => {
                if (error) {
                    if (error.code === 'ENOENT')
                        return rej(new CaNotFoundError());
                    return rej(error);
                }
                res(data.includes('ENCRYPTED'));
            });
        });
    }

    private updateVarsFile() {
        const varsTemplate = readFileSync(
            join(`${__dirname}`, 'templates', 'vars'),
            'utf-8',
        );
        const varsComplete = ejs.render(varsTemplate, this.options);
        writeFileSync(join(this.easyrsaDir, 'vars'), varsComplete);
    }

    getPKIDir() {
        return this.options.pki;
    }

    initPki({ force }: { force: boolean } = { force: true }): Promise<string> {
        return new Promise((res, rej) => {
            void (async () => {
                try {
                    const output = await this.easyrsa(
                        `init-pki ${force ? 'hard' : 'soft'}`,
                    );
                    execFile(
                        'openvpn',
                        ['--genkey', '--secret', this.options.pki + '/ta.key'],
                        (_stderr, _stdout, err) => {
                            if (err) {
                                console.error(
                                    'no se ha podido generar la clave ta.key',
                                );
                            }
                        },
                    );
                    res(output);
                } catch (error) {
                    rej(error);
                }
            })();
        });
    }

    async buildCa({
        commonName,
        password,
    }: CertificateOptions = {}): Promise<string> {
        try {
            const opts: string[] = [];
            const easy_args = password ? '' : 'nopass';
            if (commonName) opts.push(`--req-cn=${escapeShell(commonName)}`);
            if (password)
                opts.push(
                    `--passin=pass:${escapeShell(
                        password,
                    )} --passout=pass:${escapeShell(password)}`,
                );
            const result = await this.easyrsa(
                `${opts.join(' ')} build-ca ${easy_args}`,
            );

            return result;
        } catch (error) {
            if (error instanceof Error) throw error;
            throw new Error('Fail to build CA');
        }
    }

    async createCert(
        type: 'client' | 'server',
        { name, commonName, password, caPassword }: CreateCert,
    ) {
        try {
            if (
                !caPassword &&
                (await this.isPrivateKeyEncrypted(
                    join(this.options.pki, 'private', 'ca.key'),
                ))
            ) {
                throw new PrivateKeyIsEncryptedError('CA is encrypted');
            }

            let opts: string[] = [];
            const easy_args = password ? '' : 'nopass';
            if (commonName) opts.push(`--req-cn=${escapeShell(commonName)}`);
            if (password) {
                opts.push(`--passout=pass:${escapeShell(password)}`);
            }
            await this.easyrsa(
                `${opts.join(' ')} gen-req ${escapeShell(name)} ${easy_args}`,
            );

            opts = [];

            if (caPassword)
                opts.push(`--passin=pass:${escapeShell(caPassword)}`);

            return await this.easyrsa(
                `${opts.join(' ')} sign-req ${type} ${escapeShell(name)}`,
            );
        } catch (error) {
            if (error instanceof Error) throw error;
            throw new Error('Fail to create certificate');
        }
    }

    async createServer({ name, commonName, password, caPassword }: CreateCert) {
        return await this.createCert('server', {
            name,
            commonName,
            password,
            caPassword,
        });
    }

    async createClient({ name, commonName, password, caPassword }: CreateCert) {
        return await this.createCert('client', {
            name,
            commonName,
            password,
            caPassword,
        });
    }

    async revoke({
        name,
        reason,
        caPassword,
    }: {
        name: string;
        reason: IRevokeReason;
        caPassword?: string;
    }) {
        try {
            if (!RevokeReason.includes(reason))
                throw new Error('Reason is not valid');

            if (
                !caPassword &&
                (await this.isPrivateKeyEncrypted(
                    join(this.options.pki, 'private', 'ca.key'),
                ))
            ) {
                throw new PrivateKeyIsEncryptedError('CA is encrypted');
            }

            let opts = '';

            if (caPassword) opts = `--passin=pass:${escapeShell(caPassword)}`;
            await this.easyrsa(opts + ` revoke ${escapeShell(name)} ${reason}`);
        } catch (error) {
            if (error instanceof Error) throw error;
            throw new Error('Fail to create client');
        }
    }

    async renew({ name, commonName, password, caPassword }: CreateCert) {
        try {
            if (
                !caPassword &&
                (await this.isPrivateKeyEncrypted(
                    join(this.options.pki, 'private', 'ca.key'),
                ))
            ) {
                throw new PrivateKeyIsEncryptedError('CA is encrypted');
            }

            const opts: string[] = [];
            const easy_args = password ? '' : 'nopass';
            if (commonName) opts.push(`--req-cn="${escapeShell(commonName)}"`);
            if (caPassword)
                opts.push(`--passin=pass:${escapeShell(caPassword)}`);
            if (password) opts.push(`--passout=pass:${escapeShell(password)}`);
            const output = await this.easyrsa(
                `${opts.join(' ')} renew ${escapeShell(name)} ${easy_args}`,
            );

            await this.easyrsa(
                `${opts.join(' ')} revoke-renewed ${escapeShell(name)}`,
            );

            return output;
        } catch (error) {
            if (error instanceof Error) throw error;
            throw new Error('Fail to renew certificate');
        }
    }

    async genCrl(caPassword?: string): Promise<string> {
        try {
            if (
                !caPassword &&
                (await this.isPrivateKeyEncrypted(
                    join(this.options.pki, 'private', 'ca.key'),
                ))
            ) {
                throw new PrivateKeyIsEncryptedError('CA is encrypted');
            }

            const opts = caPassword
                ? `--passin=pass:${escapeShell(caPassword)}`
                : '';

            return await this.easyrsa(`${opts} gen-crl`);
        } catch (error) {
            if (error instanceof Error) throw error;
            throw new Error('Fail to create crl');
        }
    }
}
