import { existsSync, readFileSync, rmSync } from 'node:fs';
import { BadCaPasswordError, CaAlreadyExistsError, CaNotFoundError, CertificateAlreadyExistsError, CertificateNotFoundError, PkiDirNotFoundError, PrivateKeyIsEncryptedError } from '../src/errors';
import EasyRSA, { EasyRSAArgs } from '../src/index';
import { join } from 'node:path';

const pki = './.tmp/pki';

const easyrsaConf: Partial<EasyRSAArgs> = {
    pki,
    algo: 'rsa',
    keySize: 1024,
};

const password = 'Testing';
const certPassword = 'Testing';
let name: string;

const timeout = 10000; //10 seconds

describe('=== PKI AND CA ===', () => {
    const easyrsa = new EasyRSA(easyrsaConf);

    describe('Try methods without PKI initializated', () => {

        beforeAll(() => {
            rmSync(join(process.cwd(), pki), { force: true, recursive: true });
        })

        test('Failing to create CA', async () => {
            await expect(easyrsa.buildCa()).rejects.toThrow(PkiDirNotFoundError);
        })
    
        test('Fail create server', async () => {
            await expect(easyrsa.createServer({ name: 'server' })).rejects.toThrow(CaNotFoundError);
        })

        test('Fail create server with ca passphrase', async () => {
            await expect(easyrsa.createServer({ name: 'server', caPassword: password })).rejects.toThrow(PkiDirNotFoundError);
        })
    
        test('Fail create client', async () => {
            await expect(easyrsa.createClient({ name: 'client' })).rejects.toThrow(CaNotFoundError);
        })

        test('Fail create client with ca passphrase', async () => {
            await expect(easyrsa.createClient({ name: 'client', caPassword: password })).rejects.toThrow(PkiDirNotFoundError);
        })

        test('Fail renew certificate', async () => {
            await expect(easyrsa.renew({ name: 'client' })).rejects.toThrow(CaNotFoundError);
        })

        test('Fail renew certificate with ca passphrase', async () => {
            await expect(easyrsa.renew({ name: 'client', caPassword: 'aaa' })).rejects.toThrow(PkiDirNotFoundError);
        })

        test('Fail revoke certificate', async () => {
            await expect(easyrsa.revoke({ name: 'client', reason: 'unspecified' })).rejects.toThrow(CaNotFoundError);
        })

        test('Fail revoke certificate with ca passphrase', async () => {
            await expect(easyrsa.revoke({ name: 'client', reason: 'unspecified', caPassword: 'aa' })).rejects.toThrow(PkiDirNotFoundError);
        })

        test('Fail gen crl', async () => {
            await expect(easyrsa.genCrl()).rejects.toThrow(CaNotFoundError);
        })

        test('Fail gen crl with ca passphrase', async () => {
            await expect(easyrsa.genCrl('aa')).rejects.toThrow(PkiDirNotFoundError);
        })
    })

    describe('Try methods with PKI initializated and without CA created', () => {

        beforeAll(async () => {
            await easyrsa.initPki();
        })
    
        test('Fail create server', async () => {
            await expect(easyrsa.createServer({ name: 'server' })).rejects.toThrow(CaNotFoundError);
        }, timeout)
    
        test('Fail create client', async () => {
            await expect(easyrsa.createClient({ name: 'client' })).rejects.toThrow(CaNotFoundError);
        }, timeout)

        test('Fail create server with CA passphrase', async () => {
            await expect(easyrsa.createServer({ name: 'server', caPassword: password })).rejects.toThrow(CaNotFoundError);
        }, timeout)
    
        test('Fail create client with CA passphrase', async () => {
            await expect(easyrsa.createClient({ name: 'client', caPassword: password })).rejects.toThrow(CaNotFoundError);
        }, timeout)

        test('Fail renew certificate', async () => {
            await expect(easyrsa.renew({ name: 'client' })).rejects.toThrow(CaNotFoundError);
        })

        test('Fail renew certificate with ca passphrase', async () => {
            await expect(easyrsa.renew({ name: 'client', caPassword: 'aaa' })).rejects.toThrow(CaNotFoundError);
        })

        test('Fail revoke certificate', async () => {
            await expect(easyrsa.revoke({ name: 'client', reason: 'unspecified' })).rejects.toThrow(CaNotFoundError);
        })

        test('Fail revoke certificate with ca passphrase', async () => {
            await expect(easyrsa.revoke({ name: 'client', reason: 'unspecified', caPassword: 'aa' })).rejects.toThrow(CaNotFoundError);
        })

        test('Fail gen crl', async () => {
            await expect(easyrsa.genCrl()).rejects.toThrow(CaNotFoundError);
        })

        test('Fail gen crl with ca passphrase', async () => {
            await expect(easyrsa.genCrl('aa')).rejects.toThrow(CaNotFoundError);
        })
    })

    afterAll(() => {
        rmSync(join(process.cwd(), pki), { force: true, recursive: true });
    })
})

describe('=== CA ===', () => {
    const easyrsa = new EasyRSA(easyrsaConf);

    beforeEach(async () => {
        await easyrsa.initPki();
    })

    test('Creating CA without passphare', async () => {
        await expect(easyrsa.buildCa()).resolves.toBeDefined();
        expect(existsSync(join(process.cwd(), pki, 'ca.crt'))).toBeTruthy();
        expect(existsSync(join(process.cwd(), pki, 'private', 'ca.key'))).toBeTruthy();
    }, timeout)

    test('Creating CA with passphare', async () => {
        await expect(easyrsa.buildCa({ password: 'Testing'})).resolves.toBeDefined();
        expect(existsSync(join(process.cwd(), pki, 'ca.crt'))).toBeTruthy();
        expect(existsSync(join(process.cwd(), pki, 'private', 'ca.key'))).toBeTruthy();
        const privateKey = readFileSync(join(process.cwd(), pki, 'private', 'ca.key'), 'utf8');
        expect(privateKey.includes('ENCRYPTED')).toBeTruthy();
    }, timeout)

    test('Fail to re-create same CA', async () => {
        await expect(easyrsa.buildCa()).resolves.toBeDefined();
        await expect(easyrsa.buildCa()).rejects.toThrow(CaAlreadyExistsError);
    }, timeout)
})

describe('=== SERVER ===', () => {
    const easyrsa = new EasyRSA(easyrsaConf);

    describe('Try create server with unprotected CA', () => {
        beforeEach(async () => {
            await easyrsa.initPki();
            await easyrsa.buildCa();
            name = 'server';
        })

        test('Create server without passphrase', async () => {
            await expect(easyrsa.createServer({ name })).resolves.toBeDefined();
            expect(existsSync(join(process.cwd(), pki, 'issued', `${name}.crt`))).toBeTruthy();
            expect(existsSync(join(process.cwd(), pki, 'private', `${name}.key`))).toBeTruthy();
        }, timeout)

        test('Create server with passphrase', async () => {
            await expect(easyrsa.createServer({ name, password: certPassword })).resolves.toBeDefined();
            expect(existsSync(join(process.cwd(), pki, 'issued', `${name}.crt`))).toBeTruthy();
            expect(existsSync(join(process.cwd(), pki, 'private', `${name}.key`))).toBeTruthy();
            const privateKey = readFileSync(join(process.cwd(), pki, 'private', `${name}.key`), 'utf8');
            expect(privateKey.includes('ENCRYPTED')).toBeTruthy();
        }, timeout)

        test('Fail re-create server', async () => {
            await expect(easyrsa.createServer({ name })).resolves.toBeDefined();
            await expect(easyrsa.createServer({ name })).rejects.toThrow(CertificateAlreadyExistsError);
        }, timeout)

    })

    describe('Try create server with protected CA', () => {
        beforeEach(async () => {
            await easyrsa.initPki();
            await easyrsa.buildCa({ password });
            name = 'server';
        }, timeout)

        test('Create server without passphrase', async () => {
            await expect(easyrsa.createServer({ name, caPassword: password })).resolves.toBeDefined();
            expect(existsSync(join(process.cwd(), pki, 'issued', `${name}.crt`))).toBeTruthy();
            expect(existsSync(join(process.cwd(), pki, 'private', `${name}.key`))).toBeTruthy();
        }, timeout)

        test('Create server with passphrase', async () => {
            await expect(easyrsa.createServer({ name, caPassword: password, password: certPassword })).resolves.toBeDefined();
            expect(existsSync(join(process.cwd(), pki, 'issued', `${name}.crt`))).toBeTruthy();
            expect(existsSync(join(process.cwd(), pki, 'private', `${name}.key`))).toBeTruthy();
            const privateKey = readFileSync(join(process.cwd(), pki, 'private', `${name}.key`), 'utf8');
            expect(privateKey.includes('ENCRYPTED')).toBeTruthy();
        }, timeout)

        test('Fail to create server bad ca passphrase', async () => {
            await expect(easyrsa.createServer({ name, caPassword: 'a'})).rejects.toThrow(BadCaPasswordError);
        }, timeout)

        test('Fail to create server without ca passphrase', async () => {
            await expect(easyrsa.createServer({ name })).rejects.toThrow(PrivateKeyIsEncryptedError);
        }, timeout)
    })
})

describe('=== CLIENT ===', () => {
    const easyrsa = new EasyRSA(easyrsaConf);

    describe('Try create client with unprotected CA', () => {
        beforeEach(async () => {
            await easyrsa.initPki();
            await easyrsa.buildCa();
            name = 'client';
        })

        test('Create client without passphrase', async () => {
            await expect(easyrsa.createClient({ name })).resolves.toBeDefined();
            expect(existsSync(join(process.cwd(), pki, 'issued', `${name}.crt`))).toBeTruthy();
            expect(existsSync(join(process.cwd(), pki, 'private', `${name}.key`))).toBeTruthy();
        }, timeout)

        test('Create client with passphrase', async () => {
            await expect(easyrsa.createClient({ name, password: certPassword })).resolves.toBeDefined();
            expect(existsSync(join(process.cwd(), pki, 'issued', `${name}.crt`))).toBeTruthy();
            expect(existsSync(join(process.cwd(), pki, 'private', `${name}.key`))).toBeTruthy();
            const privateKey = readFileSync(join(process.cwd(), pki, 'private', `${name}.key`), 'utf8');
            expect(privateKey.includes('ENCRYPTED')).toBeTruthy();
        }, timeout)

        test('Fail re-create client', async () => {
            await expect(easyrsa.createClient({ name })).resolves.toBeDefined();
            await expect(easyrsa.createClient({ name })).rejects.toThrow(CertificateAlreadyExistsError);
        }, timeout)

    })

    describe('Try client client with protected CA', () => {
        beforeEach(async () => {
            await easyrsa.initPki();
            await easyrsa.buildCa({ password });
            name = 'client'; 
        })

        test('Create client without passphrase', async () => {
            await expect(easyrsa.createClient({ name, caPassword: password })).resolves.toBeDefined();
            expect(existsSync(join(process.cwd(), pki, 'issued', `${name}.crt`))).toBeTruthy();
            expect(existsSync(join(process.cwd(), pki, 'private', `${name}.key`))).toBeTruthy();
        }, timeout)

        test('Create client with passphrase', async () => {
            await expect(easyrsa.createClient({ name, caPassword: password, password: certPassword })).resolves.toBeDefined();
            expect(existsSync(join(process.cwd(), pki, 'issued', `${name}.crt`))).toBeTruthy();
            expect(existsSync(join(process.cwd(), pki, 'private', `${name}.key`))).toBeTruthy();
            const privateKey = readFileSync(join(process.cwd(), pki, 'private', `${name}.key`), 'utf8');
            expect(privateKey.includes('ENCRYPTED')).toBeTruthy();
        }, timeout)

        test('Fail to create client bad ca passphrase', async () => {
            await expect(easyrsa.createClient({ name, caPassword: 'a'})).rejects.toThrow(BadCaPasswordError);
        }, timeout)

        test('Fail to create client without ca passphrase', async () => {
            await expect(easyrsa.createClient({ name })).rejects.toThrow(PrivateKeyIsEncryptedError);
        }, timeout)
    })
})

describe('=== REVOKE ===', () => {
    const easyrsa = new EasyRSA(easyrsaConf);

    describe('Revoke certificate with unprotected CA', () => {
        beforeAll(async () => {
            name = 'client';
            await easyrsa.initPki();
            await easyrsa.buildCa();
        })

        test('Create and revoke certificate', async () => {
            await easyrsa.createClient({ name });
            await expect(easyrsa.revoke({ name, reason: 'unspecified' })).resolves.toBeUndefined();
        }, timeout)

        test('Fail revoke inexsistent certificate', async () => {
            await expect(easyrsa.revoke({ name: 'noexists', reason: 'unspecified' })).rejects.toThrow(CertificateNotFoundError);
        }, timeout)
    })

    describe('Revoke certificate with protected CA', () => {
        beforeAll(async () => {
            name = 'client';
            await easyrsa.initPki();
            await easyrsa.buildCa({ password });
        })

        test('Create and revoke certificate', async () => {
            await easyrsa.createClient({ name, caPassword: password });
            await expect(easyrsa.revoke({ name, reason: 'unspecified', caPassword: password })).resolves.toBeUndefined();
        }, timeout)

        test('Fail revoke certificate bad ca password', async () => {
            name = 'client2'
            await easyrsa.createClient({ name, caPassword: password });
            await expect(easyrsa.revoke({ name, reason: 'unspecified', caPassword: 'password' })).rejects.toThrow(BadCaPasswordError);
        }, timeout)

        test('Fail revoke certificate no ca password', async () => {
            name = 'client3'
            await easyrsa.createClient({ name, caPassword: password });
            await expect(easyrsa.revoke({ name, reason: 'unspecified' })).rejects.toThrow(PrivateKeyIsEncryptedError);
        }, timeout)
    })
})

describe('=== RENEW ===', () => {
    const easyrsa = new EasyRSA(easyrsaConf);

    describe('Renew certificate signed by unprotected CA', () => {
        beforeAll(async () => {
            name = 'client';
            await easyrsa.initPki();
            await easyrsa.buildCa();
        })

        test('Create and renew certificate', async () => {
            await easyrsa.createClient({ name });
            await expect(easyrsa.renew({ name })).resolves.toBeDefined();
        })

        test('Fail to renew a inexistent certificate', async () => {
            await expect(easyrsa.renew({ name: 'inexistent' })).rejects.toThrow(CertificateNotFoundError);
        })
    })

    describe('Renew certificate signed by protected CA', () => {
        beforeAll(async () => {
            name = 'client';
            await easyrsa.initPki();
            await easyrsa.buildCa({ password });
        })

        test('Create and renew certificate', async () => {
            await easyrsa.createClient({ name, caPassword: password });
            await expect(easyrsa.renew({ name, caPassword: password })).resolves.toBeDefined();
        })

        test('Fail renew certificate bad ca passphrase', async () => {
            name = 'client2';
            await easyrsa.createClient({ name, caPassword: password });
            await expect(easyrsa.renew({ name, caPassword: 'password' })).rejects.toThrow(BadCaPasswordError);
        })

        test('Fail renew certificate bad ca passphrase', async () => {
            name = 'client3';
            await easyrsa.createClient({ name, caPassword: password });
            await expect(easyrsa.renew({ name })).rejects.toThrow(PrivateKeyIsEncryptedError);
        })

        test('Fail to renew a inexistent certificate', async () => {
            await expect(easyrsa.renew({ name: 'inexistent', caPassword: password })).rejects.toThrow(CertificateNotFoundError);
        })
    })
})

describe('=== CRL ===', () => {
    const easyrsa = new EasyRSA(easyrsaConf);

    describe('Generate CRL with unprotected CA', () => {
        beforeAll(async () => {
            await easyrsa.initPki();
            await easyrsa.buildCa();
        })

        test('Generate CRL', async () => {
            await easyrsa.genCrl();
            expect(existsSync(join(process.cwd(),pki, 'crl.pem'))).toBeTruthy();
        })
    })

    describe('Generate CRL with protected CA', () => {
        beforeAll(async () => {
            await easyrsa.initPki();
            await easyrsa.buildCa({ password });
        })

        test('Fail generate CRL without CA passphrase', async () => {
            await expect(easyrsa.genCrl()).rejects.toThrow(PrivateKeyIsEncryptedError);
        })

        test('Fail generate CRL with bad CA passphrase', async () => {
            await expect(easyrsa.genCrl('hola')).rejects.toThrow(BadCaPasswordError);
        })
    })
})