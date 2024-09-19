[![Node.js CI](https://github.com/DarkMaper/node-easyrsa-wrapper/actions/workflows/node.js.yml/badge.svg)](https://github.com/DarkMaper/node-easyrsa-wrapper/actions/workflows/node.js.yml)

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://github.com/node-easyrsa-wrapper/blob/main/LICENSE)


# Wrapper Easy-RSA

An EasyRSA wrapper to maintain a private key infrastructure using Javascript


## Installation

Install Easy-RSA Wrapper with npm

```bash
  npm install @darkmaper/easyrsa-wrapper
```
    
## Usage/Examples

### Start using easyrsa

With RSA
```javascript
import EasyRSA from '@darkmaper/easyrsa-wrapper'

const easyrsaOpts = {
    pki: 'path/for/pki';
    days: 3650;
    certDays: 850;
    digest: 'sha256';
    algo: 'rsa;
    keySize: 2048;
}

const easyrsa = new EasyRSA(easyrsaOpts)
```

Or with EC
```javascript
import EasyRSA from '@darkmaper/easyrsa-wrapper';

const easyrsaOpts = {
    pki: 'path/for/pki';
    days: 3650;
    certDays: 850;
    digest: 'sha256';
    algo: 'ec;
    curve: 'secp112r1'
}

const easyrsa = new EasyRSA(easyrsaOpts);
```

[See](https://wiki.openssl.org/index.php/Command_Line_Elliptic_Curve_Operations) more information about Elliptic Curves

### Init PKI Infraestructure

For default, initPki overwrite PKI folder.
```javascript
await easyrsa.initPki({ force: true })
```

### Generate Certificate Authority

```javascript
await easyrsa.buildCa({
    commonName: 'My CA',
})
```

If want encrypt the private key, you can pass a password for the CA private key
```javascript
await easyrsa.buildCa({
    commonName: 'My CA',
    password: 'CAPassword'
})
```

### Generate a Certificate

Create a server
```javascript
await easyrsa.createServer({
    name: 'filename',
    commonName: 'My server',
    password: 'CertPassword',
    caPassword: 'CaPassword' 
})
```

Create a client
```javascript
await easyrsa.createClient({
    name: 'filename',
    commonName: 'My Client',
    password: 'CertPassword',
    caPassword: 'CaPassword' 
})
```

### Revoke a Certificate

```javascript
await easyrsa.revoke({
    name: 'filename',
    reason: 'unspecified',
    caPassword: 'CaPassword'
})
```

### Renew a Certificate

```javascript
await easyrsa.renew({
    name: 'filename',
    caPassword: 'CaPassword'
})
```

### Generate a Certificate Revocation List

```javascript
await easyrsa.genCrl('CaPassword')
```

**ATENTION:** If the CA is encrypted and not set ```caPassword``` or is a bad password easyrsa throws a error.


## License

[MIT](https://github.com/DarkMaper/node-easyrsa/actions/workflows/node.js.yml)


## Authors

- [@Luis Orozco](https://www.github.com/DarkMaper)
