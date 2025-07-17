[![Publish Package to NPM](https://github.com/DarkMaper/node-easyrsa-wrapper/actions/workflows/publish.yml/badge.svg)](https://github.com/DarkMaper/node-easyrsa-wrapper/actions/workflows/publish.yml)![NPM Version](https://img.shields.io/npm/v/%40darkmaper%2Feasyrsa-wrapper)![NPM Downloads](https://img.shields.io/npm/dw/%40darkmaper%2Feasyrsa-wrapper)



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
    pki: 'path/for/pki',
    days: 3650,
    certDays: 850,
    digest: 'sha256',
    algo: 'rsa',
    keySize: 2048,
}

const easyrsa = new EasyRSA(easyrsaOpts)
```

Or with EC
```javascript
import EasyRSA from '@darkmaper/easyrsa-wrapper';

const easyrsaOpts = {
    pki: 'path/for/pki',
    days: 3650,
    certDays: 850,
    digest: 'sha256',
    algo: 'ec',
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

Create a code signing
```javascript
await easyrsa.createCodeSigning({
    name: 'filename',
    commonName: 'My Code Signing',
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

# QA
## How can I contribute to the project?
The project is based on Easy-RSA for Linux. I plan to add Windows support in the future. For project development, it's recommended to use Linux or WSL (Windows Subsystem for Linux), as the tests won't run on Windows when using the Linux version of Easy-RSA. To contribute, fork the project and create a branch with the format ```feature/<name-feature>``` or ```fix/<fix-name>```. Don't create pull request to main branch.

## Why include the binary of Easy-RSA in the package instead of being able to use external binaries?
Easy-RSA Wrapper is, as its name suggests, a JavaScript wrapper for using the Bash binary. Both the JavaScript code and the binary's commands must match. Easy-RSA can change how its commands work, deprecate them, or remove them. To prevent the package from breaking because the version of Easy-RSA being used modified how a command works, it was decided to include the binary in the package.


## License

[MIT](https://github.com/node-easyrsa-wrapper/blob/main/LICENSE)


## Authors

- [@Luis Orozco](https://www.github.com/DarkMaper)
