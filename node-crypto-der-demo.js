import * as jsrsasign from "jsrsasign";
import crypto from "crypto";

const hash = "sha256";
const message = "hello";
const curve = "secp256k1";

const {privateKey, publicKey} = crypto.generateKeyPairSync('ec', {
    namedCurve: curve,
    publicKeyEncoding: {type: 'spki', format: 'der'},
    privateKeyEncoding: {type: 'pkcs8', format: 'der'},
});

console.log('Private key buffer', privateKey);
console.log('Public key buffer', publicKey);

console.log(`Private key:\n${privateKey.toString('hex')}`);
console.log(`Public key:\n${publicKey.toString('hex')}`);

const privateKeyPem = derToPem(privateKey, 'PRIVATE KEY');
const publicKeyPem = derToPem(publicKey, 'PUBLIC KEY');

console.log(`Private key PEM:\n${privateKeyPem}`);
console.log(`Public key PEM:\n${publicKeyPem}`);

const sign = crypto.createSign(hash);

sign.write(message);
sign.end();
const signature = sign.sign(privateKeyPem);

const verify = crypto.createVerify(hash);
verify.write(message);
verify.end();

console.log(`Message:\t${message}`);
console.log(`Hash:\t\t${hash}`);
console.log(`Curve:\t\t${curve}`);

console.log(`\nSignature: ${signature.toString('hex')}`);

console.log(`Signature verified: ${verify.verify(publicKeyPem, signature)}`);

/**
 * Converts a DER-encoded key to PEM format.
 * @param {Buffer} derKey - The DER-encoded key.
 * @param {string} type - The type of key (eg 'PRIVATE KEY' or 'PUBLIC KEY').
 * @returns {string} The PEM-encoded key.
 */
function derToPem(derKey, type) {
    return jsrsasign.hextopem(jsrsasign.BAtohex(derKey), type);
}

// /**
//  * Converts a DER-encoded key to PEM format.
//  * @param {Buffer} derKey - The DER-encoded key.
//  * @param {string} type - The type of key ('PRIVATE KEY' or 'PUBLIC KEY').
//  * @returns {string} The PEM-encoded key.
//  */
// function derToPem(derKey, type) {
//     const derKeyString = derKey.toString('base64');
//     let pemKey = '';
//     pemKey += `-----BEGIN ${type}-----\n`;
//     for (let i = 0; i < derKeyString.length; i += 64) {
//         pemKey += derKeyString.substring(i, i + 64) + '\n';
//     }
//     pemKey += `-----END ${type}-----\n`;
//     return pemKey;
// }

