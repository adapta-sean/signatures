import crypto from "crypto";

const hash = "sha256";
const message = "hello";
const curve = "secp256k1";

const {privateKey, publicKey} = crypto.generateKeyPairSync('ec', {
    namedCurve: curve,
    publicKeyEncoding: {type: 'spki', format: 'pem'},
    privateKeyEncoding: {type: 'pkcs8', format: 'pem'},
});
console.log(`Private key:\n${privateKey.toString()}`);
console.log(`Public key:\n${publicKey.toString()}`);

const sign = crypto.createSign(hash);
sign.write(message);
sign.end();
const signature = sign.sign(privateKey, 'hex');

const verify = crypto.createVerify(hash);
verify.write(message);
verify.end();

console.log(`Message:\t${message}`);
console.log(`Hash:\t\t${hash}`);
console.log(`Curve:\t\t${curve}`);

console.log(`\nSignature: ${signature.toString()}`);

console.log(`Signature verified: ${verify.verify(publicKey, signature, 'hex')}`);
