import * as jsrsasign from "jsrsasign";

const curve = 'secp256r1';
const alg = 'SHA256withECDSA';

const ec = new jsrsasign.KJUR.crypto.ECDSA({curve});
const keyPair = ec.generateKeyPairHex();
const publicKey = keyPair.ecpubhex;
const privateKey = keyPair.ecprvhex;

console.log(publicKey, privateKey);

const sig = new jsrsasign.KJUR.crypto.Signature({alg});

const data = 'hello';

sig.init({d: privateKey, curve});
sig.updateString(data);
const signature = sig.sign();

console.log(signature);

const ecdsa = new jsrsasign.KJUR.crypto.ECDSA({ curve, pub: publicKey });
const pemKey = jsrsasign.KEYUTIL.getPEM(ecdsa);

console.log(pemKey);


const sigTwo = new jsrsasign.KJUR.crypto.Signature({alg});

// const signatureEcdsa = new jsrsasign.KJUR.crypto.ECDSA({curve});
// signatureEcdsa.setPublicKeyHex(publicKey);

sigTwo.init(pemKey);
sigTwo.updateString(data);
console.log('Signature verified:', sigTwo.verify(signature));



