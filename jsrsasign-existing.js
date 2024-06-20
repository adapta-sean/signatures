import * as jsrsasign from 'jsrsasign';

const curve = 'secp256k1';
const alg = 'SHA256withECDSA';

const ec = new jsrsasign.KJUR.crypto.ECDSA({curve});
const sig = new jsrsasign.KJUR.crypto.Signature({alg});

const keypair = ec.generateKeyPairHex();
const privateKey = keypair.ecprvhex;
const publicKey = keypair.ecpubhex;

const sigvalcap = 'xoxoxoxoxoxoxoxo';
sig.init({d: privateKey, curve});
sig.updateString(sigvalcap);

const signature = sig.sign();

console.log(signature);

// Client
const sigTwo = new jsrsasign.KJUR.crypto.Signature({alg});

const signatureEcdsa = new jsrsasign.KJUR.crypto.ECDSA({curve});
signatureEcdsa.setPublicKeyHex(publicKey);
sigTwo.init(signatureEcdsa);
sigTwo.updateString(sigvalcap);
console.log('Signature verified:', sigTwo.verify(signature));
