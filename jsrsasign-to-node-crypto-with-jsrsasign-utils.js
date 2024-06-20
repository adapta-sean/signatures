import crypto from "crypto";
import * as jsrsasign from 'jsrsasign';

const curve = 'secp256k1';
const alg = 'SHA256withECDSA';

const ec = new jsrsasign.KJUR.crypto.ECDSA({curve});
const sig = new jsrsasign.KJUR.crypto.Signature({alg});

const keypair = ec.generateKeyPairHex();
const privateKeyHex = keypair.ecprvhex;
const publicKeyHex = keypair.ecpubhex;

console.log('Private key hex:', privateKeyHex);
console.log('Public key hex:', publicKeyHex);

const sigvalcap = 'xoxoxoxoxoxoxoxo';
sig.init({d: privateKeyHex, curve});
sig.updateString(sigvalcap);

const signatureHex = sig.sign();


// Client
const message = 'xoxoxoxoxoxoxoxo';

// ASN.1 DER encoding prefix for uncompressed public key on secp256r1
const derPrefix = '3056301006072a8648ce3d020106052b8104000a034200';

const publicKeyPem = jsrsasign.KJUR.asn1.ASN1Util.getPEMStringFromHex(derPrefix + publicKeyHex, 'PUBLIC KEY');

console.log(publicKeyPem);

const verify = crypto.createVerify('SHA256');
verify.update(message);
verify.end();

console.log('Signature verified:', verify.verify(publicKeyPem, signatureHex, 'hex'));