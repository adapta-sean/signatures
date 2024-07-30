import { ASN1 } from 'https://unpkg.com/@lapo/asn1js@2.0.0/asn1.js';
import { Hex } from 'https://unpkg.com/@lapo/asn1js@2.0.0/hex.js';

const body = document.body;
const publicKeyPem = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhemFss+H3XPDoU2x9luNMchNW0Lx
D9RnwBNkhiXBPIaWAA3DGqgeqbJjKS8I67ZKmnPOUh8/4Osmd6lkUx+xhQ==
-----END PUBLIC KEY-----`;

(async () => {
    const message = 'hello';
    const signatureAsn = '3045022100a13fc3d4af5371e3c391ed7c70db9446b77be6e4bee17f534df5b9e7100c417e02200537f3e0aa865224d2aa2758add527212dfb0bf4d15132f1f14c4a2130b4d270';
    console.log('hd', Hex.decode(signatureAsn));
    console.log(ASN1.decode(Hex.decode(signatureAsn)));
    console.log(ASN1.decode(Hex.decode(signatureAsn)).toPrettyString());
    console.log(ASN1.decode(Hex.decode(signatureAsn)).toHexString());
    console.log(ASN1.decode(Hex.decode(signatureAsn)).toB64String());
    console.log('r', ASN1.decode(Hex.decode(signatureAsn)).sub[0].toHexString().slice(4));
    console.log('s', ASN1.decode(Hex.decode(signatureAsn)).sub[1].toHexString().slice(4));
    console.log(ASN1.decode(Hex.decode(signatureAsn)).content());

    const r = ASN1.decode(Hex.decode(signatureAsn)).sub[0].toHexString().slice(4);
    const s = ASN1.decode(Hex.decode(signatureAsn)).sub[1].toHexString().slice(4);

    const P1363 = r + s;

    console.log(P1363);

    const messageEncoding = new TextEncoder().encode(message);
    console.log('messageEncoding', messageEncoding);
    const P1363Encoding = new TextEncoder().encode(P1363);
    console.log('buffer', P1363Encoding.buffer);
    const publicKey = await importPublicKey(publicKeyPem);
    console.log('publicKey', publicKey);

    console.log('P1363 Encoding', P1363Encoding);

    const isVerified = await verifyMessage(publicKey, P1363Encoding.buffer, messageEncoding);

    body.innerHTML = `<ul>
    <li>Public Key Pem: ${publicKeyPem}</li>
    <li>Signature: ${signatureAsn}</li>
    <li>Verified: ${isVerified}</li>
</ul>`;
})();

/**
 *
 * @param publicKey
 * @param signature
 * @param message
 * @returns {Promise<boolean>}
 */
async function verifyMessage(publicKey, signature, message) {
    return window.crypto.subtle.verify(
        {
            name: "ECDSA",
            hash: {name: "SHA-256"},
        },
        publicKey,
        signature,
        message
    );
}

/**
 *
 * @param pem
 * @returns {Promise<CryptoKey>}
 */
function importPublicKey(pem) {
    // fetch the part of the PEM string between header and footer
    const pemHeader = "-----BEGIN PUBLIC KEY-----\n";
    const pemFooter = "-----END PUBLIC KEY-----";
    const pemContents = pem.substring(
        pemHeader.length,
        pem.length - pemFooter.length - 1,
    );
    console.log('b64 key', pemContents);
    // base64 decode the string to get the binary data
    const binaryDerString = window.atob(pemContents);
    // convert from a binary string to an ArrayBuffer
    const binaryDer = str2ab(binaryDerString);

    return window.crypto.subtle.importKey(
        "spki",
        binaryDer,
        {
            name: "ECDSA",
            namedCurve: "P-256",
        },
        true,
        ["verify"],
    );
}

/**
 * Convert a string into an ArrayBuffer
 * from https://developers.google.com/web/updates/2012/06/How-to-convert-ArrayBuffer-to-and-from-String
 *
 * @param str
 * @returns {ArrayBuffer}
 */
function str2ab(str) {
    const buf = new ArrayBuffer(str.length);
    const bufView = new Uint8Array(buf);
    for (let i = 0, strLen = str.length; i < strLen; i++) {
        bufView[i] = str.charCodeAt(i);
    }
    return buf;
}

