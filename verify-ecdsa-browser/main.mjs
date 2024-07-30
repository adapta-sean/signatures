import { ASN1 } from 'https://unpkg.com/@lapo/asn1js@2.0.0/asn1.js';
import { Hex } from 'https://unpkg.com/@lapo/asn1js@2.0.0/hex.js';

const body = document.body;
const publicKeyPem = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfBbKwUFhqdJfWHQBymbtkTGvb+6A
bj9diSxQE6cmYTMU8CNUs87SOQUxFzgDtaNKQYJC/ekbG83eCrjN/J8w7g==
-----END PUBLIC KEY-----`;

(async () => {
    const message = 'hello';
    const signatureAsn = '3045022100d9093b909633d6dcb5be8fa007b8d130f3072df47074d30775c26ca75d658088022024a0745157405352dea54dc37c535884741728683e633166ce81929f2840dec8';
    const asn1 = ASN1.decode(Hex.decode(signatureAsn));

    const r = asn1.sub[0].stream.enc.slice(asn1.sub[0].posContent(), asn1.sub[0].posEnd());
    const s = asn1.sub[1].stream.enc.slice(asn1.sub[1].posContent(), asn1.sub[1].posEnd());

    console.log(r, s);
    console.log(r.length, s.length);

    const uintArr = new Uint8Array(r.length + s.length);
    uintArr.set(r, 0);
    uintArr.set(s, r.length);
    const rawSignature = uintArr.buffer;

    const derSignature = hexStringToArrayBuffer(signatureAsn);
    const rawSignatureTwo = derToRawSignature(derSignature);

    console.log('ONE:', rawSignature);
    console.log('TWO:', rawSignatureTwo);

    const messageEncoding = new TextEncoder().encode(message);
    console.log('messageEncoding', messageEncoding);
    const publicKey = await importPublicKey(publicKeyPem);
    console.log('publicKey', publicKey);

    const isVerified = await verifyMessage(publicKey, rawSignature, messageEncoding);

    body.innerHTML = `<ul>
    <li>Public Key Pem: ${publicKeyPem}</li>
    <li>Signature ASN.1: ${signatureAsn}</li>
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

function concatUint8Arrays(a, b) {
    const result = new Uint8Array(a.length + b.length);
    result.set(a, 0);
    result.set(b, a.length);
    return result;
}



////////////

function derToRawSignature(derSignature) {
    const asn1 = new Uint8Array(derSignature);
    if (asn1[0] !== 0x30) throw new Error("Invalid DER signature format");

    const rLength = asn1[3];
    const rStart = 4;
    const rEnd = rStart + rLength;

    const sLength = asn1[rEnd + 1];
    const sStart = rEnd + 2;
    const sEnd = sStart + sLength;

    const r = asn1.slice(rStart, rEnd);
    const s = asn1.slice(sStart, sEnd);

    console.log(r, s);
    console.log(r.length, s.length);


    const rawSignature = new Uint8Array(r.length + s.length);
    rawSignature.set(r, 0);
    rawSignature.set(s, r.length);

    return rawSignature.buffer;
}

// Example DER-encoded ECDSA signature (hex string)

// Convert hex string to ArrayBuffer
function hexStringToArrayBuffer(hexString) {
    const byteArray = new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    return byteArray.buffer;
}
