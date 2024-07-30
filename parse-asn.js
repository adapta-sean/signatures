import { ASN1, Stream } from 'https://unpkg.com/@lapo/asn1js@2.0.0/asn1.js';

// Function to convert hex string to byte array
function hexToBytes(hex) {
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return bytes;
}

function extractRSFromECDSASignature(asn1Signature) {
    // Decode the ASN.1 signature
    const stream = new Stream(asn1Signature);
    const asn1 = ASN1.decode(stream);

    // Ensure the ASN.1 structure is a sequence
    if (asn1.typeName() !== 'SEQUENCE' || !asn1.sub || asn1.sub.length !== 2) {
        throw new Error('Invalid ECDSA signature format');
    }

    // Extract the r and s values
    const r = asn1.sub[0].stream.parseInteger(asn1.sub[0].posContent(), asn1.sub[0].posEnd());
    const s = asn1.sub[1].stream.parseInteger(asn1.sub[1].posContent(), asn1.sub[1].posEnd());

    return { r, s };
}

// Example usage
const signatureAsn = '3045022100a13fc3d4af5371e3c391ed7c70db9446b77be6e4bee17f534df5b9e7100c417e02200537f3e0aa865224d2aa2758add527212dfb0bf4d15132f1f14c4a2130b4d270';
const asn1Signature = hexToBytes(signatureAsn);
try {
    const { r, s } = extractRSFromECDSASignature(asn1Signature);
    console.log('r:', r);
    console.log('s:', s);
} catch (error) {
    console.error('Failed to extract r and s values:', error);
}
