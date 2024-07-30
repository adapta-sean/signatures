(async () => {

    /*
    Store the calculated signature here, so we can verify it later.
    */
    let signature;

    /*
    Fetch the contents of the "message" textbox, and encode it
    in a form we can use for sign operation.
    */
    function getMessageEncoding() {
        const messageBox = document.querySelector("#ecdsa-message");
        let message = messageBox.value;
        let enc = new TextEncoder();
        return enc.encode(message);
    }

    function ArrayBuffertohex(buffer) {
        var hex = "";
        var view = new DataView(buffer);

        for (var i = 0; i < buffer.byteLength; i++) {
            hex += ("00" + view.getUint8(i).toString(16)).slice(-2);
        }

        return hex;
    }

    /*
    Get the encoded message-to-sign, sign it and display a representation
    of the first part of it in the "signature" element.
    */
    async function signMessage(privateKey) {
        const signatureValue = document.querySelector(".ecdsa .signature-value");
        signatureValue.classList.remove("valid", "invalid");

        let encoded = getMessageEncoding();
        signature = await window.crypto.subtle.sign(
            {
                name: "ECDSA",
                hash: {name: "SHA-256"},
            },
            privateKey,
            encoded
        );

        console.log('raw', signature);
        console.log('typeof', typeof signature);
        console.log('hex', ArrayBuffertohex(signature));

        signatureValue.classList.add('fade-in');
        signatureValue.addEventListener('animationend', () => {
            signatureValue.classList.remove('fade-in');
        }, { once: true });
        let buffer = new Uint8Array(signature, 0, 5);
        signatureValue.textContent = `${buffer}...[${signature.byteLength} bytes total]`;
    }

    /*
    Fetch the encoded message-to-sign and verify it against the stored signature.
    * If it checks out, set the "valid" class on the signature.
    * Otherwise set the "invalid" class.
    */
    async function verifyMessage(publicKey) {
        const signatureValue = document.querySelector(".ecdsa .signature-value");
        signatureValue.classList.remove("valid", "invalid");

        let encoded = getMessageEncoding();
        let result = await window.crypto.subtle.verify(
            {
                name: "ECDSA",
                hash: {name: "SHA-256"},
            },
            publicKey,
            signature,
            encoded
        );

        signatureValue.classList.add(result ? "valid" : "invalid");
    }

    const privateKeyPem = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgMWzCdPyhntmHUtOD
yoAVSx0HPA8wfxU4QjKwrSlmKo6hRANCAATXRLhEu8bAVJ50bKx4KxvDYNO9zShN
yyZprh3In+DiKmB1O1r20DqXP499m5pvnUTBQoYXpAHHnUdxQ78URxGw
-----END PRIVATE KEY-----`;
    const publicKeyPem = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE10S4RLvGwFSedGyseCsbw2DTvc0o
Tcsmaa4dyJ/g4ipgdTta9tA6lz+PfZuab51EwUKGF6QBx51HcUO/FEcRsA==
-----END PUBLIC KEY-----`;

    const privateKey = await importPrivateKey(privateKeyPem);
    const publicKey = await importPublicKey(publicKeyPem);

    console.log(privateKey);
    console.log(publicKey)  ;

    const signButton = document.querySelector(".ecdsa .sign-button");
    signButton.addEventListener("click", async () => {
        await signMessage(privateKey);
    });

    const verifyButton = document.querySelector(".ecdsa .verify-button");
    verifyButton.addEventListener("click", async () => {
        await verifyMessage(publicKey);
    });

    /**
     * Convert a string into an ArrayBuffer
     * from https://developers.google.com/web/updates/2012/06/How-to-convert-ArrayBuffer-to-and-from-String
     */
    function str2ab(str) {
        const buf = new ArrayBuffer(str.length);
        const bufView = new Uint8Array(buf);
        for (let i = 0, strLen = str.length; i < strLen; i++) {
            bufView[i] = str.charCodeAt(i);
        }
        return buf;
    }

    /**
     * Import a PEM encoded RSA private key, to use for RSA-PSS signing.
     * Takes a string containing the PEM encoded key, and returns a Promise
     * that will resolve to a CryptoKey representing the private key.
     */
    function importPrivateKey(pem) {
        // fetch the part of the PEM string between header and footer
        const pemHeader = "-----BEGIN PRIVATE KEY-----\n";
        const pemFooter = "-----END PRIVATE KEY-----";
        const pemContents = pem.substring(
            pemHeader.length,
            pem.length - pemFooter.length - 1,
        );

        console.log(pemContents);

        // base64 decode the string to get the binary data
        const binaryDerString = window.atob(pemContents);
        // convert from a binary string to an ArrayBuffer
        const binaryDer = str2ab(binaryDerString);

        return window.crypto.subtle.importKey(
            "pkcs8",
            binaryDer,
            {
                name: "ECDSA",
                namedCurve: "P-256",
            },
            true,
            ["sign"],
        );
    }

    function importPublicKey(pem) {
        // fetch the part of the PEM string between header and footer
        const pemHeader = "-----BEGIN PUBLIC KEY-----";
        const pemFooter = "-----END PUBLIC KEY-----";
        const pemContents = pem.substring(
            pemHeader.length,
            pem.length - pemFooter.length - 1,
        );
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
})();