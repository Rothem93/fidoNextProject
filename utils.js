const crypto = require('crypto');
const base64url = require('base64url');
const cbor = require('cbor');
const jsrsasign = require('jsrsasign');

/**
 * U2F Presence constant
 */
let U2F_USER_PRESENTED = 0x01;

/**
 * Takes signature, data and PEM public key and tries to verify signature
 * @param  {Buffer} signature
 * @param  {Buffer} data
 * @param  {String} publicKey - PEM encoded public key
 * @return {Boolean}
 */
let verifySignature = (signature, data, publicKey) => {
    console.log("verifSignature", signature, data, publicKey)
    return crypto.createVerify('SHA256')
        .update(data)
        .verify(publicKey, signature);
}


/**
 * Returns base64url encoded buffer of the given length
 * @param  {Number} len - length of the buffer
 * @return {String}     - base64url random buffer
 */
let randomBase64URLBuffer = (len) => {
    len = len || 32;

    let buff = crypto.randomBytes(len);

    return base64url(buff);
}

/**
 * Generates makeCredentials request
 * @param  {String} username       - username
 * @param  {String} displayName    - user's personal display name
 * @param  {String} id             - user's base64url encoded id
 * @return {MakePublicKeyCredentialOptions} - server encoded make credentials request
 */
let generateServerMakeCredRequest = (username, displayName, id) => {
    return {
        challenge: randomBase64URLBuffer(32),

        rp: {
            name: "BBVA Next Family"
        },

        user: {
            id: id,
            name: username,
            displayName: displayName
        },

        attestation: 'direct',

        pubKeyCredParams: [{
                type: "public-key",
                alg: -7 // "ES256" IANA COSE Algorithms registry
            },
            {
                type: "public-key",
                alg: -257 // "RS256" IANA COSE Algorithms registry
            }
        ]
    }
}

/**
 * Generates getAssertion request
 * @param  {Array} authenticators              - list of registered authenticators
 * @return {PublicKeyCredentialRequestOptions} - server encoded get assertion request
 */
let generateServerGetAssertion = (authenticators) => {
    let allowCredentials = [];
    for (let authr of authenticators) {
        allowCredentials.push({
            type: 'public-key',
            id: authr.credID,
            transports: ['usb', 'ble', 'nfc', 'internal'],
        })
    }
    return {
        challenge: randomBase64URLBuffer(32),
        allowCredentials: allowCredentials
    }
}


/**
 * Returns SHA-256 digest of the given data.
 * @param  {Buffer} data - data to hash
 * @return {Buffer}      - the hash
 */
let hash = (data) => {
    return crypto.createHash('SHA256').update(data).digest();
}

/**
 * Takes COSE encoded public key and converts it to RAW PKCS ECDHA key
 * @param  {Buffer} COSEPublicKey - COSE encoded public key
 * @return {Buffer}               - RAW PKCS encoded public key
 */
let COSEECDHAtoPKCS = (COSEPublicKey) => {
    /* 
       +------+-------+-------+---------+----------------------------------+
       | name | key   | label | type    | description                      |
       |      | type  |       |         |                                  |
       +------+-------+-------+---------+----------------------------------+
       | crv  | 2     | -1    | int /   | EC Curve identifier - Taken from |
       |      |       |       | tstr    | the COSE Curves registry         |
       |      |       |       |         |                                  |
       | x    | 2     | -2    | bstr    | X Coordinate                     |
       |      |       |       |         |                                  |
       | y    | 2     | -3    | bstr /  | Y Coordinate                     |
       |      |       |       | bool    |                                  |
       |      |       |       |         |                                  |
       | d    | 2     | -4    | bstr    | Private key                      |
       +------+-------+-------+---------+----------------------------------+
    */

    let coseStruct = cbor.decodeAllSync(COSEPublicKey)[0];
    let tag = Buffer.from([0x04]);
    let x = coseStruct.get(-2);
    let y = coseStruct.get(-3);

    return Buffer.concat([tag, x, y])
}

/**
 * Convert binary certificate or public key to an OpenSSL-compatible PEM text format.
 * @param  {Buffer} buffer - Cert or PubKey buffer
 * @return {String}             - PEM
 */
let ASN1toPEM = (pkBuffer) => {
    if (!Buffer.isBuffer(pkBuffer))
        throw new Error("ASN1toPEM: pkBuffer must be Buffer.")

    let type;
    if (pkBuffer.length == 65 && pkBuffer[0] == 0x04) {
        /*
            If needed, we encode rawpublic key to ASN structure, adding metadata:
            SEQUENCE {
              SEQUENCE {
                 OBJECTIDENTIFIER 1.2.840.10045.2.1 (ecPublicKey)
                 OBJECTIDENTIFIER 1.2.840.10045.3.1.7 (P-256)
              }
              BITSTRING <raw public key>
            }
            Luckily, to do that, we just need to prefix it with constant 26 bytes (metadata is constant).
        */

        pkBuffer = Buffer.concat([
            new Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex"),
            pkBuffer
        ]);

        type = 'PUBLIC KEY';
    } else {
        type = 'CERTIFICATE';
    }

    let b64cert = pkBuffer.toString('base64');

    let PEMKey = '';
    for (let i = 0; i < Math.ceil(b64cert.length / 64); i++) {
        let start = 64 * i;

        PEMKey += b64cert.substr(start, 64) + '\n';
    }

    PEMKey = `-----BEGIN ${type}-----\n` + PEMKey + `-----END ${type}-----\n`;

    return PEMKey
}

/**
 * Parses authenticatorData buffer.
 * @param  {Buffer} buffer - authenticatorData buffer
 * @return {Object}        - parsed authenticatorData struct
 */
let parseMakeCredAuthData = (buffer) => {
    let rpIdHash = buffer.slice(0, 32);
    buffer = buffer.slice(32);
    let flagsBuf = buffer.slice(0, 1);
    buffer = buffer.slice(1);
    let flags = flagsBuf[0];
    let counterBuf = buffer.slice(0, 4);
    buffer = buffer.slice(4);
    let counter = counterBuf.readUInt32BE(0);
    let aaguid = buffer.slice(0, 16);
    buffer = buffer.slice(16);
    let credIDLenBuf = buffer.slice(0, 2);
    buffer = buffer.slice(2);
    let credIDLen = credIDLenBuf.readUInt16BE(0);
    let credID = buffer.slice(0, credIDLen);
    buffer = buffer.slice(credIDLen);
    let COSEPublicKey = buffer;

    return { rpIdHash, flagsBuf, flags, counter, counterBuf, aaguid, credID, COSEPublicKey }
}

let verifyAuthenticatorAttestationResponse = (webAuthnResponse) => {
    let attestationBuffer = base64url.toBuffer(webAuthnResponse.response.attestationObject);
    let ctapMakeCredResp = cbor.decodeAllSync(attestationBuffer)[0];
    console.log("ctapMakeCredResp.attStmt", ctapMakeCredResp.attStmt)

    let response = { 'verified': false };

    if (ctapMakeCredResp.fmt === 'fido-u2f') {
        console.log("ENTRA DENTRO DE FIDO-u2F", ctapMakeCredResp)
        let authrDataStruct = parseMakeCredAuthData(ctapMakeCredResp.authData);

        if (!(authrDataStruct.flags & U2F_USER_PRESENTED))
            throw new Error('User was NOT presented durring authentication!');

        let clientDataHash = hash(base64url.toBuffer(webAuthnResponse.response.clientDataJSON))
        let reservedByte = Buffer.from([0x00]);
        let publicKey = COSEECDHAtoPKCS(authrDataStruct.COSEPublicKey)
        let signatureBase = Buffer.concat([reservedByte, authrDataStruct.rpIdHash, clientDataHash, authrDataStruct.credID, publicKey]);

        let PEMCertificate = ASN1toPEM(ctapMakeCredResp.attStmt.x5c[0]);
        let signature = ctapMakeCredResp.attStmt.sig;

        response.verified = verifySignature(signature, signatureBase, PEMCertificate)

        if (response.verified) {
            response.authrInfo = {
                fmt: 'fido-u2f',
                publicKey: base64url.encode(publicKey),
                counter: authrDataStruct.counter,
                credID: base64url.encode(authrDataStruct.credID)
            }
        }
    } else if (ctapMakeCredResp.fmt === 'packed' && ctapMakeCredResp.attStmt.hasOwnProperty('x5c')) {
        let authrDataStruct = parseMakeCredAuthData(ctapMakeCredResp.authData);

        if (!(authrDataStruct.flags & U2F_USER_PRESENTED))
            throw new Error('User was NOT presented durring authentication!');

        let clientDataHash = hash(base64url.toBuffer(webAuthnResponse.response.clientDataJSON))
        let publicKey = COSEECDHAtoPKCS(authrDataStruct.COSEPublicKey)
        let signatureBase = Buffer.concat([ctapMakeCredResp.authData, clientDataHash]);

        let PEMCertificate = ASN1toPEM(ctapMakeCredResp.attStmt.x5c[0]);
        let signature = ctapMakeCredResp.attStmt.sig;

        response.verified = verifySignature(signature, signatureBase, PEMCertificate)

        if (response.verified) {
            response.authrInfo = {
                fmt: 'packed',
                publicKey: base64url.encode(publicKey),
                counter: authrDataStruct.counter,
                credID: base64url.encode(authrDataStruct.credID)
            }
        }
    } else if (ctapMakeCredResp.fmt === 'android-safetynet') {
        return verifySafetyNetAttestation(ctapMakeCredResp, webAuthnResponse)
    } else {
        console.log("ctapMakeCredResp", ctapMakeCredResp)
        console.log("ctapMakeCredResp.fmt", ctapMakeCredResp.fmt)
        throw new Error('Unsupported attestation format! ' + ctapMakeCredResp.fmt);
    }

    return response
}


/**
 * Takes an array of registered authenticators and find one specified by credID
 * @param  {String} credID        - base64url encoded credential
 * @param  {Array} authenticators - list of authenticators
 * @return {Object}               - found authenticator
 */
let findAuthr = (credID, authenticators) => {
    for (let authr of authenticators) {
        if (authr.credID === credID)
            return authr
    }

    throw new Error(`Unknown authenticator with credID ${credID}!`)
}

/**
 * Parses AuthenticatorData from GetAssertion response
 * @param  {Buffer} buffer - Auth data buffer
 * @return {Object}        - parsed authenticatorData struct
 */
let parseGetAssertAuthData = (buffer) => {
    let rpIdHash = buffer.slice(0, 32);
    buffer = buffer.slice(32);
    let flagsBuf = buffer.slice(0, 1);
    buffer = buffer.slice(1);
    let flags = flagsBuf[0];
    let counterBuf = buffer.slice(0, 4);
    buffer = buffer.slice(4);
    let counter = counterBuf.readUInt32BE(0);

    return { rpIdHash, flagsBuf, flags, counter, counterBuf }
}

let verifyAuthenticatorAssertionResponse = (webAuthnResponse, authenticators) => {
    let authr = findAuthr(webAuthnResponse.id, authenticators);
    let authenticatorData = base64url.toBuffer(webAuthnResponse.response.authenticatorData);

    let response = { 'verified': false };
    if (authr.fmt === 'fido-u2f' || authr.fmt === 'packed' || authr.fmt === 'android-safetynet') {
        let authrDataStruct = parseGetAssertAuthData(authenticatorData);

        if (!(authrDataStruct.flags & U2F_USER_PRESENTED))
            throw new Error('User was NOT presented durring authentication!');

        let clientDataHash = hash(base64url.toBuffer(webAuthnResponse.response.clientDataJSON))
        let signatureBase = Buffer.concat([authrDataStruct.rpIdHash, authrDataStruct.flagsBuf, authrDataStruct.counterBuf, clientDataHash]);

        let publicKey = ASN1toPEM(base64url.toBuffer(authr.publicKey));
        let signature = base64url.toBuffer(webAuthnResponse.response.signature);

        response.verified = verifySignature(signature, signatureBase, publicKey)

        if (response.verified) {
            if (response.counter <= authr.counter)
                throw new Error('Authr counter did not increase!');

            authr.counter = authrDataStruct.counter
        }
    }

    return response
}


let gsr2 = 'MIIDujCCAqKgAwIBAgILBAAAAAABD4Ym5g0wDQYJKoZIhvcNAQEFBQAwTDEgMB4GA1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjIxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDYxMjE1MDgwMDAwWhcNMjExMjE1MDgwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKbPJA6+Lm8omUVCxKs+IVSbC9N/hHD6ErPLv4dfxn+G07IwXNb9rfF73OX4YJYJkhD10FPe+3t+c4isUoh7SqbKSaZeqKeMWhG8eoLrvozps6yWJQeXSpkqBy+0Hne/ig+1AnwblrjFuTosvNYSuetZfeLQBoZfXklqtTleiDTsvHgMCJiEbKjNS7SgfQx5TfC4LcshytVsW33hoCmEofnTlEnLJGKRILzdC9XZzPnqJworc5HGnRusyMvo4KD0L5CLTfuwNhv2GXqF4G3yYROIXJ/gkwpRl4pazq+r1feqCapgvdzZX99yqWATXgAByUr6P6TqBwMhAo6CygPCm48CAwEAAaOBnDCBmTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUm+IHV2ccHsBqBt5ZtJot39wZhi4wNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5nbG9iYWxzaWduLm5ldC9yb290LXIyLmNybDAfBgNVHSMEGDAWgBSb4gdXZxwewGoG3lm0mi3f3BmGLjANBgkqhkiG9w0BAQUFAAOCAQEAmYFThxxol4aR7OBKuEQLq4GsJ0/WwbgcQ3izDJr86iw8bmEbTUsp9Z8FHSbBuOmDAGJFtqkIk7mpM0sYmsL4h4hO291xNBrBVNpGP+DTKqttVCL1OmLNIG+6KYnX3ZHu01yiPqFbQfXf5WRDLenVOavSot+3i9DAgBkcRcAtjOj4LaR0VknFBbVPFd5uRHg5h6h+u/N5GJG79G+dwfCMNYxdAfvDbbnvRG15RjF+Cv6pgsH/76tuIMRQyV+dTZsXjAzlAcmgQWpzU/qlULRuJQ/7TBj0/VLZjmmx6BEP3ojY+x1J96relc8geMJgEtslQIxq/H5COEBkEveegeGTLg==';

var getCertificateSubject = (certificate) => {
    let subjectCert = new jsrsasign.X509();
    subjectCert.readCertPEM(certificate);

    let subjectString = subjectCert.getSubjectString();
    let subjectFields = subjectString.slice(1).split('/');

    let fields = {};
    for (let field of subjectFields) {
        let kv = field.split('=');
        fields[kv[0]] = kv[1];
    }

    return fields
}

var validateCertificatePath = (certificates) => {
    if ((new Set(certificates)).size !== certificates.length)
        throw new Error('Failed to validate certificates path! Dublicate certificates detected!');

    for (let i = 0; i < certificates.length; i++) {
        let subjectPem = certificates[i];
        let subjectCert = new jsrsasign.X509();
        subjectCert.readCertPEM(subjectPem);

        let issuerPem = '';
        if (i + 1 >= certificates.length)
            issuerPem = subjectPem;
        else
            issuerPem = certificates[i + 1];

        let issuerCert = new jsrsasign.X509();
        issuerCert.readCertPEM(issuerPem);

        if (subjectCert.getIssuerString() !== issuerCert.getSubjectString())
            throw new Error('Failed to validate certificate path! Issuers dont match!');

        let subjectCertStruct = jsrsasign.ASN1HEX.getTLVbyList(subjectCert.hex, 0, [0]);
        let algorithm = subjectCert.getSignatureAlgorithmField();
        let signatureHex = subjectCert.getSignatureValueHex()

        let Signature = new jsrsasign.crypto.Signature({ alg: algorithm });
        Signature.init(issuerPem);
        Signature.updateHex(subjectCertStruct);

        if (!Signature.verify(signatureHex))
            throw new Error('Failed to validate certificate path!')
    }

    return true
}

let verifySafetyNetAttestation = (ctapMakeCredResp, webAuthnResponse) => {
    let attestationStruct = ctapMakeCredResp;
    let authrDataStruct = parseMakeCredAuthData(ctapMakeCredResp.authData);
    let response = { 'verified': false };

    let jwsString = attestationStruct.attStmt.response.toString('utf8');
    let jwsParts = jwsString.split('.');

    let HEADER = JSON.parse(base64url.decode(jwsParts[0]));
    let PAYLOAD = JSON.parse(base64url.decode(jwsParts[1]));
    let SIGNATURE = jwsParts[2];

    /* ----- Verify payload ----- */
    let clientDataHashBuf = hash(base64url.toBuffer(webAuthnResponse.response.clientDataJSON));
    let nonceBase = Buffer.concat([attestationStruct.authData, clientDataHashBuf]);
    let nonceBuffer = hash(nonceBase);
    let expectedNonce = nonceBuffer.toString('base64');

    if (PAYLOAD.nonce !== expectedNonce)
        throw new Error(`PAYLOAD.nonce does not contains expected nonce! Expected ${PAYLOAD.nonce} to equal ${expectedNonce}!`);

    if (!PAYLOAD.ctsProfileMatch)
        throw new Error('PAYLOAD.ctsProfileMatch is FALSE!');
    /* ----- Verify payload ENDS ----- */


    /* ----- Verify header ----- */
    let certPath = HEADER.x5c.concat([gsr2]).map((cert) => {
        let pemcert = '';
        for (let i = 0; i < cert.length; i += 64)
            pemcert += cert.slice(i, i + 64) + '\n';

        return '-----BEGIN CERTIFICATE-----\n' + pemcert + '-----END CERTIFICATE-----';
    })

    if (getCertificateSubject(certPath[0]).CN !== 'attest.android.com')
        throw new Error('The common name is not set to "attest.android.com"!');

    validateCertificatePath(certPath);
    /* ----- Verify header ENDS ----- */

    /* ----- Verify signature ----- */
    let signatureBaseBuffer = Buffer.from(jwsParts[0] + '.' + jwsParts[1]);
    let certificate = certPath[0];
    let signatureBuffer = base64url.toBuffer(SIGNATURE);

    let publicKey = COSEECDHAtoPKCS(authrDataStruct.COSEPublicKey);
    console.log("------------------------------PBK-------------------------------------------------------", publicKey);
    response.verified = crypto.createVerify('sha256')
        .update(signatureBaseBuffer)
        .verify(certificate, signatureBuffer);

    if (!response.verified)
        throw new Error('Failed to verify the signature!');


    response.authrInfo = {
        fmt: 'android-safetynet',
        publicKey: base64url.encode(publicKey),
        counter: authrDataStruct.counter,
        credID: base64url.encode(authrDataStruct.credID)
    }

    /* ----- Verify signature ENDS ----- */

    return response;
}

module.exports = {
    randomBase64URLBuffer,
    generateServerMakeCredRequest,
    generateServerGetAssertion,
    verifyAuthenticatorAttestationResponse,
    verifyAuthenticatorAssertionResponse
}