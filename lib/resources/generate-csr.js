const forge = require("node-forge");
const crypto = require('crypto');

// Function to generate a CSR using node-forge
function generateCSR(session, privateKey, publicKey, subjects, subject_alternative_names) {

    let csr = forge.pki.createCertificationRequest();

    // Getting public key in required format
    let pubKey = publicKey.getAttribute({
        modulus: null,
        publicExponent: null
    });
    let publicKeyCrypto = crypto.createPublicKey({
        key: {
            "kty": "RSA",
            "n": forge.util.binary.base64.encode(pubKey.modulus),
            "e": forge.util.binary.base64.encode(pubKey.publicExponent)
        }, format: 'jwk'
    });
    let imported_pub_pem = publicKeyCrypto.export({type: 'spki', format: 'pem'});
    csr.publicKey = forge.pki.publicKeyFromPem(imported_pub_pem);


    // Setting subject
    csr.setSubject(subjects);

    // Add extensions (e.g., subject alternative names)
    let extensions = [
        {
            name: "subjectAltName",
            altNames: subject_alternative_names
        }
    ];

    csr.addAttribute({
        name: 'extensionRequest',
        extensions: extensions
    });

    csr.md = forge.md.sha256.create();
    let algorithmOid = forge.oids[csr.md.algorithm + 'WithRSAEncryption'];
    csr.signatureOid = csr.siginfo.algorithmOid = algorithmOid;

    csr.certificationRequestInfo = forge.pki.getCertificationRequestInfo(csr);
    let bytes = forge.asn1.toDer(csr.certificationRequestInfo);
    let requestInfoBytes = bytes.getBytes();
    csr.md.update(requestInfoBytes);

    let sign = session.createSign("SHA256_RSA_PKCS", privateKey);
    sign.update(forge.util.binary.raw.decode(requestInfoBytes));
    let signature = sign.final();

    csr.signature = forge.util.binary.raw.encode(signature);

    return csr;

}

module.exports = generateCSR;