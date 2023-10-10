const graphene = require("graphene-pk11");
const Module = graphene.Module;
const forge = require("node-forge");
const pkcs11 = require("pkcs11js");


function assemblepublicKey(publicKey) {

    const publicKeyAttributes = publicKey.items(0).getAttribute({
        modulus: null, // Use appropriate attribute names and types
        publicExponent: null,
    });

    const BigInteger = forge.jsbn.BigInteger; // Import BigInteger from node-forge

    // Assuming publicKeyAttributes.modulus and publicKeyAttributes.publicExponent are Buffers
    const modulus = new BigInteger(publicKeyAttributes.modulus.toString("hex"), 16);
    const publicExponent = new BigInteger(publicKeyAttributes.publicExponent.toString("hex"), 16);


    const rsaPublicKey = forge.pki.rsa.setPublicKey(modulus, publicExponent);

    console.log(rsaPublicKey);

    return rsaPublicKey;
}

function checkSignature(session, privateKey, publicKey, dataToSign, signAlgo) {
    const rsaPublicKey = assemblepublicKey(publicKey);

    const signature = session.createSign(signAlgo, privateKey.items(0));
    signature.update(dataToSign);
    const signatureValue = signature.final();


    const md = forge.md.sha256.create();
    md.update(dataToSign, 'utf8');
    const verified = rsaPublicKey.verify(md.digest().getBytes(), signatureValue);

    console.log("Signature result: ", verified);

}

function generateCSR(session, privateKey, publicKey, subjects, subject_alternative_names) {
    const csr = forge.pki.createCertificationRequest();

    const rsaPublicKey = assemblepublicKey(publicKey);

    //console.log(rsaPublicKey);

    csr.publicKey = rsaPublicKey;

    csr.setSubject(subjects);

    csr.setAttributes([{
  name: 'challengePassword',
  value: 'password'
}, {
  name: 'unstructuredName',
  value: 'My Company, Inc.'
}, {
  name: 'extensionRequest',
  extensions: [{
    name: 'subjectAltName',
    altNames: [{
      // 2 is DNS type
      type: 2,
      value: 'test.domain.com'
    }, {
      type: 2,
      value: 'other.domain.com',
    }, {
      type: 2,
      value: 'www.domain.net'
    }]
  }]
}]);


    csr.md = forge.md.sha256.create();
    var algorithmOid = forge.pki.oids[csr.md.algorithm + 'WithRSAEncryption'];

    if (!algorithmOid) {
        var error = new Error('Could not compute certification request digest. ' +
            'Unknown message digest algorithm OID.');
        error.algorithm = csr.md.algorithm;
        throw error;
    }

    console.log(algorithmOid);

    csr.signatureOid = csr.siginfo.algorithmOid = algorithmOid;

    csr.certificationRequestInfo = forge.pki.getCertificationRequestInfo(csr);

    var bytes = forge.asn1.toDer(csr.certificationRequestInfo);
    csr.md.update(bytes.getBytes());
    const signature = session.createSign("SHA256_RSA_PKCS", privateKey.items(0));
    console.log(bytes.getBytes());

    signature.update(csr.md.digest().bytes());

    var sig = signature.final();
    console.log(sig.toString("binary"));

    csr.signature = sig.toString("binary");

    const verify = csr.verify();
    var verified = rsaPublicKey.verify(csr.md.digest().bytes, sig);

    console.log(verified);

    const csrPem = forge.pki.certificationRequestToPem(csr);

    const asn1Pem = forge.pki.certificationRequestToAsn1(csr);

    //console.log(csr);

    console.log(csrPem);

    console.log(csr.signature);

    //console.log(asn1Pem);
    return csr;
}


const subjects = [{"shortName": "CN", "value": "test"}, {
    "shortName": "O",
    "value": "Campus Schwarzwald"
}, {"shortName": "OU", "value": "Showcase Robot"}, {"shortName": "C", "value": "DE"}]
const subject_alternative_names = []

const mod = Module.load("/usr/local/lib/softhsm/libsofthsm2.so", "SoftHSM");
mod.initialize();

const slots = mod.getSlots(true);
if (slots.length > 0) {
    const slot = slots.items(0);

    if (slot.flags & graphene.SlotFlag.TOKEN_PRESENT) {
        var session = slot.open(graphene.SessionFlag.SERIAL_SESSION | graphene.SessionFlag.RW_SESSION);
        session.login("1234");

        // Find the private key with the specified label
        const privateKey = session.find({
            label: "Private_label",
            class: graphene.ObjectClass.PRIVATE_KEY
        });
        const publicKey = session.find({
            label: "Public_label",
            class: graphene.ObjectClass.PUBLIC_KEY
        });

        if (privateKey.length > 0) {
            const dataToSign = "Test";
            const signAlgo = "SHA256_RSA_PKCS";

            //const checksig = checkSignature(session, privateKey, publicKey, dataToSign, signAlgo);
            //console.log(checksig);
            // Generate a CSR using node-forge
            const csr = generateCSR(session, privateKey, publicKey, subjects, subject_alternative_names);

            console.log(csr);

            session.logout();
            session.close();
        } else {
            console.error("Private key not found.");
        }
    } else {
        console.error("Slot is not initialized.");
    }
} else {
    console.error("No available slots.");
}

