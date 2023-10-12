const graphene = require("graphene-pk11");
const Module = graphene.Module;
const forge = require("node-forge");
const pkcs11 = require("pkcs11js");
const crypto = require('crypto');


module.exports = function (RED) {

    function isValidSubject(subject) {
        // Check if the subject is an object
        if (typeof subject !== 'object' || subject === null) {
            return false;
        }

        // Check if 'shortName' and 'value' keys are present
        if (!subject.hasOwnProperty('shortName') || !subject.hasOwnProperty('value')) {
            return false;
        }

        // Check if 'shortName' and 'value' are non-empty strings
        if (typeof subject.shortName !== 'string' || typeof subject.value !== 'string') {
            return false;
        }

        // You can add more validation rules here if needed

        return true;
    }

    function isValidSubjectAlternativeName(san) {
        // Check if the SAN is an object
        if (typeof san !== 'object' || san === null) {
            return false;
        }

        // Check if 'type' key is present and has a valid value
        if (!san.hasOwnProperty('type') || typeof san.type !== 'number') {
            return false;
        }

        // Check if 'value' or 'ip' key is present based on 'type' value
        if (
            (san.type === 2 || san.type === 6) &&
            (!san.hasOwnProperty('value') || typeof san.value !== 'string')
        ) {
            return false;
        }

        if (san.type === 7 && (!san.hasOwnProperty('ip') || typeof san.ip !== 'string')) {
            return false;
        }

        // You can add more validation rules here if needed

        return true;
    }

    function CreateCSRNode(config) {
        RED.nodes.createNode(this, config);
        const node = this;

        node.on('input', function (msg, send, done) {
            const subjects = msg.ejbca.subjects;
            const subject_alternative_names = msg.ejbca.subject_alternative_names;
            var pkcs11ConfigNode = RED.nodes.getNode(config.pkcs11Config);
            var libraryPath = pkcs11ConfigNode.libraryPath;
            var slotNumber = pkcs11ConfigNode.slot;
            var slotPin = pkcs11ConfigNode.password;
            const keyLabel = config.keyLabel;
            const pubkeyLabel = config.pubkeyLabel;
            const dataToVerify = msg.payload; // Input data to verify
            const signature = msg.signature.buffer; // Signature to verify

            if (!subjects) {
                node.error("Subject is missing.");
                return;
            }

            const allSubjectsValid = subjects.every(isValidSubject);
            const allSANsValid = subject_alternative_names.every(isValidSubjectAlternativeName);

            if (!allSubjectsValid) {
                node.error(`Subjects do not have the right format: e.g. {"key": "CN", "value": "example"}`);
                done();
                return;
            }
            if (!allSANsValid) {
                node.error(`Subject Alternative Names do not have the right format: e.g. {"type": 2, "value": "www.example.de"} or {"type": 7, "ip": "192.168.1.1"}`);
                done();
                return;
            }

            try {
                const mod = Module.load(libraryPath, "SoftHSM");
                mod.initialize();

                const slots = mod.getSlots(true);
                if (slots.length > 0) {
                    const slot = slots.items(slotNumber);

                    if (slot.flags & graphene.SlotFlag.TOKEN_PRESENT) {
                        var session = slot.open(graphene.SessionFlag.SERIAL_SESSION | graphene.SessionFlag.RW_SESSION);
                        session.login(slotPin);

                        // Find the private key with the specified label
                        const privateKey = session.find({label: keyLabel, class: graphene.ObjectClass.PRIVATE_KEY}).items(0);
                        const publicKey = session.find({label: pubkeyLabel, class: graphene.ObjectClass.PUBLIC_KEY}).items(0);

                        if (privateKey.length > 0) {
                            // Generate a CSR using node-forge
                            const csr = generateCSR(session, privateKey, publicKey, subjects, subject_alternative_names);

                            msg.ejbca = {};
                            msg.ejbca.csr = csr;

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

                mod.finalize();
                send(msg);
                done();
            } catch (error) {
                console.error('CSR generation failed:', error);
                node.status({fill: 'red', shape: 'ring', text: 'Error'});
                done(error);
            }
        });
    }

    RED.nodes.registerType("p11-create-csr", CreateCSRNode);
};

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
    let imported_pub_pem = publicKeyCrypto.export({ type: 'spki', format: 'pem' });
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

    let csrPem = forge.pki.certificationRequestToPem(csr);

    return csrPem;

}

