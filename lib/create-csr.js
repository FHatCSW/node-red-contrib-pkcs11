const graphene = require("graphene-pk11");
const Module = graphene.Module;
const forge = require("node-forge");
const pkcs11 = require("pkcs11js");

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
                        const privateKey = session.find({label: keyLabel, class: graphene.ObjectClass.PRIVATE_KEY});
                        const publicKey = session.find({label: pubkeyLabel, class: graphene.ObjectClass.PUBLIC_KEY});

                        if (privateKey.length > 0) {
                            // Generate a CSR using node-forge
                            const csr = generateCSR(session, privateKey, publicKey, subjects, subject_alternative_names);

                            // Store the CSR in the output message
                            msg.csr = csr;

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
    const csr = forge.pki.createCertificationRequest();

    console.error(publicKey.CKA_MODULUS);

    //var CKA_MODULUS = privateKey.getAttribute({ type: pkcs11.CKA_MODULUS });
    var CKA_PUBLIC_EXPONENT = privateKey.get(pkcs11.CKA_PUBLIC_EXPONENT);

    console.error(CKA_MODULUS);
    console.error(CKA_PUBLIC_EXPONENT);
    csr.publicKey = publicKey;

    csr.setSubject(subjects);

    // Add extensions (e.g., subject alternative names)
    const extensions = [
        {
            name: "subjectAltName",
            altNames: subject_alternative_names
        }
    ];

    csr.addAttribute({
        name: 'extensionRequest',
        extensions: extensions
    });
    console.error(privateKey);
    console.error(csr);


    csr.md = forge.md.sha256.create();
    var algorithmOid = "sha256WithRSAEncryption";

    console.error("1");

    csr.signatureOid = csr.siginfo.algorithmOid = algorithmOid;
    console.error("1");

    // get CertificationRequestInfo, convert to DER
    csr.certificationRequestInfo = forge.pki.getCertificationRequestInfo(csr);
        console.error("1");

    var bytes = forge.pki.toDer(csr.certificationRequestInfo);
        console.error("1");


    // digest and sign
    csr.md.update(bytes.getBytes());
        console.error("1");

    const signature = session.createSign("SHA256_RSA_PKCS", privateKey.items(0));
        console.error("1");

    signature.update(csr.md);
    csr.signature = signature.final();

    return csr;
}
