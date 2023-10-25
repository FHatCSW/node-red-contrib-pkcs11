const graphene = require("graphene-pk11");
const Module = graphene.Module;
const forge = require("node-forge");
const resolveValue = require('./resources/resolve-value.js');
const isValidSubject = require('./resources/validate-subject.js');
const isValidSubjectAlternativeName = require('./resources/validate-subject-altname.js');
const generateCSR = require('./resources/generate-csr.js');


module.exports = function (RED) {

    function CreateCSRNode(config) {
        RED.nodes.createNode(this, config);
        var globalContext = this.context().global;
        var flowContext = this.context().flow;
        const node = this;

        this.subjects = config.subjects;
        this.fieldTypesubjects = config.subjects_fieldType;
        this.subjectAltnames = config.subjectAltnames;
        this.fieldTypesubjectAltnames = config.subjectAltnames_fieldType;
        this.privateKeyLabel = config.privateKeyLabel;
        this.fieldTypePrivateKeyLabel = config.privateKeyLabel_fieldType;
        this.publicKeyLabel = config.publicKeyLabel;
        this.fieldTypePublicKeyLabel = config.publicKeyLabel_fieldType;

        node.on('input', function (msg, send, done) {
            node.status({});

            var mod;
            var slot;
            var session;
            var slots;
            var subject_alternative_names;
            var subjects;
            var privateKeyLabel;
            var publicKeyLabel;
            var allSubjectsValid;
            var allSANsValid;
            var csr;
            var privateKey;
            var publicKey;
            var csrPem;


            var pkcs11ConfigNode = RED.nodes.getNode(config.pkcs11Config);
            var libraryPath = pkcs11ConfigNode.libraryPath;
            var slotNumber = pkcs11ConfigNode.slot;
            var slotPin = pkcs11ConfigNode.password;

            privateKeyLabel = resolveValue(msg, this.fieldTypePrivateKeyLabel, globalContext, flowContext, this.privateKeyLabel);
            publicKeyLabel = resolveValue(msg, this.fieldTypePublicKeyLabel, globalContext, flowContext, this.publicKeyLabel);
            subjects = resolveValue(msg, this.fieldTypesubjects, globalContext, flowContext, this.subjects);
            subject_alternative_names = resolveValue(msg, this.fieldTypesubjectAltnames, globalContext, flowContext, this.subjectAltnames);


            try {

                if (!subjects) {
                    throw new Error("Subject is missing.");
                }

                allSubjectsValid = subjects.every(isValidSubject);
                allSANsValid = subject_alternative_names.every(isValidSubjectAlternativeName);

                if (!allSubjectsValid) {
                    throw new Error('Subjects do not have the right format: e.g. {"key": "CN", "value": "example"}');
                }
                if (!allSANsValid) {
                    throw new Error('Subject Alternative Names do not have the right format: e.g. {"type": 2, "value": "www.example.de"} or {"type": 7, "ip": "192.168.1.1"}');
                }

                mod = Module.load(libraryPath, "SoftHSM");
                mod.initialize();

                slots = mod.getSlots(true);
                if (slots.length === 0) {
                    throw new Error("No available slots.");
                }
                slot = slots.items(parseInt(slotNumber));

                if (!slot.flags & !graphene.SlotFlag.TOKEN_PRESENT) {
                    throw new Error("Slot is not initialized.");
                }

                session = slot.open(graphene.SessionFlag.SERIAL_SESSION | graphene.SessionFlag.RW_SESSION);
                session.login(slotPin);

                // Find the private key with the specified label
                privateKey = session.find({
                    label: privateKeyLabel,
                    class: graphene.ObjectClass.PRIVATE_KEY
                }).items(0);
                publicKey = session.find({
                    label: publicKeyLabel,
                    class: graphene.ObjectClass.PUBLIC_KEY
                }).items(0);

                if (privateKey === null) {
                    throw new Error("Private key not found.");
                }

                // Generate a CSR using node-forge
                csr = generateCSR(session, privateKey, publicKey, subjects, subject_alternative_names);

                if (!csr.verify()) {
                    throw new Error("Invalid CSR signature");
                }

                csrPem = forge.pki.certificationRequestToPem(csr);

                if (!msg.ejbca) {
                    msg.ejbca = {};
                }
                msg.ejbca.csr = csrPem;

            } catch (error) {
                node.error('CSR generation failed:', error);
                console.error(error);
                node.status({fill: 'red', shape: 'ring', text: "Error"});
                done(error);
            } finally {
                session.logout();
                session.close();
                mod.finalize();
                send(msg);
                done();
            }
        });
    }

    RED.nodes.registerType("p11-create-csr", CreateCSRNode);
};
