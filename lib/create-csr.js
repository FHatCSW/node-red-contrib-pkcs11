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
            var pkcs11ConfigNode = RED.nodes.getNode(config.pkcs11Config);
            var libraryPath = pkcs11ConfigNode.libraryPath;
            var slotNumber = pkcs11ConfigNode.slot;
            var slotPin = pkcs11ConfigNode.password;

            const privateKeyLabel = resolveValue(msg, this.fieldTypePrivateKeyLabel, globalContext, flowContext, this.privateKeyLabel);
            const publicKeyLabel = resolveValue(msg, this.fieldTypePublicKeyLabel, globalContext, flowContext, this.publicKeyLabel);
            const subjects = resolveValue(msg, this.fieldTypesubjects, globalContext, flowContext, this.subjects);
            const subject_alternative_names = resolveValue(msg, this.fieldTypesubjectAltnames, globalContext, flowContext, this.subjectAltnames);


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
                        const privateKey = session.find({
                            label: privateKeyLabel,
                            class: graphene.ObjectClass.PRIVATE_KEY
                        }).items(0);
                        const publicKey = session.find({
                            label: publicKeyLabel,
                            class: graphene.ObjectClass.PUBLIC_KEY
                        }).items(0);

                        console.error(privateKey);
                        console.error(privateKey.length);

                        if (privateKey != null) {
                            // Generate a CSR using node-forge
                            const csr = generateCSR(session, privateKey, publicKey, subjects, subject_alternative_names);

                            if (!csr.verify()) {
                                console.error("Invalid CSR signature");
                                return;
                            }

                            let csrPem = forge.pki.certificationRequestToPem(csr);

                            if (!msg.ejbca) {
                                msg.ejbca = {};
                            }
                            msg.ejbca.csr = csrPem;

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
