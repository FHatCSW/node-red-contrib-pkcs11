const graphene = require("graphene-pk11");
const Module = graphene.Module;
const resolveValue = require('./resources/resolve-value.js');
const forge = require("node-forge");


module.exports = function (RED) {
    function StoreNode(config) {
        RED.nodes.createNode(this, config);
        var globalContext = this.context().global;
        var flowContext = this.context().flow;
        const node = this;

        this.fieldTypeCertificate = config.certificate_fieldType;
        this.certificate = config.certificate;
        this.fieldTypecertificateLabel = config.certificateLabel_fieldType;
        this.certificateLabel = config.certificateLabel;


        node.on('input', function (msg, send, done) {

            var pkcs11ConfigNode = RED.nodes.getNode(config.pkcs11Config);
            var libraryPath = pkcs11ConfigNode.libraryPath;
            var slotNumber = pkcs11ConfigNode.slot;
            var slotPin = pkcs11ConfigNode.password;

            const certificate = resolveValue(msg, this.fieldTypeCertificate, globalContext, flowContext, this.certificate);
            const certificateLabel = resolveValue(msg, this.fieldTypecertificateLabel, globalContext, flowContext, this.certificateLabel);

            try {
                const mod = Module.load(libraryPath, "SoftHSM");
                mod.initialize();

                const slots = mod.getSlots(true);
                if (slots.length > 0) {
                    const slot = slots.items(parseInt(slotNumber));

                    if (slot.flags & graphene.SlotFlag.TOKEN_PRESENT) {

                        const session = slot.open(graphene.SessionFlag.SERIAL_SESSION | graphene.SessionFlag.RW_SESSION);
                        session.login(slotPin);

                        const derCertificate = forge.util.decode64(certificate);
                        var certificate_pem = forge.pki.certificateToPem(forge.pki.certificateFromAsn1(forge.asn1.fromDer(derCertificate)));
                        var certificate_forge = forge.pki.certificateFromPem(certificate_pem);

                        // Extract and format the subject attributes
                        const subjectAttributes = certificate_forge.subject.attributes;
                        const serializedSubject = JSON.stringify(subjectAttributes);
                        const subjectBuffer = Buffer.from(serializedSubject, 'utf8');

                        const certificateBuffer = Buffer.from(derCertificate, 'binary');

                        const template = {
                            class: graphene.ObjectClass.CERTIFICATE,
                            certType: graphene.CertificateType.X_509,
                            private: false,
                            token: true,
                            label: certificateLabel,
                            subject: subjectBuffer,
                            value: certificateBuffer,
                        };

                        const objCert = session.create(template).toType();
                        node.status({fill: 'green', shape: 'dot', text: 'Success: ' + objCert.label + ' stored'});

                        session.logout();
                        session.close();
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
                console.error('Signing failed:', error);
                node.status({fill: 'red', shape: 'ring', text: "Error"});
            }
        });
    }

    RED.nodes.registerType("p11-store-cert", StoreNode);
};
