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
            node.status({});

            var mod;
            var slot;
            var session;
            var slots;
            var certificate;
            var certificateLabel;
            var certificate_pem;
            var certificate_forge;
            var derCertificate;
            var subjectAttributes;
            var serializedSubject;
            var subjectBuffer;
            var certificateBuffer;
            var template;
            var objCert;

            var pkcs11ConfigNode = RED.nodes.getNode(config.pkcs11Config);
            var libraryPath = pkcs11ConfigNode.libraryPath;
            var slotNumber = pkcs11ConfigNode.slot;
            var slotPin = pkcs11ConfigNode.password;

            certificate = resolveValue(msg, this.fieldTypeCertificate, globalContext, flowContext, this.certificate);
            certificateLabel = resolveValue(msg, this.fieldTypecertificateLabel, globalContext, flowContext, this.certificateLabel);


            try {
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

                derCertificate = forge.util.decode64(certificate);
                certificate_pem = forge.pki.certificateToPem(forge.pki.certificateFromAsn1(forge.asn1.fromDer(derCertificate)));
                certificate_forge = forge.pki.certificateFromPem(certificate_pem);

                // Extract and format the subject attributes
                subjectAttributes = certificate_forge.subject.attributes;
                serializedSubject = JSON.stringify(subjectAttributes);
                subjectBuffer = Buffer.from(serializedSubject, 'utf8');

                certificateBuffer = Buffer.from(derCertificate, 'binary');

                template = {
                    class: graphene.ObjectClass.CERTIFICATE,
                    certType: graphene.CertificateType.X_509,
                    private: false,
                    token: true,
                    label: certificateLabel,
                    subject: subjectBuffer,
                    value: certificateBuffer,
                };

                objCert = session.create(template).toType();

            } catch (error) {
                node.error('Store certificate failed:', error);
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

    RED.nodes.registerType("p11-store-cert", StoreNode);
};
