const graphene = require("graphene-pk11");
const Module = graphene.Module;
const resolveValue = require('./resources/resolve-value.js');

module.exports = function (RED) {
    function VerifyNode(config) {
        RED.nodes.createNode(this, config);
        var globalContext = this.context().global;
        var flowContext = this.context().flow;
        const node = this;

        this.payload = config.payload;
        this.fieldTypepayload = config.payload_fieldType;
        this.signature = config.signature;
        this.fieldTypesignature = config.signature_fieldType;
        this.publicKeyLabel = config.publicKeyLabel;
        this.fieldTypePublicKeyLabel = config.publicKeyLabel_fieldType;

        node.on('input', function (msg, send, done) {
            node.status({});

            var mod;
            var slot;
            var session;
            var slots;
            var publicKey;
            var verifier;
            var verificationResult;
            var payload;
            var signature;
            var publicKeyLabel;

            var pkcs11ConfigNode = RED.nodes.getNode(config.pkcs11Config);
            var libraryPath = pkcs11ConfigNode.libraryPath;
            var slotNumber = pkcs11ConfigNode.slot;
            var slotPin = pkcs11ConfigNode.password;
            var signAlgo = config.signAlgo;

            payload = resolveValue(msg, this.fieldTypepayload, globalContext, flowContext, this.payload);
            signature = resolveValue(msg, this.fieldTypesignature, globalContext, flowContext, this.signature);
            publicKeyLabel = resolveValue(msg, this.fieldTypePublicKeyLabel, globalContext, flowContext, this.publicKeyLabel);

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

                // Find the public key with the specified label
                publicKey = session.find({label: publicKeyLabel, class: graphene.ObjectClass.PUBLIC_KEY});
                if (publicKey.length === 0) {
                    throw new Error("Public key not found.");
                }
                verifier = session.createVerify(signAlgo, publicKey.items(0));
                verifier.update(payload);

                // Verify the signature
                verificationResult = verifier.final(signature);

                // Store the verification result in the output message
                msg.verificationResult = verificationResult;

                if (verificationResult) {
                    node.status({fill: 'green', shape: 'ring', text: 'Signature matches'});
                } else {
                    node.status({fill: 'red', shape: 'ring', text: 'Signature does NOT match'});
                }

            } catch (error) {
                node.error('Verify failed:', error);
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

    RED.nodes.registerType("p11-verify", VerifyNode);
};
