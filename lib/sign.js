const graphene = require("graphene-pk11");
const Module = graphene.Module;
const resolveValue = require('./resources/resolve-value.js');


module.exports = function (RED) {
    function SignNode(config) {
        RED.nodes.createNode(this, config);
        var globalContext = this.context().global;
        var flowContext = this.context().flow;
        const node = this;

        this.payload = config.payload;
        this.fieldTypepayload = config.payload_fieldType;
        this.privateKeyLabel = config.privateKeyLabel;
        this.fieldTypePrivateKeyLabel = config.privateKeyLabel_fieldType;

        node.on('input', function (msg, send, done) {
                node.status({});

                var mod;
                var slot;
                var session;
                var slots;
                var privateKey;
                var signature;
                var signatureValue;
                var signAlgo;
                var payload;
                var privateKeyLabel;

                var pkcs11ConfigNode = RED.nodes.getNode(config.pkcs11Config);
                var libraryPath = pkcs11ConfigNode.libraryPath;
                var slotNumber = pkcs11ConfigNode.slot;
                var slotPin = pkcs11ConfigNode.password;
                signAlgo = config.signAlgo;
                payload = resolveValue(msg, this.fieldTypepayload, globalContext, flowContext, this.payload);
                privateKeyLabel = resolveValue(msg, this.fieldTypePrivateKeyLabel, globalContext, flowContext, this.privateKeyLabel);

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

                    // Find the private key with the specified label
                    privateKey = session.find({
                        label: privateKeyLabel,
                        class: graphene.ObjectClass.PRIVATE_KEY
                    });
                    if (privateKey.length === 0) {
                        throw new Error("Private key not found.");
                    }
                    signature = session.createSign(signAlgo, privateKey.items(0));
                    signature.update(payload);
                    signatureValue = signature.final();

                    // Store the signature in the output message
                    msg.signature = {};
                    msg.signature.hex = signatureValue.toString("hex");
                    msg.signature.buffer = signatureValue;

                } catch (error) {
                    node.error('Signing failed:', error);
                    node.status({fill: 'red', shape: 'ring', text: "Error"});
                    done(error);
                } finally {
                    session.logout();
                    session.close();
                    mod.finalize();
                    send(msg);
                    done();
                }
            }
        );
    }

    RED.nodes.registerType("p11-sign", SignNode);
}
;
