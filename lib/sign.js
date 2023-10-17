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

            var pkcs11ConfigNode = RED.nodes.getNode(config.pkcs11Config);
            var libraryPath = pkcs11ConfigNode.libraryPath;
            var slotNumber = pkcs11ConfigNode.slot;
            var slotPin = pkcs11ConfigNode.password;
            const signAlgo = config.signAlgo;

            const payload = resolveValue(msg, this.fieldTypepayload, globalContext, flowContext, this.payload);
            const privateKeyLabel = resolveValue(msg, this.fieldTypePrivateKeyLabel, globalContext, flowContext, this.privateKeyLabel);


            try {
                const mod = Module.load(libraryPath, "SoftHSM");
                mod.initialize();

                const slots = mod.getSlots(true);
                if (slots.length > 0) {
                    const slot = slots.items(parseInt(slotNumber));

                    if (slot.flags & graphene.SlotFlag.TOKEN_PRESENT) {

                        const session = slot.open(graphene.SessionFlag.SERIAL_SESSION | graphene.SessionFlag.RW_SESSION);
                        session.login(slotPin);

                        // Find the private key with the specified label
                        const privateKey = session.find({label: privateKeyLabel, class: graphene.ObjectClass.PRIVATE_KEY});
                        if (privateKey.length > 0) {
                            const signature = session.createSign(signAlgo, privateKey.items(0));
                            signature.update(payload);
                            const signatureValue = signature.final();

                            // Store the signature in the output message
                            msg.signature = {};
                            msg.signature.hex = signatureValue.toString("hex");
                            msg.signature.buffer = signatureValue;

                        } else {
                            console.error("Private key not found.");
                        }

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

    RED.nodes.registerType("p11-sign", SignNode);
};
