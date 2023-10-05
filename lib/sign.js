const graphene = require("graphene-pk11");
const Module = graphene.Module;

module.exports = function (RED) {
    function SignNode(config) {
        RED.nodes.createNode(this, config);
        const node = this;

        node.on('input', function (msg, send, done) {

            var pkcs11ConfigNode = RED.nodes.getNode(config.pkcs11Config);
            var libraryPath = pkcs11ConfigNode.libraryPath;
            var slotNumber = pkcs11ConfigNode.slot;
            var slotPin = pkcs11ConfigNode.password;
            const keyLabel = config.keyLabel;
            const dataToSign = msg.payload; // Input data to sign

            try {
                const mod = Module.load(libraryPath, "SoftHSM");
                mod.initialize();

                const slots = mod.getSlots(true);
                const slot = slots.items(parseInt(slotNumber));
                if (slots.length > 0) {
                    const slot = slots.items(slotNumber);

                    if (slot.flags & graphene.SlotFlag.TOKEN_PRESENT) {
                        const session = slot.open();
                        session.login(slotPin);

                        // Find the private key with the specified label
                        const privateKey = session.find({ label: keyLabel, class: graphene.ObjectClass.PRIVATE_KEY });
                        if (privateKey.length > 0) {
                            const signature = session.createSign(graphene.Mechanism.RSA_PKCS, privateKey.items(0));
                            signature.update(dataToSign);
                            const signatureValue = signature.final();

                            // Store the signature in the output message
                            msg.signature = signatureValue.toString("hex");

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
                console.error('Signing failed:', error);
                node.status({ fill: 'red', shape: 'ring', text: 'Error' });
                done(error);
            }
        });
    }

    RED.nodes.registerType("p11-sign", SignNode);
};
