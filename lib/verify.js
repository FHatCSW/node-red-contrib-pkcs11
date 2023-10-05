const graphene = require("graphene-pk11");
const Module = graphene.Module;

module.exports = function (RED) {
    function VerifyNode(config) {
        RED.nodes.createNode(this, config);
        const node = this;

        node.on('input', function (msg, send, done) {
            var pkcs11ConfigNode = RED.nodes.getNode(config.pkcs11Config);
            var libraryPath = pkcs11ConfigNode.libraryPath;
            var slotNumber = pkcs11ConfigNode.slot;
            var slotPin = pkcs11ConfigNode.password;
            const keyLabel = config.keyLabel;
            const dataToVerify = msg.payload; // Input data to verify
            const signature = msg.signature; // Signature to verify

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

                        // Find the public key with the specified label
                        const publicKey = session.find({ label: keyLabel, class: graphene.ObjectClass.PUBLIC_KEY });
                        if (publicKey.length > 0) {
                            const verifier = session.createVerify(graphene.Mechanism.RSA_PKCS, publicKey.items(0));
                            verifier.update(dataToVerify);

                            // Verify the signature
                            const verificationResult = verifier.final(signature);

                            // Store the verification result in the output message
                            msg.verificationResult = verificationResult;

                            session.logout();
                            session.close();
                        } else {
                            console.error("Public key not found.");
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
                console.error('Verification failed:', error);
                node.status({ fill: 'red', shape: 'ring', text: 'Error' });
                done(error);
            }
        });
    }

    RED.nodes.registerType("p11-verify", VerifyNode);
};
