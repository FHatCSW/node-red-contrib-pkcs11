const graphene = require("graphene-pk11");
const Module = graphene.Module;
const resolveValue = require('./resources/resolve-value.js');

module.exports = function (RED) {
    function HashNode(config) {
        RED.nodes.createNode(this, config);
        var globalContext = this.context().global;
        var flowContext = this.context().flow;
        const node = this;

        this.payload = config.payload;
        this.fieldTypepayload = config.payload_fieldType;

        node.on('input', function (msg, send, done) {
            node.status({});

            var mod;
            var slot;
            var session;
            var slots;
            var digest;
            var md;
            var payload;

            var pkcs11ConfigNode = RED.nodes.getNode(config.pkcs11Config);
            var libraryPath = pkcs11ConfigNode.libraryPath;
            var slotNumber = pkcs11ConfigNode.slot;
            var selectedAlgorithm = config.algorithm;

            payload = resolveValue(msg, this.fieldTypepayload, globalContext, flowContext, this.payload);

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

                session = slot.open();

                digest = session.createDigest({ name: selectedAlgorithm, params: null });
                    digest.update(payload);
                    md = digest.final();

                    msg.digest = md.toString("hex");

            } catch (error) {
                node.error('Hashing failed:', error);
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

    RED.nodes.registerType("p11-digest", HashNode);
};
