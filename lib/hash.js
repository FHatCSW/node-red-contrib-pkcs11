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

            var pkcs11ConfigNode = RED.nodes.getNode(config.pkcs11Config);
            var libraryPath = pkcs11ConfigNode.libraryPath;
            var slotNumber = pkcs11ConfigNode.slot;
            const selectedAlgorithm = config.algorithm;

            const payload = resolveValue(msg, this.fieldTypepayload, globalContext, flowContext, this.payload);


            try {
                var mod = Module.load(libraryPath, "SoftHSM");
                mod.initialize();
                const slots = mod.getSlots(true);
                const slot = slots.items(parseInt(slotNumber));
                if (slot.flags & graphene.SlotFlag.TOKEN_PRESENT) {
                    const session = slot.open();
                    const digest = session.createDigest({ name: selectedAlgorithm, params: null });
                    digest.update(payload);
                    const md = digest.final();

                    msg.digest = md.toString("hex");

                    session.close();
                } else {
                    console.error("Slot is not initialized");
                }

                mod.finalize();
                send(msg);
                done();
            } catch (error) {
                console.error('Hashing failed:', error);
                node.status({ fill: 'red', shape: 'ring', text: 'Error' });
                done(error);
            }
        });
    }

    RED.nodes.registerType("p11-digest", HashNode);
};
