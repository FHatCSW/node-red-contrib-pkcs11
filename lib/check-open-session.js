const graphene = require("graphene-pk11");

module.exports = function (RED) {
    function CheckOpenSessionNode(config) {
        RED.nodes.createNode(this, config);
        const node = this;

        node.on("input", function (msg, send, done) {
            var pkcs11ConfigNode = RED.nodes.getNode(config.pkcs11Config);
            var libraryPath = pkcs11ConfigNode.libraryPath;


            // Load the PKCS#11 module
            const mod = graphene.Module.load(libraryPath, "SoftHSM");

            // Initialize the module
            mod.initialize();

            try {
                // Get a list of existing sessions
                const sessions = mod.getSessions();

                if (sessions.length > 0) {
                    // There are open sessions
                    const openSessionHandles = sessions.map((session) => session.handle);
                    msg.payload = openSessionHandles;
                    node.send(msg);
                } else {
                    msg.payload = "No open sessions found.";
                    node.send(msg);
                }
            } catch (error) {
                node.error("Error checking open sessions:", error);
                done(error);
            } finally {
                // Always finalize the module when you're done
                mod.finalize();
            }
        });
    }

    RED.nodes.registerType("check-open-session", CheckOpenSessionNode);
};
