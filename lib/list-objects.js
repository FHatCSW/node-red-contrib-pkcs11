const graphene = require("graphene-pk11");
const pkcs11 = require("pkcs11js");
const Module = graphene.Module;

module.exports = function (RED) {
    function ListObjectsNode(config) {
        RED.nodes.createNode(this, config);
        const node = this;
        node.status({});

        node.on('input', function (msg, send, done) {
            const pkcs11ConfigNode = RED.nodes.getNode(config.pkcs11Config);
            const libraryPath = pkcs11ConfigNode.libraryPath;
            const slotNumber = pkcs11ConfigNode.slot;

            try {
                const mod = Module.load(libraryPath, "SoftHSM");
                mod.initialize();

                const slots = mod.getSlots(true);
                const slot = slots.items(parseInt(slotNumber));

                if (slot.flags & graphene.SlotFlag.TOKEN_PRESENT) {
                    var session = slot.open(graphene.SessionFlag.SERIAL_SESSION | graphene.SessionFlag.RW_SESSION);
                    session.login(pkcs11ConfigNode.password);

                    // Define the ObjectClass values for the search
                    const objectClasses = [
                        graphene.ObjectClass.PUBLIC_KEY,
                        graphene.ObjectClass.PRIVATE_KEY,
                        graphene.ObjectClass.CERTIFICATE
                    ];

                    // Prepare an object to store results for each ObjectClass
                    const keyLists = {};

                          // Perform separate searches for each ObjectClass
                    for (const objectClass of objectClasses) {
                        const searchCriteria = { class: objectClass };
                        const keys = session.find(searchCriteria);
                        const keyArray = Array.from(keys);
                        const objectClassName = Object.keys(graphene.ObjectClass).find(key => graphene.ObjectClass[key] === objectClass);

                        const keyList = keyArray.map((key) => {
                            var CKA_LABEL = key.get(pkcs11.CKA_LABEL).toString();
                            var CKA_ID = key.get(pkcs11.CKA_ID).toString();
                            var CKA_CLASS = key.get(pkcs11.CKA_CLASS).toString();
                            var CKA_KEY_TYPE = key.get(pkcs11.CKA_KEY_TYPE).toString();

                            return {
                                "CKA_LABEL": CKA_LABEL,
                                "CKA_ID": CKA_ID,
                                "CKA_CLASS": CKA_CLASS,
                                "CKA_KEY_TYPE": CKA_KEY_TYPE
                            };
                        });

                        keyLists[objectClassName] = keyList;
                    }

                    msg.keyList = keyLists;

                    session.logout();
                    session.close();
                } else {
                    console.error("Slot is not initialized.");
                }

                mod.finalize();
                send(msg);
                done();
            } catch (error) {
                console.error('Listing keys failed:', error);
                node.status({ fill: 'red', shape: 'ring', text: 'Error' });
                done(error);
            }
        });
    }

    RED.nodes.registerType("list-objects", ListObjectsNode);
};
