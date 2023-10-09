const graphene = require("graphene-pk11");
const pkcs11 = require("pkcs11js");
const Module = graphene.Module;

module.exports = function (RED) {
    function ListKeysNode(config) {
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

                    // Define the search criteria to retrieve all public keys
                    const searchCriteria = {
                        or: [
                            { class: graphene.ObjectClass.PUBLIC_KEY },
                            { class: graphene.ObjectClass.PRIVATE_KEY }
                        ]
                    };

                    graphene.ObjectClass.CERTIFICATE

                    // Use the session to search for public keys
                    const keys = session.find(searchCriteria);

                    // Convert keys to an array for mapping
                    const keyArray = Array.from(keys);

                    // Prepare an array to store key information
                    const keyList = keyArray.map((key) => {
                        var CKA_LABEL = key.get(pkcs11.CKA_LABEL).toString();
                        var CKA_ID = key.get(pkcs11.CKA_ID).toString();
                        var CKA_CLASS = key.get(pkcs11.CKA_CLASS).toString();
                        var CKA_KEY_TYPE = key.get(pkcs11.CKA_KEY_TYPE).toString();
                        //var CKA_WRAP = key.get(pkcs11.CKA_WRAP);
                        //var CKA_UNWRAP = key.get(pkcs11.CKA_UNWRAP);
                        //var CKA_DERIVE = key.get(pkcs11.CKA_DERIVE);
                        //var CKA_SIGN = key.get(pkcs11.CKA_SIGN);
                        //var CKA_VERIFY = key.get(pkcs11.CKA_VERIFY);
                        //var CKA_ENCRYPT = key.get(pkcs11.CKA_ENCRYPT);
                        //var CKA_DECRYPT = key.get(pkcs11.CKA_DECRYPT);

                        return {
                            "CKA_LABEL": CKA_LABEL,
                            "CKA_ID": CKA_ID,
                            "CKA_CLASS": CKA_CLASS,
                            "CKA_KEY_TYPE": CKA_KEY_TYPE
                            //"CKA_WRAP": CKA_WRAP,
                            //"CKA_UNWRAP": CKA_UNWRAP
                            // "CKA_DERIVE": CKA_DERIVE,
                            // "CKA_SIGN": CKA_SIGN,
                            // "CKA_VERIFY": CKA_VERIFY,
                            // "CKA_ENCRYPT": CKA_ENCRYPT,
                            // "CKA_DECRYPT": CKA_DECRYPT
                        };
                    });

                    msg.keyList = keyList;

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
                node.status({fill: 'red', shape: 'ring', text: 'Error'});
                done(error);
            }
        });
    }

    RED.nodes.registerType("list-keys", ListKeysNode);
};
