const graphene = require("graphene-pk11");
const Module = graphene.Module;

module.exports = function (RED) {
    function ListKeysNode(config) {
        RED.nodes.createNode(this, config);
        const node = this;

        node.on('input', function (msg, send, done) {
            const pkcs11ConfigNode = RED.nodes.getNode(config.pkcs11Config);
            const libraryPath = pkcs11ConfigNode.libraryPath;
            const slotNumber = pkcs11ConfigNode.slot;
            const searchCriteria = config.searchCriteria || {}; // User-configured search criteria

            try {
                const mod = Module.load(libraryPath, "SoftHSM");
                mod.initialize();


                const slots = mod.getSlots(true);
                const slot = slots.items(parseInt(slotNumber));
                if (slot.flags & graphene.SlotFlag.TOKEN_PRESENT) {
                    var session = slot.open(graphene.SessionFlag.SERIAL_SESSION | graphene.SessionFlag.RW_SESSION);
                    session.login(pkcs11ConfigNode.password);


                    // Specify the label you want to search for
                    const labelToSearch = "YourRSAKeyLabel";

// Define the search criteria
                    const searchCriteria = {
                        class: graphene.ObjectClass.PUBLIC_KEY // Search for a public key
                        //label: labelToSearch, // Search for a key with the specified label
                    };

// Use the session to search for the key
                    const keys = session.find(searchCriteria);

                    msg.keys = keys;

                    // if (keys.length > 0) {
                    //     // Key(s) with the specified label found
                    //     for (const key of keys.items) {
                    //         // Process each key as needed
                    //         console.error("Found key with label:", key.label.toString());
                    //     }
                    // } else {
                    //     // Key with the specified label not found
                    //     console.error("No key with label", labelToSearch, "found.");
                    // }


                    // const test = keys.items(1).label;
                    //
                    // console.error(test);
                    //
                    // //console.error(keys);
                    //
                    // const item_1 = session.getObject(keys.innerItems[1]);
                    // const modulus = item_1.modulus.toString("base64");
                    // const publicExponent = item_1.publicExponent.toString("base64");
                    //
                    // console.error(item_1);
                    // console.error(modulus);
                    // console.error(publicExponent);
                    //
                    // // Prepare an array to store key information
                    // const keyList = [];
                    //
                    // if (keys.length > 0) {
                    //     for (const key of keys.items) {
                    //         // Add key information to the list
                    //         keyList.push({
                    //             label: key.label,
                    //             id: key.id,
                    //             class: key.class,
                    //             type: key.type,
                    //             // Add other key attributes as needed
                    //         });
                    //     }
                    // }
                    //
                    // // Store the list of keys in the output message
                    // msg.keys = keyList;

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
