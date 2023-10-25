const graphene = require("graphene-pk11");
const Module = graphene.Module;


module.exports = function (RED) {
    function GetPkcs11InfoNode(config) {
        RED.nodes.createNode(this, config);
        var node = this;

        node.on('input', function (msg, send, done) {
            node.status({});

            var mod;
            var slots;

            var pkcs11ConfigNode = RED.nodes.getNode(config.pkcs11Config);
            var libraryPath = pkcs11ConfigNode.libraryPath;

            try {
                mod = Module.load(libraryPath, "SoftHSM");
                mod.initialize();

                // Initialize msg.hsm object
                msg.hsm = {
                    slots: []
                };

                // Get slots
                slots = mod.getSlots(true);
                if (slots.length > 0) {
                    for (var i = 0; i < slots.length; i++) {
                        var slot = slots.items(i);
                        var slotInfo = {
                            slotNumber: slot.handle,
                            description: slot.slotDescription,
                            serialNumber: slot.getToken().serialNumber,
                            minPinLength: slot.getToken().minPinLen,
                            maxPinLength: slot.getToken().maxPinLen,
                            isHardware: !!(slot.flags & graphene.SlotFlag.HW_SLOT),
                            isRemovable: !!(slot.flags & graphene.SlotFlag.REMOVABLE_DEVICE),
                            isInitialized: !!(slot.flags & graphene.SlotFlag.TOKEN_PRESENT),
                            mechanisms: []
                        };

                        // Get Mechanisms
                        var mechs = slot.getMechanisms();
                        for (var j = 0; j < mechs.length; j++) {
                            var mech = mechs.items(j);
                            var mechInfo = {
                                name: mech.name,
                                digest: !!(mech.flags & graphene.MechanismFlag.DIGEST),
                                sign: !!(mech.flags & graphene.MechanismFlag.SIGN),
                                verify: !!(mech.flags & graphene.MechanismFlag.VERIFY),
                                encrypt: !!(mech.flags & graphene.MechanismFlag.ENCRYPT),
                                decrypt: !!(mech.flags & graphene.MechanismFlag.DECRYPT),
                                wrap: !!(mech.flags & graphene.MechanismFlag.WRAP),
                                unwrap: !!(mech.flags & graphene.MechanismFlag.UNWRAP)
                            };
                            slotInfo.mechanisms.push(mechInfo);
                        }

                        // Add slotInfo to msg.hsm
                        msg.hsm.slots.push(slotInfo);
                    }
                }

            } catch (error) {
                node.error('PKCS11 info failed:', error);
                node.status({fill: 'red', shape: 'ring', text: "Error"});
                done(error);
            } finally {
                mod.finalize();
                send(msg);
                done();
            }


        });
    }

    RED.nodes.registerType("p11-info", GetPkcs11InfoNode);
};
