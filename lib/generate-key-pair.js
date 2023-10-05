const graphene = require("graphene-pk11");

module.exports = function (RED) {
    function GenerateKeyPairNode(config) {
        RED.nodes.createNode(this, config);
        const node = this;

        node.on('input', function (msg, send, done) {
            var pkcs11ConfigNode = RED.nodes.getNode(config.pkcs11Config);
            var libraryPath = pkcs11ConfigNode.libraryPath;
            var slotNumber = pkcs11ConfigNode.slot;
            var slotPin = pkcs11ConfigNode.password;

            var Module = graphene.Module;
            var mod = Module.load(libraryPath, "SoftHSM");
            mod.initialize();

            try {
                const slots = mod.getSlots(true);
                const slot = slots.items(parseInt(slotNumber));
                var session = slot.open(graphene.SessionFlag.SERIAL_SESSION | graphene.SessionFlag.RW_SESSION);

                session.login(slotPin);

                var publicKeyHandle;
                var privateKeyHandle;

                switch (config.keyType) {
                    case 'RSA':
                        // Generate RSA key pair
                        var rsaKeys = session.generateKeyPair(graphene.KeyGenMechanism.RSA, {
                            label: config.publicKeyLabel,
                            keyType: graphene.KeyType.RSA,
                            modulusBits: parseInt(config.bitLength),
                            publicExponent: Buffer.from([3]),
                            token: true,
                            verify: true,
                            encrypt: true,
                            wrap: true,
                        }, {
                            label: config.privateKeyLabel, // Label for the private key
                            keyType: graphene.KeyType.RSA,
                            token: true,
                            sign: true,
                            decrypt: true,
                            unwrap: true,
                        });
                        publicKeyHandle = rsaKeys.publicKey.handle;
                        privateKeyHandle = rsaKeys.privateKey.handle;
                        break;
                    case 'ECC':
                        // Generate ECC key pair
                        var eccKeys = session.generateKeyPair(graphene.KeyGenMechanism.EC, {
                            label: config.publicKeyLabel,
                            keyType: graphene.KeyType.EC,
                            paramsEC: graphene.NamedCurve.getByName(config.curveType).value,
                            token: true,
                            verify: true,
                            encrypt: true,
                            wrap: true,
                            derive: false,
                        }, {
                            label: config.privateKeyLabel, // Label for the private key
                            keyType: graphene.KeyType.EC,
                            token: true,
                            sign: true,
                            decrypt: true,
                            unwrap: true,
                            derive: false,
                        });


                        publicKeyHandle = eccKeys.publicKey.handle;
                        privateKeyHandle = eccKeys.privateKey.handle;
                        break;
                    case 'AES':
                        // Generate AES key
                        var aesKey = session.generateKey(graphene.KeyGenMechanism.AES, {
                            label: config.privateKeyLabel, // Label for the private key
                            keyType: graphene.KeyType.AES,
                            valueLen: 256 / 8,
                            extractable: true,
                            token: true,
                            encrypt: true,
                        });
                        privateKeyHandle = aesKey.handle;
                        break;
                    default:
                        throw new Error("Invalid key type specified.");
                }

                msg.publicKeyHandle = publicKeyHandle;
                msg.privateKeyHandle = privateKeyHandle;
                node.status({fill: 'green', shape: 'dot', text: 'Success'});

                send(msg);
                done();
            } catch (error) {
                console.error('Key pair generation failed:', error);
                node.status({fill: 'red', shape: 'ring', text: 'Error'});
                done(error);
            } finally {
                mod.finalize();
            }
        });
    }

    RED.nodes.registerType("p11-generate-key-pair", GenerateKeyPairNode);
};