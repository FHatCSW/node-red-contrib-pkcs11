const graphene = require("graphene-pk11");
const Module = graphene.Module;
const forge = require("node-forge");
const resolveValue = require('./resources/resolve-value.js');


module.exports = function (RED) {
    function GenerateKeyPairNode(config) {
        RED.nodes.createNode(this, config);
        var globalContext = this.context().global;
        var flowContext = this.context().flow;
        const node = this;

        this.privateKeyLabel = config.privateKeyLabel;
        this.fieldTypePrivateKeyLabel = config.privateKeyLabel_fieldType;
        this.publicKeyLabel = config.publicKeyLabel;
        this.fieldTypePublicKeyLabel = config.publicKeyLabel_fieldType;

        node.on('input', function (msg, send, done) {
            node.status({});

            var mod;
            var slot;
            var session;
            var slots;
            var publicKeyHandle;
            var privateKeyHandle;
            var privateKeyLabel;
            var publicKeyLabel;

            var pkcs11ConfigNode = RED.nodes.getNode(config.pkcs11Config);
            var libraryPath = pkcs11ConfigNode.libraryPath;
            var slotNumber = pkcs11ConfigNode.slot;
            var slotPin = pkcs11ConfigNode.password;

            privateKeyLabel = resolveValue(msg, this.fieldTypePrivateKeyLabel, globalContext, flowContext, this.privateKeyLabel);
            publicKeyLabel = resolveValue(msg, this.fieldTypePublicKeyLabel, globalContext, flowContext, this.publicKeyLabel);

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

                session = slot.open(graphene.SessionFlag.SERIAL_SESSION | graphene.SessionFlag.RW_SESSION);
                session.login(slotPin);

                switch (config.keyType) {
                    case 'RSA':
                        // Generate RSA key pair
                        var rsaKeys = session.generateKeyPair(graphene.KeyGenMechanism.RSA, {
                            label: publicKeyLabel,
                            keyType: graphene.KeyType.RSA,
                            modulusBits: parseInt(config.bitLength),
                            publicExponent: Buffer.from([3]),
                            token: true,
                            verify: true,
                            encrypt: true,
                            wrap: true
                        }, {
                            label: privateKeyLabel, // Label for the private key
                            keyType: graphene.KeyType.RSA,
                            token: true,
                            sign: true,
                            decrypt: true,
                            unwrap: true,
                        });

                        var pubKey = rsaKeys.publicKey.getAttribute({
                            modulus: null,
                            publicExponent: null
                        });

                        // convert values to base64
                        pubKey.modulus = pubKey.modulus.toString("base64");
                        pubKey.publicExponent = pubKey.publicExponent.toString("base64");

                        //console.log(JSON.stringify(pubKey, null, 4));

                        publicKeyHandle = rsaKeys.publicKey.handle;
                        privateKeyHandle = rsaKeys.privateKey.handle;
                        break;
                    case 'ECC':
                        // Generate ECC key pair
                        var eccKeys = session.generateKeyPair(graphene.KeyGenMechanism.EC, {
                            label: publicKeyLabel,
                            keyType: graphene.KeyType.EC,
                            paramsEC: graphene.NamedCurve.getByName(config.curveType).value,
                            token: true,
                            verify: true,
                            encrypt: true,
                            wrap: true,
                            derive: false,
                        }, {
                            label: privateKeyLabel, // Label for the private key
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
                            label: privateKeyLabel, // Label for the private key
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

            } catch (error) {
                node.error('Generate keys failed:', error);
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

    RED.nodes.registerType("p11-generate-key-pair", GenerateKeyPairNode);
};
