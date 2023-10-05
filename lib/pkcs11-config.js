module.exports = function (RED) {
    function Pkcs11ConfigNode(config) {
        RED.nodes.createNode(this, config);
        this.name = config.name;
        this.libraryPath = config.libraryPath;
        this.slot = config.slot;
        this.password = config.password;

    }

    RED.nodes.registerType("pkcs11-config", Pkcs11ConfigNode);
};
