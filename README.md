# node-red-contrib-pkcs11

## Developing and testing on a remote machine

1. Pack the package `npm pack ./node-red-contrib-pkcs11`
2. Copy it to the node-red root directory: `scp ./node-red-contrib-pkcs11-1.0.1.tgz admin@node-001.local:~/.node-red/`
3. Installthe package: `npm install node-red-contrib-pkcs11-1.0.1.tgz`
4. Restart node-red: `sudo systemctl restart node-red.service`

## pkcs11-tool

```
pkcs11-tool --module /usr/local/lib/softhsm/libsofthsm2.so --list-objects --slot-index 0 --pin 1234
```

## Setting up SoftHSM

### MacOS 

> The following example uses hombrew

#### Step 1: Install SoftHSM

```
brew install softhsm
```

#### Step 2: Initialize SoftHSM

After the installation is complete, you'll need to initialize SoftHSM and set up a token. Replace <TOKEN_LABEL>, <TOKEN_PIN>, and <SO_PIN> with your desired values:

```
mkdir -p ~/softhsm/tokens
softhsm2-util --init-token --slot 0 --label <TOKEN_LABEL> --pin <TOKEN_PIN> --so-pin <SO_PIN>
```

#### Step 3: Verify Configuration

You can verify that SoftHSM is running and view slot information using the pkcs11-tool command. Make sure to replace the path to the SoftHSM library if necessary:

> To use the ppkcs11-tool you need to install OpenSC: `brew install opensc`

```
pkcs11-tool --module /usr/local/lib/softhsm/libsofthsm2.so --list-slots
```

You should receive an output which looks like this:

```
Available slots:
Slot 0 (0x19d6b915): SoftHSM slot ID 0x19d6b915
  token label        : keyfactor_soft
  token manufacturer : SoftHSM project
  token model        : SoftHSM v2
  token flags        : login required, rng, token initialized, PIN initialized, other flags=0x20
  hardware version   : 2.6
  firmware version   : 2.6
  serial num         : 6c1b366619d6b915
  pin min/max        : 4/255
Slot 1 (0x1): SoftHSM slot ID 0x1
  token state:   uninitialized

```