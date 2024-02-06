# POC (non-browser)

This is a proof of concept implementation for the A-WAYF: Automated Where Are You From in Multilateral Federations paper.

## Get started

The following dependencies are required to build the project:

* [Zig 0.11.0](https://ziglang.org/download/)

After you've installed all required dependencies run `zig build` to
build the authenticator and client executables. The executables will
be placed into `./zig-out/bin/`.

> TODO: fork the solokeys firmware, modify it and add it as submodule to the repo.

## Project structure

The given project is structured as follows:

* `src`: Contains all source code.
* `src/authenticator.zig`: Example authenticator implementation.
* `src/fed_management_extension/`: POC code for the proposed extension. This is used by both authenticator and client.
* `src/make_credential/`: Modified implementation of the `authenticatorMakeCredential` command that uses the new extension.

## Authenticator

The given authenticator implements the CTAP2 spec + the proposed fedEntity extension. It keeps its state in memory, i.e. you will loose all created credentials when terminating
the application.

* TODO: currently the authenticator exposes itself via usb but this is a feature only supported by Linux. As we control both authenticator and client it should be feasible to use another IPC method that works across OSes OR we just provide a virtual machine.

You can run the authenticator by executing `./zig-out/bin/authenticator`. Make sure you run the following script to enable the `uhid` module on Linux:

```bash
#!/bin/sh

# Exit immediately if any command returns a non-zero exit status
set -e 

# Create a udev rule that allows all users that belong to the group fido to access /dev/uhid
echo 'KERNEL=="uhid", GROUP="fido", MODE="0660"' > /etc/udev/rules.d/90-uinput.rules

# Create a new group called fido
getent group fido || (groupadd fido && usermod -a -G fido $SUDO_USER)

# Add uhid to the list of modules to load during boot
echo "uhid" > /etc/modules-load.d/fido.conf 

echo "Installed successfully. Please reboot..."

# Exit successfully
exit 0
```

## Client

You can run the client by executing `./zig-out/bin/authenticator`. The POC client will use the first authenticator available via USB.

## Example Output

Authenticator:
```
./zig-out/bin/authenticator
info: Auth.init: no settings found
info: Auth.init: generating new settings...
info: writing (53657474696e6773, Root): a66a70696e5265747269657308697576526574726965730870666f7263655f70696e5f6368616e6765f46e6d696e5f70696e5f6c656e6774680469616c776179735f7576f46b75736167655f636f756e7400
info: Auth.init: new settings persisted
info: request(66): a101010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
info: response(66): 00a30146686d2e65647502583168747470733a2f2f7368692d696470322e727a2e66682d6d75656e6368656e2e64652f6964702f73686962626f6c6574680301
```

Client:
```
./zig-out/bin/client
info: [0]: https://shi-idp2.rz.fh-muenchen.de/idp/shibboleth, hm.edu, 1
```

