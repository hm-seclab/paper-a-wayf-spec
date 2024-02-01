# POC (non-browser)

This is a proof of concept implementation for the 
A-WAYF: Automated Where Are You From in Multilateral Federations
paper.

## Get started

The following dependencies are required to build the project:

* [Zig 0.11.0](https://ziglang.org/download/)

After you've installed all required dependencies run `zig build` to
build the authenticator and client executables. The executables will
be placed into `./zig-out/bin/`.

> TODO: fork the solokeys firmware, modify it and add it as submodule to the repo.

## Authenticator

The given authenticator implements the CTAP2 spec + the proposed fedEntity extension (TODO).
It keeps its state in memory, i.e. you will loose all created credentials when terminating
the application.

* TODO: currently the authenticator exposes itself via usb but this is a feature only supported by Linux. As we control both authenticator and client it should be feasible to use another IPC method that works across OSes OR we just provide a virtual machine.

You can run the authenticator by executing `./zig-out/bin/authenticator`. Make sure you run the following script
to enable the `uhid` module:

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

