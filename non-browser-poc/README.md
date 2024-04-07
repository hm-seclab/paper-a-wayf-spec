# POC (non-browser)

This is a proof of concept implementation for the _A-WAYF: Automated Where Are You From in Multilateral Federations_ paper.

## Get started

The following dependencies are required to build the project:

* [Zig 0.11.0](https://ziglang.org/download/)
* Curl library and headers
    * Ubuntu: `sudo apt install libcurl4-gnutls-dev`
* OpenSSL (RS256 support)
    * Ubuntu: `sudo apt install libssl-dev`
* udev for client
    * Ubuntu: `sudo apt install libudev-dev`

After you've installed all required dependencies run `zig build` to
build the authenticator and client executables. The executables will
be placed into `./zig-out/bin/`.

> NOTE: The applications have been tested on Linux.

If you have a [Solo Hacker authenticator](https://solokeys.com/collections/all/products/solo-hacker) you can 
flash your authenticator with a [modified solo firmware](https://github.com/hm-seclab/awayf-solo1?tab=readme-ov-file#build-locally)
that implements the extension and command proposed by A-WAYF. Just follow the _Build locally_ instructions.

## Project structure

The given project is structured as follows:

* `src`: Contains all source code.
* `src/authenticator.zig`: Example authenticator implementation.
* `src/fed_management_extension/`: POC code for the proposed extension. This is used by both authenticator and client.
* `src/make_credential/`: Modified implementation of the `authenticatorMakeCredential` command that uses the new extension.
* `src/client.zig`: Client that implements A-WAYF.

## Authenticator

The given authenticator implements the CTAP2 spec + the proposed federationId extension. It keeps its state in memory, i.e. you will lose all created credentials when terminating
the application.

* NOTE: The authenticator exposes itself via _uhid_ but this is a feature only supported by Linux.

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

## Server

First [setup Dockers apt repository](https://docs.docker.com/engine/install/ubuntu/#install-using-the-repository) and then install docker compose:

```
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

Then clone the [django server](https://github.com/hm-seclab/awayf-spid-cie-oidc-django?tab=readme-ov-file#docker-compose) and build the docker container:

```
git clone https://github.com/hm-seclab/awayf-spid-cie-oidc-django.git
cd awayf-spid-cie-oidc-django
bash docker-prepare.sh
sudo docker compose up
```

Finally, add the following line to `/etc/hosts`:

```
0.0.0.0 ta.a-wayf.local rp.a-wayf.local op.a-wayf.local
```

## Client

You can run the client by executing `./zig-out/bin/client`. The PoC client will use the first authenticator available via USB. This can either be the platform authenticator or a modified Solo Hacker. The client supports a verbose flag `-v` that prints additional output.
