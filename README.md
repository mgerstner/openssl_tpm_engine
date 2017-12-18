# README for the *forked* OpenSSL 1.0.x/1.1.x TPM engine

- Original Author: Kent Yoder <kyoder@users.sf.net>
- Fork Maintainer: Matthias Gerstner <matthias.gerstner@suse.com>
- Report bugs: via GitHub issues or direct email

## About

This package contains two sets of code, a command-line utility used to
generate a TSS key blob and write it to disk and an OpenSSL engine which
interfaces with the TSS API.

Since the
[original upstream
project](https://sourceforge.net/p/trousers/openssl_tpm_engine/ci/master/tree/)
is unresponsive I have forked the code base and moved it to GitHub. The main
reason for this is the compatibility with OpenSSL 1.1 which requires major
changes to the OpenSSL APIs used and the build system.

At the moment this code works against both OpenSSL 1.0.x and 1.1.x versions.
In the future support for 1.0.x may be dropped.

## Building

Requirements:

- OpenSSL 1.0.x or 1.1.x version
- TrouSerS TSS 1.2 stack

By default, the build will look for the OpenSSL libraries via `pkg-config`.
You can choose a custom OpenSSL to build against using the `--with-openssl`
switch.

```sh
$ configure [--enable-debug] [--with-openssl=/path/to/custom/openssl] [--with-enginedir=/path/to/engines] 
$ make
# make install
```

## Differences between OpenSSL 1.0 and 1.1

Depending on the Linux distribution used the OpenSSL engines are possibly
installed in different directories for OpenSSL 1.0 and OpenSSL 1.1. Also the
naming scheme for OpenSSL engines has changed. In OpenSSL 1.0 they are named
like regular libraries (i.e. `libtpm.so`) and in OpenSSL 1.1 they are named
like plugins (i.e. `tpm.so`).

The OpenSSL core libraries will fail to load engines using an incompatible
naming scheme. Therefore the tpm engine build system adjusts the target name
dynamically depending on whether the build is against OpenSSL 1.0 or OpenSSL
1.1.

## Running

```sh
create_tpm_key

        create_tpm_key: create a TPM key and write it to disk
        usage: create_tpm_key [options] <filename>

        Options:
                -e|--enc-scheme encryption scheme to use [PKCSV15] or OAEP
                -q|--sig-scheme signature scheme to use [DER] or SHA1
                -s|--key-size   key size in bits [2048]
                -a|--auth       require a password for the key [NO]
                -p|--popup      use TSS GUI popup dialogs to get the password
				for the key [NO] (implies --auth)
```

- Key type: The TPM key type of the key created will be legacy, so that it can
  be used for both signing and encryption.

- Padding schemes:  Choosing the encryption and signature schemes at key
  creation time is mandatory because of the structure of a TPM key blob.  Once
  a key is created by the TPM, the encryption and signature schemes are set in
  store and cannot be changed without corrupting the key (making it unloadable
  into a TPM). Here are the trade-offs:

- Encryption schemes:

    * PKCSV15 encryption scheme - all encrypted data will be padded using the
    PKCSv1.5 padding algorithm. OAEP padding is considered more secure, but
    many legacy apps will require PKCSv1.5 (most notably openssl). PKCSV15
    padding will also allow a slightly larger chunk of data to be encrypted in
    one operation.

    * OAEP encryption scheme - all encrypted data will be padded using the OAEP
    padding algorithm.

- Signature schemes:

    * DER signature scheme - assumes data to be signed is DER encoded (although
    this is not required). Will allow signatures to be made of arbitrary
    size, up to the size the padding will allow.
    * SHA1 signature scheme - assumes *all* data to be signed is a SHA1 hash.
    This restricts the data size to be signed to 20 bytes, always.

- Defaults:

    * Key sizes: Default=2048 bits. Other valid sizes are 512 and 1024 bits.

    * Key auth: Default=none. if `-a` is specified, you will be prompted on the
    command line using OpenSSL for a passphrase. This passphrase is SHA1
    hashed by the TSS and used as the key's password. At key load time, you'll
    be prompted for the passphrase again by OpenSSL. If `-p` is specified,
    you'll get a GUI  prompt for password.

## Password Usage

In order to make the TPM engine prompt you for your password, add the
following code to your app:

- To set the SRK password explicitly in your code, do:
```c
ENGINE_ctrl_cmd(e, "PIN", 0, SRK_password, NULL, 0);
```

- The default secret mode is `TSS_SECRET_MODE_PLAIN`, so the above code will
always work with a plaintext SRK secret.  If you have the hash of your secret,
do this:
```c
ENGINE_ctrl_cmd(e, "SECRET_MODE", TSS_SECRET_MODE_SHA1, NULL, NULL, 0);
ENGINE_ctrl_cmd(e, "PIN", 0, SRK_password_hash, NULL, 0);
```

- To force the TSS to popup a dialog prompting you for your SRK password:
```c
ENGINE_ctrl_cmd(e, "SECRET_MODE", TSS_SECRET_MODE_POPUP, NULL, NULL, 0);
```

## Engine Configuration

Included in this package is a sample `openssl.cnf` file, which can be used to
turn on use of the TPM engine in apps where OpenSSL config support is compiled
in.


## Use Cases

If there's a use case for the TPM engine that you'd like to see it support,
please drop a line to trousers-users@lists.sf.net.

Examples:

Create a self-signed cert using the TPM engine:

1. Generate a TPM key and write it to a file:
```sh
$ create_tpm_key <keyfilename>
```
2. Make the openssl certificate request:
```sh
$ openssl req -keyform engine -engine tpm -key <keyfilename> -new -x509 -days 365 -out <certfilename>
```
3. Test using openssl:
```sh
$ openssl s_server -cert <certfilename> -www -accept 4433 -keyform engine -engine tpm -key <keyfilename>
$ konqueror https://localhost:4433
```
