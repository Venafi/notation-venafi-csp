# notation-venafi-csp

Venafi CodeSign Protect Signature Plugin for the Notary v2 [Notation CLI](https://github.com/notaryproject/notation).

This is a WIP plugin that aims to be compliant with the plugin [spec](https://github.com/notaryproject/notaryproject/blob/main/specs/plugin-extensibility.md).

## Getting Started:
The following summarizes the steps to configure the Venafi CodeSign Protect notation plugin and sign and verify a container image.  The following steps are based off of the Notation hello-signing [example](https://github.com/notaryproject/notation/blob/main/docs/hello-signing.md#getting-started).

- This plugin leverages the [Venafi vSign SDK](https://github.com/venafi/vsign), which means you'll need to customize the config.ini in terms of `tpp_url`, `access_token`, and `tpp_project`.
- Install notation [CLI](https://github.com/notaryproject/notation/releases/tag/v1.0.0-rc.4).  Version v1.0.0-rc.4 has been tested. Note that `make install` creates the plugin directory structure based on a MacOS environment.  Update the Makefile based on your OS.  It then copies the plugin to the appropriate location based on the notation plugin directory structure spec.
- Install the notation-venafi-csp pluging for remote signing and verification:
 ```bash
 git clone https://github.com/venafi/notation-venafi-csp.git
 cd notation-venafi-csp
 make build
 make install
 ```
  
- Install [Docker Desktop](https://www.docker.com/products/docker-desktop) for local docker operations
- Create and run an OCI-compatible registry on your development system using an open source [registry](https://github.com/distribution/distribution) implementation.
  ```bash
  docker run -d -p 5001:5000 -e REGISTRY_STORAGE_DELETE_ENABLED=true --name registry registry
  ```
- Build and Push the `net-monitor` software

```bash
docker build -t localhost:5001/net-monitor:v1 https://github.com/wabbit-networks/net-monitor.git#main
docker push localhost:5001/net-monitor:v1
```

- Get the digest value of *localhost:5001/net-monitor:v1*:

```bash
docker inspect localhost:5001/net-monitor:v1 -f '{{ .Id }}'
sha256:073b75987e95b89f187a89809f08a32033972bb63cda279db8a9ca16b7ff555a
```

- List the image, and any associated signatures.  At this point there shouldn't be any signatures

```bash
IMAGE=localhost:5001/net-monitor@sha256:073b75987e95b89f187a89809f08a32033972bb63cda279db8a9ca16b7ff555a
notation ls $IMAGE
```

- Create a trust policy
In order to verify the container image, you need to configure the trust policy to specify trusted identities which sign the artifacts, and level of signature verification to use. See [trust policy](https://notaryproject.dev/docs/concepts/trust-store-trust-policy-specification/#trust-policy) spec to understand more about trust policy. 

```
{
    "version": "1.0",
    "trustPolicies": [
        {
            "name": "wabbit-networks-images",
            "registryScopes": [ "*" ],
            "signatureVerification": {
                "level" : "strict" 
            },
            "trustStores": [ "ca:wabbit-networks.io" ],
            "trustedIdentities": [
                "*"
            ]
        }
    ]
}
```

For a Linux user, store file trustpolicy.json under directory `$HOME/.config/notation/`.

For a Mac user, store file trustpolicy.json under directory `$HOME/Library/Application Support/notation/`.

For a Window user, store file trustpolicy.json under directory `C:\Users\<username>\AppData\Roaming\notation\`.


# Remotely sign with Venafi CodeSign Protect
- Obtain certificate

```bash
pkcs11config getcertificate <...>
```

- Add the Key Id to the keys and certs

```bash
notation key add --default "vsign-rsa2048-cert" --plugin venafi-csp --id "vsign-rsa2048-cert" --plugin-config "config"="/path/to/vsign/config.ini"
notation certificate add --type ca --store example.com /path/to/chain.crt
```

- List the keys and certs to confirm

```bash
notation key list
notatation certificate list
```

- Sign the container image with default signature manifest as `image`

```bash
notation sign --key "vsign-rsa2048-cert" $IMAGE
```

- Confirm that there is one signature

```bash
notation ls $IMAGE
localhost:5001/net-monitor@sha256:073b75987e95b89f187a89809f08a32033972bb63cda279db8a9ca16b7ff555a
└── application/vnd.cncf.notary.v2.signature
    └── sha256:ba3a68a28648ba18c51a479145fca60d96b43dc96c6ab22f412c89ac56a9038b
```

- Verify the container image signature

```bash
notation verify $IMAGE
```

```bash
Signature verification succeeded for sha256:73b3c3f2200bc6c161663b88b1fde3b3ed486518d6b6453fccdfdbbaefa09c7b
```