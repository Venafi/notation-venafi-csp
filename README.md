[![Venafi](https://raw.githubusercontent.com/Venafi/.github/master/images/Venafi_logo.png)](https://www.venafi.com/)
[![Apache 2.0 License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![Community Supported](https://img.shields.io/badge/Support%20Level-Community-brightgreen)
![Compatible with TPP 23.x](https://img.shields.io/badge/Compatibility-TPP%2023.x-f9a90c)

Venafi CodeSign Protect Signature and Verification Plugin for the [Notation CLI](https://github.com/notaryproject/notation).

This is a plugin that aims to be compliant with the plugin [spec](https://github.com/notaryproject/notaryproject/blob/main/specs/plugin-extensibility.md).

#### Signature Format Compatibility
| Type | Supported |
| ---- | --------- |
| [JWS](https://github.com/notaryproject/notaryproject/blob/main/specs/signature-envelope-jws.md) | :heavy_check_mark: |
| [COSE Sign1](https://github.com/notaryproject/notaryproject/blob/main/specs/signature-envelope-cose.md) | :heavy_check_mark: |

#### Plugin Spec Compatibility
| Capability | Compatibility |
| ---------- | ------------- |
| keySpec | `RSA-2048`, `RSA-3072`, `RSA-4096`, `EC-256`, `EC-384`, `EC-521` |
| hashAlgorithm | `SHA-256` |
| signingAlgorithm | `RSASSA-PSS-SHA-256`, `ECDSA-SHA-256` |
| pluginCapability | `SIGNATURE_GENERATOR.ENVELOPE`, `SIGNATURE_VERIFIER.TRUSTED_IDENTITY`, `SIGNATURE_VERIFIER.REVOCATION_CHECK` |
| signatureEnvelopeType | `application/jose+json` ([JWS](https://datatracker.ietf.org/doc/html/rfc7515)), `application/cose` ([COSE](https://datatracker.ietf.org/doc/rfc9052)) |
| extendedAttributes | `com.venafi.notation.plugin.x5u` (only generated with TPP 23.1+ for experimental identity validation support)|
| signingScheme | `notary.x509` |


## Getting Started:
The following summarizes the steps to configure the Venafi CodeSign Protect notation plugin and sign and verify a container image.  The following steps are based off of the Notation hello-signing [example](https://github.com/notaryproject/notation/blob/main/docs/hello-signing.md#getting-started).

- This plugin leverages the [Venafi vSign SDK](https://github.com/venafi/vsign), which means you'll need to meet the pre-requisites as well as customize the config.ini in terms of `tpp_url`, `access_token`, and `tpp_project`.
- Install notation [CLI](https://github.com/notaryproject/notation/releases/tag/v1.1.0).  Version v1.1.0 has been tested. Note that `make install` creates the plugin directory structure based on a MacOS environment.  Update the Makefile based on your OS.  It then copies the plugin to the appropriate location based on the notation plugin directory structure spec.

## Installation

Install the notation-venafi-csp plugin for remote signing and verification, using the `notation plugin install` command:

```bash
notation plugin install --url https://github.com/Venafi/notation-venafi-csp/releases/download/v0.3.0/notation-venafi-csp-linux-amd64.tar.gz --sha256sum 03771794643f18c286b6db3a25a4d0b8e7c401e685b1e95a19f03c9356344f5a

```

Adjust the `--url` and `--sha256sum` parameters based on the release and platform you are deploying the plugin for.

#### Build and Install from Source
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
In order to verify the container image, you need to configure the trust policy to specify trusted identities which sign the artifacts, and level of signature verification to use. Follow the [Manage trust policies](https://notaryproject.dev/docs/user-guides/how-to/manage-trust-policy/) guide to understand and implement Notation trust policy. 

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

As an example, you can use `notation policy import` to import the trust policy configuration from the above JSON file:

```
notation policy import ./trustpolicy.json
```

# Remotely sign with Venafi CodeSign Protect
- Obtain certificate

You should use the certificate label that matches the Venafi CodeSign Protect environment obtained using `pkcs11config`:

```bash
pkcs11config getcertificate <...>
```

- Add the Key Id to the keys and certs

```bash
notation key add --default "vsign-rsa2048-cert" --plugin venafi-csp --id "vsign-rsa2048-cert" --plugin-config "config"="/path/to/vsign/config.ini"
notation certificate add --type ca --store example.com /path/to/chain.crt
```

*Note: A best practice for Key Id naming would be to use the certificate label that matches the Venafi CodeSign Protect environment*

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

*Note: Verification does perform additional checks such as verifying the revocation status of the code signing certificate, as well as validating that the certificate does exist in CodeSign Protec via PKS for identity validation purposes when using TPP 23.1+.*