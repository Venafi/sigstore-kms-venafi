# sigstore-kms-venafi
Sigstore [KMS Plugin](https://github.com/sigstore/sigstore/tree/main/pkg/signature/kms/cliplugin) for CyberArk Code Sign Manager (previously Venafi CodeSign Protect)

Supports [cosign](https://github.com/sigstore/cosign) image and artifact signing with [CyberArk Code Sign Manager](https://www.cyberark.com/products/code-sign-manager/) leveraging the [vSign](https://github.com/Venafi/vsign) SDK

### KMS Plugin Spec Compatibility
| Capability | Compatibility |
| ---------- | ------------- |
| DefaultAlgorithm | RSA-2048 |
| SupportedAlgorithsm | RSA, ECDSA |
| CreateKey | :x: |
| PublicKey | :heavy_check_mark: |
| SignMessage | :heavy_check_mark: |
| VerfiyMessage | :heavy_check_mark: |
| CryptoSigner | :x: |


### Pre-requisites
* CyberArk Code Sign Manager Self-Hosted/SaaS
* Sigstore [cosign](https://github.com/sigstore/cosign) v2.4.3+

### Installation

For the sigstore library to invoke the plugin, the binary must be in your system's PATH.

```sh
git clone https://github.com/Venafi/sigstore-kms-venafi.git
cd sigstore-kms-venafi
go build -o sigstore-kms-venafi
cp sigstore-kms-venafi /usr/local/bin
```

### Configuration

The CyberArk Code Sign Manager KMS plugin relies on environment variables, and therefore must be set prior to running cosign with the plugin.  Review the [vSign](https://github.com/Venafi/vsign) SDK for detailed information on creating the necessary CyberArk API oauth token.

#### Create Environment Variables


##### Self-Hosted
These are the minimum variables required

```sh
VSIGN_URL="https://tpp.example.com"
VSIGN_TOKEN="xxxxxxxxxx"
VSIGN_JWT="xxxxxxxxxxx"
```

For authentication only use either `VSIGN_TOKEN` or `VSIGN_JWT`, since the JWT will be exchanged for an access token.

##### SaaS

```sh
VSIGN_URL="https://api.venafi.cloud"
VSIGN_APIKEY="xxxxxxxxxxxxx"
VSIGN_KEY_LABEL="{project}-{signing-key}"
```

If using Service Accounts

```sh
VSIGN_URL="https://api.venafi.cloud"
VSIGN_CLIENT_ID="xxxx"
VSIGN_PRIVATE_KEY_FILE="/path/to/service-account-private-key.key"
VSIGN_KEY_LABEL="{project}-{signing-key}"
```

*You can obtain the Service Account Client ID and signing key label from the SaaS UI*

Please review the following [documentation](https://developer.venafi.com/tlsprotectcloud/docs/code-sign-client-auth-user) on how to obtain the SaaS API Key.

*Currently only Certificate environments are supported*

### Signing a Container Image

#### Self-Hosted

```sh
cosign sign --key "venafi://{venafi-csp-project-name\environment}" --tlog-upload=false my-org-repo/my-image:v1
```

Example:

```sh
cosign sign --key "venafi://container-signing-project\my-cert" --tlog-upload=false my-org-repo/my-image:v1
```

#### SaaS

```sh
cosign sign --key "venafi://{project}-{signing-key-name}" --tlog-upload=false my-org-repo/my-image:v1
```

Example:

```sh
cosign sign --key "venafi://myproject-mysigner" --tlog-upload=false my-org-repo/my-image:v1
```


### Verifying a Container Image

#### Self-Hosted

```sh
cosign verify --key "venafi://{venafi-csp-project-name\environment}" --insecure-ignore-tlog=true my-org-repo/my-image:v1
```

Example:

```sh
cosign verify --key "venafi://container-signing-project\my-cert" --insecure-ignore-tlog=true my-org-repo/my-image:v1
```

#### SaaS

```sh
cosign verify --key "venafi://{project}-{signing-key-name}" --insecure-ignore-tlog=true my-org-repo/my-image:v1
```

Example:

```sh
cosign verify --key "venafi://myproject-mysigner" --insecure-ignore-tlog=true my-org-repo/my-image:v1
```

### Creating Verifiable Records with Tekton Chains and CyberArk Code Sign Manager

Checkout the following [Tekton Chains and CyberArk Code Sign Manager KMS Plugin](./TEKTONCHAINS.md) integration guide

### Creating and Managing Verifiable Evidence with Valint and CyberArk Code Sign Manager

Checkout the following [Valint and CyberArk Code Sign Manager KMS Plugin](./VALINT.md) integration guide

## Want to Contribute

* Any questions, suggestions or issues please use [GitHub Issues](https://github.com/Venafi/sigstore-kms-venafi/issues)

### Contributing to sigstore-kms-venafi

CyberArk welcomes contributions from the developer community.

1. Fork it to your account (https://github.com/Venafi/sigstore-kms-venafi/fork)
2. Clone your fork:
   ```sh
   git clone git@github.com:youracct/sigstore-kms-venafi.git
   ```
3. Create a feature branch:
   ```sh
   git checkout -b your-branch-name
   ```
4. Implement and test your changes
5. Commit your changes:
   ```sh
   git commit -am 'Added some cool functionality'
   ```
6. Push to the branch
   ```sh
   git push origin your-branch-name
   ```
7. Create a new Pull Request at https://github.com/youracct/sigstore-kms-venafi/pull/new/your-branch-name

## License

Copyright &copy; CyberArk Software Ltd. All rights reserved.

sigstore-kms-venafi is licensed under the Apache License, Version 2.0. See [LICENSE](./LICENSE) for the full license text.

Please direct questions/comments to opensource@venafi.com.