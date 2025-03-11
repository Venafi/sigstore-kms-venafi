# sigstore-kms-venafi
Sigstore KMS Plugin for Venafi CodeSign Protect

Supports [cosign](https://github.com/sigstore/cosign) image and artifact signing with [Venafi CodeSign Protect](https://venafi.com/codesign-protect/) leveraging the [vSign](https://github.com/Venafi/vsign) SDK

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
* Venafi CodeSign Protect (22+)
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

The Venafi KMS plugin relies on environment variables, and therefore must be set prior to running cosign with the plugin.  Review the [vSign](https://github.com/Venafi/vsign) SDK for detailed information on creating the necessary Venafi API oauth token.

#### Create Environment Variables

These are the minimum variables required

```sh
VSIGN_URL="https://tpp.example.com"
VSIGN_TOKEN="xxxxxxxxxx"
VSIGN_JWT="xxxxxxxxxxx"
```

For authentication only use either `VSIGN_TOKEN` or `VSIGN_JWT`, since the JWT will be exchanged for an access token.

*Currently only Certificate environments are supported*

### Signing a Container Image

```sh
cosign sign --key "venafi://{venafi-csp-project-name\environment}" --tlog-upload=false my-org-repo/my-image:v1
```

Example:

```sh
cosign sign --key "venafi://container-signing-project\my-cert" --tlog-upload=false my-org-repo/my-image:v1
```

### Verifying a Container Image

```sh
cosign verify --key "venafi://{venafi-csp-project-name\environment}" --insecure-ignore-tlog=true my-org-repo/my-image:v1
```

Example:

```sh
cosign verify --key "venafi://container-signing-project\my-cert" --insecure-ignore-tlog=true my-org-repo/my-image:v1
```

## Want to Contribute

* Any questions, suggestions or issues please use [GitHub Issues](https://github.com/Venafi/sigstore-kms-venafi/issues)

### Contributing to sigstore-kms-venafi

Venafi welcomes contributions from the developer community.

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

Copyright &copy; Venafi, Inc. All rights reserved.

sigstore-kms-venafi is licensed under the Apache License, Version 2.0. See [LICENSE](./LICENSE) for the full license text.

Please direct questions/comments to opensource@venafi.com.