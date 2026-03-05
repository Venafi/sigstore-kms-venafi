# Integration with Valint

## Requirements
* Follow the [Attestation](https://github.com/scribe-security/docs/blob/master/docs/valint/attestations.md) documentation for Valint
* Valint CLI

## Steps
1. Follow the [README](./README.md) for installing the `sigstore-kms-venafi` plugin and ensuring it is in the `PATH`
2. Configure the necessary [vSign](https://github.com/venafi/vsign.git) environment variables 

```sh
VSIGN_URL="https://api.venafi.cloud"
VSIGN_APIKEY="xxxxxxxxxxxxx"
```
3. Run valint and sign evidence with the appropriate Code Sign Manager signing key:

```sh
valint bom busybox:latest --kms venafi://{project}-{signing-key-name}
```

*You can obtain the project and signing key name from the SaaS UI via `Inventory -> Signing Keys`.  This represents the key label when you concatenate the project with the signing key. You can also use the `pkcs11config list` to obtain the key label and supply in the KMS URI above.*