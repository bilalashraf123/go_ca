# GoCA Documentation

The go-ca is a command line CA utility used for generation of PKI. It includes the following features:

  - Support for hardware based PKI (key pairs for PKI in PKCS#11 based hardware device)
  - Support for software based PKI (key pairs for PKI in files - PEM encoded)
  - RSA algorithm support (2048, 3072 and 4096 key length) in both software and hardware
  - ECDSA algorithm support (P-256, P-384 and P-521 curves) in both software and hardware
  - Support for multiple types of certificate e.g. TLS server, client authentication and so on based on certificate profile
  - Digest algorithms (sha256, sha384 and sha512) support to sign certificates and CRLs
    
Note:- The go-ca CLI is written 100% in Go Language.

- Get the respective release from https://github.com/bilalashraf123/go_ca/releases
- Unzip the file. Go to the required platform directory (For linux, go to linux/amd64 and for macOS, go to macos/arm64)
- Run ./go-ca -h  

# GoCA Commands

```text
bilal@bilal-HP-ProBook-450-G8-Notebook-PC:~/development/go_ca$ ./go-ca -h
go-ca is a command line utility for PKI and crypto related operations

Usage:
  go_ca [command]

Available Commands:
  help        Help about any command
  pki         Creates software and hardware based PKIs using RSA and ECDSA algorithms
  timestamp   Generate RFC3161 timestamp

Flags:
  -h, --help      help for go_ca
  -v, --version   version for go_ca

Use "go_ca [command] --help" for more information about a command.
```

```text
bilal@bilal-HP-ProBook-450-G8-Notebook-PC:~/development/go_ca$ ./go-ca pki -h
Creates software and hardware based PKIs using RSA and ECDSA algorithms

Usage:
  go_ca pki [command]

Available Commands:
  csr_cert_gen Generates certificate using software/hardware CA key by providing CSR and subject information as an input
  key_cert_gen Generates RSA or ECDSA key pair in software (PEM format) or hardware (HSM or Tokens) and selfsigned/delegated certifcate in one go
  key_csr_gen  Generates RSA or ECDSA key pair in software (PEM format) or hardware (HSM or Tokens) and CSR in one go
  key_gen      Generates RSA or ECDSA key pair in software (PEM format) or hardware (HSM or Tokens)

Flags:
  -h, --help      help for pki
  -v, --version   version for pki

Use "go_ca pki [command] --help" for more information about a command.

```