# GoCA Commands

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