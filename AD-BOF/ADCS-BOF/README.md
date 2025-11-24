# ADCS-BOF
A library of beacon object files to interact with ADCS servers and certificates.

## certi request

Request an enrollment certificate

```
certi req <--ca CA> [--template Template] [--subject CN] [--altname CN] [--alturl tag:microsoft.com,2022-09-14:sid:<SID>] [--install] [--machine] [--policy] [--dns]
```

* `--ca` - The certificate authority to use
* `--template` - The certificate type to request (else default for User/Machine)
* `--subject` - The subject's distinguished name (else default for user/machine)
* `--altname` - The alternate subject's distinguished name
* `--alturl` - SAN URL entry, can be used to specify the alternate subject's SID
* `--install` - Install the certificate in current context?
* `--machine` - Request a certificate for a machine instead of a user?
* `--policy` - Adds App policy to allow client auth and Acting as a certificate agent (for ESC15)
* `--dns` - Subject Altname given as a DNS name (else: Subject alt name given as UPN).

## References
- [https://github.com/trustedsec/CS-Remote-OPs-BOF](https://github.com/trustedsec/CS-Remote-OPs-BOF)
