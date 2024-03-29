
## Lightweight ACME Client written in the D computer language

This project is yet another [_Let's Encrypt_](https://letsencrypt.org) client.
It has the following properties.

* It is written in the D computer language.
* A commandline tool provides all operations of RFC855 as best as possible
* It hast ddox and unittest support.

### Referenzes

* https://tools.ietf.org/html/rfc8555  Automatic Certificate Management Environment (ACME)
* https://tools.ietf.org/html/rfc7638  JSON Web Key (JWK) Thumbprint
* https://tools.ietf.org/html/rfc7518  JSON Web Algorithms (JWA)
* https://tools.ietf.org/html/rfc7515  JSON Web Signature (JWS)
* https://tools.ietf.org/html/rfc7231  Hypertext Transfer Protocol (HTTP)

* https://wiki.openssl.org/index.php/EVP_Signing_and_Verifying
* https://github.com/letsencrypt/boulder/blob/master/csr/csr.go

#### Building and Installing

Building requires dub, a working D compiler, openssl and curl. On Debian based
systems you can install them with:
```
sudo apt-get install dub libssl-dev libcurl4-openssl-dev
```

On Red Hat based systems use this:
```
yum install dub openssl-devel curl-devel
```

To build and install run:
```
dub build
```

To run the unittests:
```
dub test
```

Run it as a dub package:
```
dub fetch acme-lw-d
dub run acme-lw-d -- -h
```

#### Let's Encrypt Credentials

To use any _Let's Encrypt_ client you need to sign requests with your _Let's Encrypt_'s account's private key.
This library uses a private key in PEM format. If you want to use an existing _Let's Encrypt_ private key, it's in JWK
format. The [acme-tiny](https://github.com/diafygi/acme-tiny) library has good documentation on
[how to convert](https://github.com/diafygi/acme-tiny#use-existing-lets-encrypt-key) it.

Create a SSL key pair with:
```
openssl genrsa -out key.pem 2048
```

Otherwise the client will create a new key, if the given file doesn't exist.

#### Command Line Client

The command line client is run as follows:

```
$ ./acme-lw-d
Usage: acme_client <options>
-k            --key Required: The path to private key of ACME account. (PEM file)
-p      --domainkey Required: The path to your private key for X509 certificates (PEM file)
-d         --domain Required: A domain name. Can be given multiple times. First entry will be subject name.
-c        --contact Required: A contact for the account. Can be given multiple times.
-o         --output Required: The output file for the PEM encoded X509 cert
-w --setupchallange Required: Programm to call to setup a challange
-b           --bits           RSA bits to use for keys. Used on new key creation
-y          --agree           Agree to TermsOfService, when creating the account.
-s        --staging           Use the staging server for initial testing or developing
           --server           Alternate ACME server directory url
-v        --verbose           Verbose output
-h           --help           This help information.

Example:
  $ ./acme-lw-d -k key.pem -p domain.key -o domain.pem \
       -d your-domain.net -d www.your-domain.net \
       -c "mailto:webmaster@domain.net" \
       -w "./examples/setupChallange.sh" \
       -y -v -b {rsa2048|rs4096}

  RS keys will be created on first run and stored on disk. They are reused
  when existing.

  The setup-challange script is called with the challange type, the filename
   and token. Right new, only http challange is supported (FIXME).
```

#### Library API

The API of the library is documented with ddox:
```
dub run -b ddox
```

All methods report errors by throwing some exception, which will normally be an instance of acme.AcmeException.

#### ToDOs

Mandatory:
* Cleanup output with respect to -v option
* Implement account deactivation

Optional:
* Implement 7.3.4.  External Account Binding
* Implement 7.3.5.  Account Key Rollover
* Implement 7.3.6.  Account Deactivation
* Implement 7.4.1.  Pre-authorization

Nice to have:
* Split code into a library package and an optional CLI client, which uses the library package.
