## Lightweight ACME Client written in the D computer language

This project is yet another [_Let's Encrypt_](https://letsencrypt.org) client. It has the following properties.

* It is written in the D computer language.
* WIP: The main artifact is a D static library.
* A commandline tool provides all operations of RFC855 as best as possible
* Tries to be a good example of D programming. It hast ddoc and unittest
  support.

#### Building and Installing

Building requires dub, openssl and curl. On Debian based systems this will install them.

```
apt-get install dub libssl-dev libcurl4-gnutls-dev
```

On Red Hat based systems this will do it.

```
yum install dub openssl-devel curl-devel
```

Workaround for problems with dub:openssl package
```
cd <somepath>
git clone https://github.com/cschlote/openssl.git
cd openssl && git checkout fixup_EVP_MD_CTX_new
dub add-local <somepath>/openssl
```

To build and install run:

```
dub build
```

To run against the _Let's Encrypt_ staging environment generate your makefiles with this.
(NOT WORKING YET)

```
dub build -c acme-staging
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

#### Command Line Client

The command line client is run as follows.

```
./acme-lw-d -k key.pem -d honk.com -d bubu.com -y -c "mailto:santaclaus@northpol.org"
./acme-lw-d -h
```

#### Library API

The API of the library is documented in its [source file](source/acme/acme-lw.d). The command line client
[source](source/app.d) provides an example of how it's used.

All methods report errors by throwing some exception, which will normally be an instance of acme.AcmeException.

#### ToDOs

Mandatory:
* Implement 7.4.    Applying for Certificate Issuance

Optional:
* Implement 7.3.4.  External Account Binding
* Implement 7.3.5.  Account Key Rollover
* Implement 7.3.6.  Account Deactivation
* Implement 7.4.1.  Pre-authorization

Nice to have:
* Create a new SSL private/public key pair in program, if not existent and allowed by cmdline arg.
  It avoids the use of the openssl command client (see above). Should create only supported keys.
* Split code into a library package and an optional CLI client, which uses the library package.

