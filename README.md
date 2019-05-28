## Lightweight ACME Client written in the D computer language

This project is yet another [_Let's Encrypt_](https://letsencrypt.org) client. It has the following properties.

* The main artifact is a D static library.
* Functionality only supports creating and updating certificates using http challenges.
* All code runs 'in process', i.e., no processes are spawned.

#### Building and Installing

Building requires dub, openssl and curl. On Debian based systems this will install them.

```
apt-get install dub libssl-dev libcurl4-gnutls-dev
```

On Red Hat based systems this will do it.

```
yum install dub openssl-devel curl-devel
```

To build and install run:

```
dub build
```

To run against the _Let's Encrypt_ staging environment generate your makefiles with this.

```
dub build -c acme-staging
```

#### Let's Encrypt Credentials

To use any _Let's Encrypt_ client you need to sign requests with your _Let's Encrypt_'s account's private key.
This library uses a private key in PEM format. If you want to use an existing _Let's Encrypt_ private key, it's in JWK
format. The [acme-tiny](https://github.com/diafygi/acme-tiny) library has good documentation on
[how to convert](https://github.com/diafygi/acme-tiny#use-existing-lets-encrypt-key) it.

```
openssl genrsa -out key.pem 2048
```

#### Command Line Client

The command line client is run as follows.

```
acme_lw_d <filename of account private key> <domain name> ...
```

Multiple domain names can be on the command line.

The behavior is similar to the official _Let's Encrypt_ client run as follows:

```
certbot certonly --manual -d <domain name>
```

#### Library API

The API of the library is documented in its [source file](source/acme/acme-lw.d). The command line client [source](source/app.d)
provides an example of how it's used.

All methods report errors by throwing std.exception, which will normally be an instance of acme.AcmeException.


#### ToDOs

Split code into a library package and an optional CLI client, which uses the library package.
