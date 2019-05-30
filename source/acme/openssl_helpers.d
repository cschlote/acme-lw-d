
/** Small helpers for libCURL
 *
 * This module contains all the OpenSSL related helpers to wrap
 * functionality of the D language binding provided by the dub module
 * 'openssl'.
 *
 * See: https://github.com/D-Programming-Deimos/openssl
 */
module acme.openssl_helpers;

import deimos.openssl.evp;
import deimos.openssl.pem;
import deimos.openssl.rsa;
import deimos.openssl.x509v3;

import std.conv;
import std.string;
import std.typecons;

import acme.exception;

/* ----------------------------------------------------------------------- */

/** Get the contents of a big number as string
 *
 * Param:
 *  bn - pointer to a big number structure
 * Returns:
 *  a string representing the BIGNUM
 */
string getBigNumber(BIGNUM* bn)
{
	BIO * bio = BIO_new(BIO_s_mem());
	scope(exit) BIO_free(bio);
	BN_print(bio, bn);
	char[2048] buffer;
	auto rc = BIO_gets(bio, buffer.ptr, buffer.length);
	auto num = buffer[0..rc].to!string;
	return num;
}

/** Get the content bytes of a big number as string
 *
 * Param:
 *  bn - pointer to a big number structure
 * Returns:
 *  a string representing the BIGNUM
 */
ubyte[] getBigNumberBytes(const BIGNUM* bn)
{
	/* Get number of bytes to store a BIGNUM */
	int numBytes = BN_num_bytes(bn);
	ubyte[] buffer;
	buffer.length = numBytes;

	/* Copy bytes of BIGNUM to our buffer */
	BN_bn2bin(bn, buffer.ptr);

	return buffer;
}


/* ----------------------------------------------------------------------- */

/** Export BIO contents as an array of chars
 *
 * Param:
 *   bio - pointer to a BIO structure
 * Returns:
 *   An array of chars representing the BIO structure
 */
char[] toVector(BIO * bio)
{
	enum buffSize = 1024;
	char[buffSize] buffer;
	char[] rc;

	int count = 0;
	do
	{
		count = BIO_read(bio, buffer.ptr, buffer.length);
		if (count > 0)
		{
			rc ~= buffer[0..count];
		}
	}
	while (count > 0);

	return rc;
}

/** Export BIO contents as an array of immutable chars (string)
 *
 * Param:
 *   bio - pointer to a BIO structure
 * Returns:
 *   An array of immutable chars representing the BIO structure
 */
string toString(BIO *bio)
{
	char[] v = toVector(bio);
	return to!string(v);
}

/* ----------------------------------------------------------------------- */

/** Encode data as Base64
 *
 * We use openssl to do this since we're already linking to it. As an
 * alternative we could also use the phobos routines.
 *
 * Params:
 *  t - data to encode as base64
 * Returns:
 *  An array of chars with the base64 encoded data.
 */
char[] base64Encode(T)(T t)
	if ( is(T : string) || is(T : char[]) || is(T : ubyte[]))
{
	BIO * bio = BIO_new(BIO_s_mem());
	BIO * b64 = BIO_new(BIO_f_base64());

	// OpenSSL inserts new lines by default to make it look like PEM format.
	// Turn that off.
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	BIO_push(b64, bio);
	if (BIO_write(b64, cast(void*)(t.ptr), t.length.to!int) < 0 ||
		BIO_flush(b64) < 0)
	{
		throw new AcmeException("Can't encode data as base64.");
	}
	return toVector(bio);
}

/** Encode data as URl-safe Base64
 *
 * We need url safe base64 encoding and openssl only gives us regular
 * base64, so we convert it here. Also trim trailing '=' from data
 * (see RFC).
 *
 * The following replacements are done:
 *  * '+' is converted to '-'
 *  * '/' is converted to '_'
 *  * '=' terminates the output at this point, stripping all '=' chars
 *
 * Params:
 *  t - data to encode as base64
 * Returns:
 *  An array of chars with the base64 encoded data.
 */
char[] base64EncodeUrlSafe(T)(T t)
	if ( is(T : string) || is(T : char[]) || is(T : ubyte[]))
{
	/* Do a Standard Base64 Encode */
	char[] s = base64Encode(t);

	/* Do the replacements */
	foreach (i, ref v; s)
	{
		     if (s[i] == '+') { s[i] = '-'; }
		else if (s[i] == '/') {	s[i] = '_';	}
		else if (s[i] == '=') {	s.length = i; break; }
	}
	return s;
}

/** Encode BIGNUM data as URl-safe Base64
 *
 * We need url safe base64 encoding and openssl only gives us regular
 * base64, so we convert it here. Also trim trailing '=' from data
 * (see RFC).
 *
 * The following replacements are done:
 *  * '+' is converted to '-'
 *  * '/' is converted to '_'
 *  * '=' terminates the output at this point, stripping all '=' chars
 *
 * Params:
 *  bn - pointer to BIGNUM to encode as base64
 * Returns:
 *  An array of chars with the base64 encoded data.
 */
char[] base64EncodeUrlSafe(const BIGNUM* bn)
{
	/* Get contents bytes of a BIGNUM */
	ubyte[] buffer = getBigNumberBytes(bn);

	/* Encode the buffer as URL-safe base64 string */
	return base64EncodeUrlSafe(buffer);
}

/** Calculate the SHA256 of a string
 *
 * We use openssl to do this since we're already linking to it. We could
 * also use functions from the phobos library.
 *
 * Param:
 *  s - string to calculate hash from
 * Returns:
 *  ubyte[SHA256_DIGEST_LENGTH] for the hash
 */
ubyte[SHA256_DIGEST_LENGTH] sha256Encode(const char[] s)
{
	ubyte[SHA256_DIGEST_LENGTH] hash;
	SHA256_CTX sha256;
	if (!SHA256_Init(&sha256) ||
		!SHA256_Update(&sha256, s.ptr, s.length) ||
		!SHA256_Final(hash.ptr, &sha256))
	{
		throw new AcmeException("Error hashing string data");
	}
	return hash;
}

/** Convert certificate from DER format to PEM format
 *
 * Params:
 *   der - DER encoded certificate
 * Returns:
 *   a PEM-encoded certificate
 */
string convertDERtoPEM(const char[] der)
{
	/* Write DER to BIO buffer */
	BIO* derBio = BIO_new(BIO_s_mem());
	BIO_write(derBio, cast(const(void)*)der.ptr, der.length.to!int);

	/* Add conversion filter */
	X509* x509 = d2i_X509_bio(derBio, null);

	/* Write DER through filter to as PEM to other BIO buffer */
	BIO* pemBio = BIO_new(BIO_s_mem());
	PEM_write_bio_X509(pemBio, x509);

	/* Output data as data string */
	return toString(pemBio);
}

/** Extract expiry date from a PEM encoded Zertificate
 *
 * Params:
 *  cert - PEM encoded certificate to query
 *  extractor - function or delegate process an ASN1_TIME* argument.
 */
T extractExpiryData(T, alias extractor)(const(char[]) cert)
{
	BIO* bio = BIO_new(BIO_s_mem());
	if (BIO_write(bio, cast(const(void)*) cert.ptr, cert.length.to!int) <= 0)
	{
		throw new AcmeException("Can't write PEM data to BIO struct.");
	}
	X509* x509 = PEM_read_bio_X509(bio, null, null, null);

	ASN1_TIME * t = X509_get_notAfter(x509);

	T rc = extractor(t);
	return rc;
}

/* ----------------------------------------------------------------------- */

/// Return tuple of makeCertificateSigningRequest
alias tupleCsrPkey = Tuple!(string, "csr", string, "pkey");

/** Create a CSR with our domains
 *
 * Params:
 *   domainNames - Names of domains, first element is subject of cert
 * Returns:
 *   tupleCsrPkey containing CSr and PKey
 */
tupleCsrPkey makeCertificateSigningRequest(string[] domainNames)
{
	if (domainNames.length < 1)
	{
		throw new AcmeException("We need at least one domain name.");
	}

	BIGNUM* bn = BN_new();
	if (!BN_set_word(bn, RSA_F4))
	{
		throw new AcmeException("Can't set word.");
	}

	RSA* rsa = RSA_new();
	enum bits = 2048;
	if (!RSA_generate_key_ex(rsa, bits, bn, null))
	{
		throw new AcmeException("Can't generate key.");
	}

	/* Set first element of domainNames as cert CN subject */
	X509_REQ* req = X509_REQ_new();
	auto name = domainNames[0];

	X509_NAME* cn = X509_REQ_get_subject_name(req);
	if (!X509_NAME_add_entry_by_txt(cn,
									"CN",
									MBSTRING_ASC,
									cast(const ubyte*)(name.toStringz),
									-1, -1, 0))
	{
		throw new AcmeException("Can't add CN entry.");
	}

	/* Add other domainName as extension */
	if (domainNames.length > 1)
	{
		// We have multiple Subject Alternative Names
		auto extensions = sk_X509_EXTENSION_new_null();
		if (!extensions)
		{
			throw new AcmeException("Unable to allocate Subject Alternative Name extensions");
		}

		foreach (i, ref v ; domainNames)
		{
			auto cstr = ("DNS:" ~ v).toStringz;
			auto nid = X509V3_EXT_conf_nid(null, null, NID_subject_alt_name, cast(char*)cstr);
			if (!sk_X509_EXTENSION_push(extensions, nid))
			{
				throw new AcmeException("Unable to add Subject Alternative Name to extensions");
			}
		}

		if (X509_REQ_add_extensions(req, extensions) != 1)
		{
			throw new AcmeException("Unable to add Subject Alternative Names to CSR");
		}

		sk_X509_EXTENSION_pop_free(extensions, &X509_EXTENSION_free);
	}

	EVP_PKEY* key = EVP_PKEY_new();
	if (!EVP_PKEY_assign_RSA(key, rsa))
	{
		throw new AcmeException("Can't set RSA key.");
	}
	rsa = null;     // rsa will be freed when key is freed.

	BIO* keyBio = BIO_new(BIO_s_mem());
	if (PEM_write_bio_PrivateKey(keyBio, key, null, null, 0, null, null) != 1)
	{
		throw new AcmeException("Can't set private key.");
	}

	string privateKey = toString(keyBio);

	if (!X509_REQ_set_pubkey(req, key))
	{
		throw new AcmeException("Can't set subkey.");
	}

	if (!X509_REQ_sign(req, key, EVP_sha256()))
	{
		throw new AcmeException("Can't sign.");
	}

	BIO* reqBio = BIO_new(BIO_s_mem());
	if (i2d_X509_REQ_bio(reqBio, req) < 0)
	{
		throw new AcmeException("Can't setup sign request");
	}

	tupleCsrPkey rc = tuple(base64EncodeUrlSafe(toVector(reqBio)).to!string, privateKey);
	return rc;
}

/* ----------------------------------------------------------------------- */

/** Sign a given string with an SHA256 hash
 *
 * Param:
 *  s - string to sign
 *  privateKey - signing key to use
 *
 *  Returns:
 *    A SHA256 signature on provided data
 * See: https://wiki.openssl.org/index.php/EVP_Signing_and_Verifying
 */
char[] signDataWithSHA256(char[] s, EVP_PKEY* privateKey)
{
	size_t signatureLength = 0;

	EVP_MD_CTX* context = EVP_MD_CTX_create();
	const EVP_MD * sha256 = EVP_get_digestbyname("SHA256");
	if ( !sha256 ||
		EVP_DigestInit_ex(context, sha256, null) != 1 ||
		EVP_DigestSignInit(context, null, sha256, null, privateKey) != 1 ||
		EVP_DigestSignUpdate(context, s.toStringz, s.length) != 1 ||
		EVP_DigestSignFinal(context, null, &signatureLength) != 1)
	{
		throw new AcmeException("Error creating SHA256 digest");
	}

	ubyte[] signature;
	signature.length = signatureLength;
	if (EVP_DigestSignFinal(context, signature.ptr, &signatureLength) != 1)
	{
		throw new AcmeException("Error creating SHA256 digest in final signature");
	}

	return base64EncodeUrlSafe(signature);
}

