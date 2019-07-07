
/** Small helpers for openssl
 *
 * This module contains all the OpenSSL related helpers to wrap
 * functionality of the D language binding provided by the dub module
 * 'openssl'.
 *
 * See: https://github.com/D-Programming-Deimos/openssl
 *
 * Note:
 *   The D binding seem to be outdated or otherwise broken. At least some
 *   code only works in C. That's why a C stub was added. However, the code
 *   is still available in D below in hope that things can be fixed later.
 */
module acme.openssl_helpers;

import std.conv;
import std.string;
import std.typecons;

import acme.exception;

/* ----------------------------------------------------------------------- */

/** Get the contents of a big number as string
 *
 * Param:
 *  bn = pointer to a big number structure
 * Returns:
 *  a string representing the BIGNUM
 */
string getBigNumber(BIGNUM* bn)
{
	BIO * bio = stubSSL_BIO_new_BIO_s_mem();
	scope(exit) stubSSL_BIO_free(bio);
	stubSSL_BN_print(bio, bn);
	char[2048] buffer;
	auto rc = stubSSL_BIO_gets(bio, buffer.ptr, buffer.length);
	auto num = buffer[0..rc].to!string;
	return num;
}

/** Get the content bytes of a big number as string
 *
 * Param:
 *  bn = pointer to a big number structure
 * Returns:
 *  a string representing the BIGNUM
 */
ubyte[] getBigNumberBytes(const BIGNUM* bn)
{
	/* Get number of bytes to store a BIGNUM */
	ubyte[2048] buffer;
	auto numBytes = stubSSL_getBigNumberBytes(bn, cast(void*)buffer.ptr, buffer.length);
	return buffer[0..numBytes].dup;
}


/* ----------------------------------------------------------------------- */

/** Export BIO contents as an array of chars
 *
 * Param:
 *   bio = pointer to a BIO structure
 * Returns:
 *   An array of chars representing the BIO structure
 */
char[] toVector(BIO * bio)
{
	enum uint buffSize = 1024;
	char[buffSize] buffer;
	char[] rc;

	int count = 0;
	do
	{
		count = stubSSL_BIO_read(bio, buffer.ptr, buffer.length);
		if (count > 0)
		{
			rc ~= buffer[0..count];
		}
	}
	while (count > 0);

	return rc;
}



/* ----------------------------------------------------------------------- */

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
 *  t = data to encode as base64
 * Returns:
 *  An array of chars with the base64 encoded data.
 */
char[] base64EncodeUrlSafe(T)(T t)
	if ( is(T : string) || is(T : char[]) || is(T : ubyte[]))
{
	static if (is(T : ubyte[])) {
		import std.base64 : Base64URLNoPadding;
		auto s = Base64URLNoPadding.encode(t);
	} else {
	    ubyte[] tt = (cast(ubyte*)t.ptr)[0..t.length];
		import std.base64 : Base64URLNoPadding;
		auto s = Base64URLNoPadding.encode(tt);
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
 *  bn = pointer to BIGNUM to encode as base64
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
 *  s = string to calculate hash from
 * Returns:
 *  ubyte[SHA256_DIGEST_LENGTH] for the hash
 */
auto sha256Encode(const char[] s)
{
	import std.digest.sha : sha256Of;
	return sha256Of(s);
}

/** Convert certificate from DER format to PEM format
 *
 * Params:
 *   der = DER encoded certificate
 * Returns:
 *   a PEM-encoded certificate
 */
string convertDERtoPEM(const char[] der)
{
	BIO* pemBio = stubSSL_convertDERtoPEM(der.ptr, der.length.to!int);
	/* Output data as data string */
	return cast(string)(toVector(pemBio));
}

/** Extract expiry date from a PEM encoded Zertificate
 *
 * Params:
 *  cert = PEM encoded certificate to query
 *  extractor = function or delegate process an ASN1_TIME* argument.
 */
T extractExpiryData(T, alias extractor)(const(char[]) cert)
{
	ASN1_TIME * t = stubSSL_X509_getNotAfter(cert.ptr, cert.length.to!int);
	T rc = extractor(t);
	return rc;
}

/* ----------------------------------------------------------------------- */

/** Sign a given string with an SHA256 hash
 *
 * Param:
 *  s = string to sign
 *  privateKey = signing key to use
 *
 *  Returns:
 *    A SHA256 signature on provided data
 * See: https://wiki.openssl.org/index.php/EVP_Signing_and_Verifying
 */
char[] signDataWithSHA256(char[] s, EVP_PKEY* privateKey)
{
	char[1024] sig;
	auto rc = stubSSL_signDataWithSHA256(s.ptr, s.length.to!int, privateKey, sig.ptr, sig.length.to!int);
	if (rc == 0)
	{
		throw new AcmeException("Error creating SHA256 digest in final signature");
	}
	return base64EncodeUrlSafe(sig[0..rc]);
}

version (HAS_WORKING_SSL)
{
	/** Initialize SSL library
	 *
	 * Do any kind of initialization here.
	 * Returns:
	 *   true or false
	 */
	bool SSL_OpenLibrary()
	{
		/* Load the human readable error strings for libcrypto */
		OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, null);

		/* Load all digest and cipher algorithms */
		//OpenSSL_add_all_algorithms(); // Is a macro for
		OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS
						  | OPENSSL_INIT_ADD_ALL_DIGESTS
						  | OPENSSL_INIT_LOAD_CONFIG, null);
		return true;
	}

	/** Teardown SSL library
	 *
	 * Reverse anything done in SSL_OpenLibrary().
	 */
	void SSL_CloseLibrary()
	{
		/* Clean up */
		OPENSSL_cleanup();
	}

	/* http://stackoverflow.com/questions/256405/programmatically-create-x509-certificate-using-openssl
	 * http://www.codepool.biz/how-to-use-openssl-to-generate-x-509-certificate-request.html
	 */

	/** Make a x509 pkey
	 *
	 * Create a RSA private keys with 2048 bits
	 * Returns: pointer to EVP_PKEY structure
	 * @internal
	 */
	EVP_PKEY* SSL_x509_make_pkey(int bits = 4096)
	{
		EVP_PKEY * pkey;
		pkey = EVP_PKEY_new();
		RSA * rsa;
		rsa = RSA_generate_key(
				bits,   /* number of bits for the key - 2048 is a sensible value */
				RSA_F4, /* exponent - RSA_F4 is defined as 0x10001L */
				null,   /* callback - can be null if we aren't displaying progress */
				null    /* callback argument - not needed in this case */
			);
		EVP_PKEY_assign_RSA(pkey, rsa);
		return pkey;
	}


	/** Add extension using V3 code: we can set the config file as null
	 * because we wont reference any other sections.
	 *
	 * Params:
	 *   sk = pointer to STACK_OF(X509_EXTENSION
	 *   nid = Extention ID
	 *   value = value of nid
	 * Returns:
	 * 	  bool_t: 0 == False, !=0 True
	 */
	private
	bool add_req_ext(STACK_OF!X509_EXTENSION *sk, int nid, string value)
	{
		X509_EXTENSION *ex;
		ex = X509V3_EXT_conf_nid(cast(LHASH_OF!(CONF_VALUE)*)null, cast(v3_ext_ctx*)null, nid, cast(char*)value.toStringz);
		if (!ex)
			return false;
		sk_X509_EXTENSION_push(sk, ex);
		return true;
	}

	/** Make a x509 CSR (cert signing request)
	 * @param pkey pointer to pkey struct to store
	 * @param dev_serial pointer to device serial string
	 * Returns: pointer to X509_REQ structure
	 */
	X509_REQ* SSL_x509_make_csr(EVP_PKEY* pkey, string[] domainNames)
	{
		assert(domainNames.length >= 1, "No domain names given.");
		auto cnStr = domainNames[0].toStringz;
		string[] extStrs; extStrs.length = domainNames.length - 1;

		X509_REQ * x509_req;
		x509_req = X509_REQ_new();
		assert(x509_req.req_info !is null, "The allocated X509_REQ* has req_info member set to NULL. This shouldn't be.");

		X509_REQ_set_version(x509_req, 1);
		X509_REQ_set_pubkey(x509_req, pkey);

		X509_NAME * name;
		name = X509_REQ_get_subject_name(x509_req);
		assert (name !is null, "Can't read the req subject name struct.");

		/* Setup some fields for the CSR */
		version(none) {
			X509_NAME_add_entry_by_txt(name, cast(char*)("ST".ptr), MBSTRING_ASC, cast(ubyte*)("Niedersachsen".ptr), -1, -1, 0);
			X509_NAME_add_entry_by_txt(name, cast(char*)("L".ptr),  MBSTRING_ASC, cast(ubyte*)("Hannover".ptr), -1, -1, 0);
			X509_NAME_add_entry_by_txt(name, cast(char*)("OU".ptr), MBSTRING_ASC, cast(ubyte*)("IT".ptr), -1, -1, 0);
			X509_NAME_add_entry_by_txt(name, cast(char*)("O".ptr),  MBSTRING_ASC, cast(ubyte*)("Vahanus ".ptr), -1, -1, 0);
			X509_NAME_add_entry_by_txt(name, cast(char*)("C".ptr),  MBSTRING_ASC, cast(ubyte*)("DE".ptr), -1, -1, 0);
			X509_NAME_add_entry_by_txt(name, cast(char*)("CN".ptr), MBSTRING_ASC, cast(ubyte*)(dev_serial.toStringz), -1, -1, 0);
		}
		X509_NAME_add_entry_by_txt(name, cast(char*)("CN".ptr), MBSTRING_ASC, cast(ubyte*)(cnStr), -1, -1, 0);
		/* Add other domainName as extension */
		if (domainNames.length > 1)
		{
			// We have multiple Subject Alternative Names
			auto extensions = sk_X509_EXTENSION_new_null();
			if (extensions is null) {
				throw new AcmeException("Unable to allocate Subject Alternative Name extensions");
			}
			foreach (i, ref v ; domainNames[1..$])
			{
				auto cstr = ("DNS:" ~ v).toStringz;
				auto nid = X509V3_EXT_conf_nid(null, null, NID_subject_alt_name, cast(char*)cstr);
				if (!sk_X509_EXTENSION_push(extensions, nid)) {
					throw new AcmeException("Unable to add Subject Alternative Name to extensions");
				}
			}
			if (X509_REQ_add_extensions(x509_req, extensions) != 1) {
				throw new AcmeException("Unable to add Subject Alternative Names to CSR");
			}
			sk_X509_EXTENSION_pop_free(extensions, &X509_EXTENSION_free);
		}

		/* Code below might BREAK acception of CSR at ACME server. Leave it out for now. */
		version(none) {
			STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null();

			// # Extensions for client certificates (`man x509v3_config`).
			// basicConstraints = CA:FALSE
			// nsCertType = client, email
			// nsComment = "OpenSSL Generated Client Certificate"
			// subjectKeyIdentifier = hash
			// authorityKeyIdentifier = keyid,issuer
			// keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
			// extendedKeyUsage = clientAuth, emailProtection

			/* Add various extensions: standard extensions */
			add_req_ext(exts, NID_basic_constraints, "CA:FALSE");
			add_req_ext(exts, NID_key_usage, "critical, nonRepudiation, digitalSignature, keyEncipherment");
			add_req_ext(exts, NID_ext_key_usage, "clientAuth, emailProtection");
			add_req_ext(exts, NID_subject_key_identifier, "hash");
			add_req_ext(exts, NID_authority_key_identifier, "keyid,issuer");

			/* Some Netscape specific extensions */
			add_req_ext(exts, NID_netscape_cert_type, "client, email");
			add_req_ext(exts, NID_netscape_comment, "OpenSSL Generated Client Certificate");

			X509_REQ_add_extensions(x509_req, exts);

			sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
		}

		/* Sign the CSR with our PKEY */
		X509_REQ_sign(x509_req, pkey, EVP_sha1());
		return x509_req;
	}


}
else
{
	/* Here we import the autogenerated DI file for the C module */
	import std.stdint;
	import acme.openssl_glues;

	/** Initialize library */
	void SSL_OpenLibrary()
	{
		stubSSL_OpenLibrary();
	}
	/** Close library */
	void SSL_CloseLibrary()
	{
		stubSSL_CloseLibrary();
	}
	/** Make a private key */
	EVP_PKEY* SSL_x509_make_pkey(int bits)
	{
		return stubSSL_EVP_PKEY_makePrivateKey(bits);
	}
	/** Make a CSR */
	X509_REQ* SSL_x509_make_csr(EVP_PKEY* pkey, string[] domainNames)
	{
		char*[] C_domainNames;
		C_domainNames.length =  domainNames.length;
		foreach(i, ref v; domainNames) C_domainNames[i] = cast(char*)v.toStringz;
		return stubSSL_X509_REQ_makeCSR(pkey, cast(char**)(C_domainNames.ptr), domainNames.length.to!int);
	}
}



/** Get a CSR as PEM string */
char[] SSL_x509_get_PEM(X509_REQ* x509_req)
{
	char* rs = stubSSL_X509_REQ_getAsPEM(x509_req);
	import std.string : fromStringz;
	return rs.fromStringz;
}

/** Get a CSR as base64url-encoded DER string */
char[] SSL_x509_get_DER_as_B64URL(X509_REQ* x509_req)
{
	ubyte[2048] b;
	auto rc = stubSSL_X509_REQ_getAsDER(x509_req, b.ptr, b.length.to!int);
	char[] rs = base64EncodeUrlSafe(b[0..rc]);
	return rs;
}

/** Read a x509 pkey pem string from memory
 */
EVP_PKEY* SSL_x509_read_pkey_memory(const char[] pkeyString, RSA** rsaRef)
{
	auto cstr = cast(char*)pkeyString.toStringz;
	return stubSSL_EVP_PKEY_readPkeyFromMemory(cstr, rsaRef);
}

/** Save a x509 pkey to a file
 * @param path pathname of file to write
 * @param pkey pointer to pkey struct to store
 * Returns: return value of PEM_write_PrivateKey()
 * @internal
 */
int SSL_x509_write_pkey(char[] path, EVP_PKEY * pkey)
{
	return stubSSL_EVP_PKEY_writePrivateKey( cast(char*)(path.toStringz), pkey);
}

/** Read a x509 pkey from a file
 * @param path pathname of file to read
 * Returns: pointer to EVP_PKEY, return value of PEM_write_PrivateKey()
 * @internal
 */
EVP_PKEY * SSL_x509_read_pkey(char[] path)
{
	return stubSSL_EVP_PKEY_readPrivateKey(cast(char*)(path.toStringz));
}


/* ------------------------------------------------------------------------ */

/** Create a SSL private key
 *
 * This functions creates an EVP_PKEY with 2048 bits. It's returned as
 * PEM encoded text.
 *
 * Returns:
 * 		pointer to pem encoded string containing EVP_PKEY private key.
 */
char[] openSSL_CreatePrivateKey(int bits = 4096)
{
	//import std.stdio;
	//writeln("Create a SSL pKey.");
	char[] rs;
	char* cs = stubSSL_createPrivateKey(bits);
	rs = cs.fromStringz;
	return rs;
}
unittest {
	import std.stdio : writeln, writefln, stdout, stderr;
	import std.datetime.stopwatch : benchmark;

	/* Test Key Generation */
	writeln("Testing the SSL routines ported from C");
	writeln("--- Create a private key ---");
	stdout.flush;
	char[] myPKey = openSSL_CreatePrivateKey();
	writeln("Got the following from library:\n", myPKey);
	stdout.flush;

	/* Benchmark Key Generation */
	writeln("--- Benchmark creating a private key ---");
	stdout.flush;
	void benchCreateKeyStub() {
		const char[] tmp = openSSL_CreatePrivateKey();
		assert(tmp !is null && !tmp.empty, "Empty private key.");
	}
	auto dur = benchmark!(benchCreateKeyStub)(100);
	writeln("Benchmarking 100 calls, duration ", dur);
	stdout.flush;
}

/** Create a SSL cert signing request from a pkey and a serial number
 *
 * This functions creates an CertificateSignRequest (CSR) with 2048 bits.
 * It's returned as PEM encoded text.
 *
 * Params:
 *   prkey = private key as PEM string
 *   domainNames = same custom data, e.g. a serial number
 * Returns:
 *   pointer to bas64url encoded DER data! See RFC.
 */
char[] openSSL_CreateCertificateSignRequest(const char[] prkey, string[] domainNames)
{
	/* Get EVP_PKEY from PEM encoded string */
	EVP_PKEY* pkey;
	RSA* rsa;
	pkey = SSL_x509_read_pkey_memory(prkey, &rsa);

	/* Create CSR from private key and serial number */

	X509_REQ* x509_req = SSL_x509_make_csr(pkey, domainNames);
	assert (x509_req !is null, "Returned empty cert req.");

	/* Convert to PEM string */
	auto pemStr = SSL_x509_get_PEM(x509_req);
	import std.stdio : writeln;
	writeln("CSR(PEM):", pemStr);

	/* Convert to DER with base64url-encoded data */
	auto rs = SSL_x509_get_DER_as_B64URL(x509_req);
	stubSSL_EVP_PKEY_free(pkey);
	return rs;
}
unittest {
	import std.stdio : writeln, writefln, stdout, stderr;
	import std.datetime.stopwatch : benchmark;

	/* Test Key Generation */
	writeln("Testing the CSR-creation routines ported from C");
	writeln("--- Create a private key ---");
	stdout.flush;
	char[] myPKey = openSSL_CreatePrivateKey();
	writeln("Got the following from library:\n", myPKey);
	stdout.flush;
	char[] myCSR = openSSL_CreateCertificateSignRequest(myPKey, [ "bodylove.myds.me" ]);
	writeln("Got the following CSR from library:\n", myCSR);

	/* Benchmark CSR Generation */
	writeln("--- Benchmark creating a CSR ---");
	stdout.flush;
	void benchCreateCSRStub() {
		const char[] tmp = openSSL_CreateCertificateSignRequest(myPKey, [ "bodylove.myds.me" ]);
		assert(tmp !is null && !tmp.empty, "Empty CSR.");
	}
	auto dur = benchmark!(benchCreateCSRStub)(100);
	writeln("Benchmarking 100 calls, duration ", dur);
	stdout.flush;
}

/* ------------------------------------------------------------------------ */

