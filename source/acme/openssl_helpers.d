
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

import deimos.openssl.conf;
import deimos.openssl.evp;
import deimos.openssl.err;
import deimos.openssl.pem;
import deimos.openssl.x509;
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

extern(C) ASN1_TIME * C_X509_get_notAfter(const char* certPtr, int certLen);

/** Extract expiry date from a PEM encoded Zertificate
 *
 * Params:
 *  cert - PEM encoded certificate to query
 *  extractor - function or delegate process an ASN1_TIME* argument.
 */
T extractExpiryData(T, alias extractor)(const(char[]) cert)
{
	ASN1_TIME * t = C_X509_get_notAfter(cert.ptr, cert.length.to!int);
/+ Code below works in C, but not in D (yet).
	BIO* bio = BIO_new(BIO_s_mem());
	if (BIO_write(bio, cast(const(void)*) cert.ptr, cert.length.to!int) <= 0)
	{
		throw new AcmeException("Can't write PEM data to BIO struct.");
	}
	X509* x509 = PEM_read_bio_X509(bio, null, null, null);

	ASN1_TIME * t = X509_get_notAfter(x509);
+/
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
	if (domainNames.length < 1) {
		throw new AcmeException("We need at least one domain name.");
	}

	BIGNUM* bn = BN_new();
	if (!BN_set_word(bn, RSA_F4)) {
		throw new AcmeException("Can't set word.");
	}
	EVP_PKEY * pkey;
	pkey = EVP_PKEY_new();

	RSA* rsa = RSA_new();
	enum bits = 2048;
	if (!RSA_generate_key_ex(rsa, bits, bn, null))
	{
		throw new AcmeException("Can't generate key.");
	}
	EVP_PKEY_assign_RSA(pkey, rsa);

	/* Set first element of domainNames as cert CN subject */
	X509_REQ* x509_req = X509_REQ_new();
	auto name = domainNames[0];

	X509_REQ_set_version(x509_req, 1);
	X509_REQ_set_pubkey(x509_req, pkey);

	X509_NAME* cn = X509_REQ_get_subject_name(x509_req);
	assert (cn !is null, "Can get X509_REQ_get_subject_name");
	auto rc_cn = X509_NAME_add_entry_by_txt(
				cn,
				"CN",
				MBSTRING_ASC,
				cast(const ubyte*)(name.toStringz),
				-1, -1, 0);
	if (!rc_cn)
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

		if (X509_REQ_add_extensions(x509_req, extensions) != 1) {
			throw new AcmeException("Unable to add Subject Alternative Names to CSR");
		}

		sk_X509_EXTENSION_pop_free(extensions, &X509_EXTENSION_free);
	}

	// EVP_PKEY* key = EVP_PKEY_new();
	// if (!EVP_PKEY_assign_RSA(key, rsa))
	// {
	// 	throw new AcmeException("Can't set RSA key.");
	// }
	//rsa = null;     // rsa will be freed when key is freed.

	BIO* keyBio = BIO_new(BIO_s_mem());
	if (PEM_write_bio_PrivateKey(keyBio, pkey, null, null, 0, null, null) != 1) {
		throw new AcmeException("Can't copy private key to BIO.");
	}
	string privateKey = toString(keyBio);

	if (!X509_REQ_set_pubkey(x509_req, pkey)) {
		throw new AcmeException("Can't set subkey.");
	}

	if (!X509_REQ_sign(x509_req, pkey, EVP_sha256())) {
		throw new AcmeException("Can't sign.");
	}

	BIO* reqBio = BIO_new(BIO_s_mem());
	if (i2d_X509_REQ_bio(reqBio, x509_req) < 0)	{
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

	EVP_MD_CTX* context = EVP_MD_CTX_new();
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

	/** Add extension using V3 code: we can set the config file as null,
	 * because we wont reference any other sections.
	 * @param cert pointer to X509 cert
	 * @param nid Extention ID
	 * @param value value of nid
	 * Returns: bool_t: 0 == False, !=0 True
	 */
	private bool add_ext(X509* cert, int nid, char[] value)
	{
		X509_EXTENSION *ex;
		X509V3_CTX ctx;
		/* This sets the 'context' of the extensions. */
		/* No configuration database */
		X509V3_set_ctx_nodb(&ctx);
		/* Issuer and subject certs: both the target since it is self signed,
		 * no request and no CRL
		 */
		X509V3_set_ctx(&ctx, cert, cert, null, null, 0);
		ex = X509V3_EXT_conf_nid(cast(LHASH_OF!(CONF_VALUE)*)null, &ctx, nid, cast(char*)value.toStringz);
		if (!ex)
			return false;

		X509_add_ext(cert, ex, -1);
		X509_EXTENSION_free(ex);
		return true;
	}

	/** Make a x509 cert
	 *
	 * Creates a X509 Zertifikate with direkt library calls.
	 * @param pkey pointer to pkey struct to store
	 * @param dev_serial pointer to device serial string
	 * Returns: pointer to selfsigned x509 structure
	 * @todo Add leica fields to x509 cert
	 * @todo Add error handling to X509 Cert creation code.
	 * @internal
	 */
	X509* SSL_x509_make_cert(EVP_PKEY* pkey, char[] dev_serial)
	{
		X509 * x509;
		x509 = X509_new();

		ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

		X509_gmtime_adj(X509_get_notBefore(x509), 0); // now!
		X509_gmtime_adj(X509_get_notAfter(x509), 50 * 31536000L); // 99 years

		X509_set_pubkey(x509, pkey);

		X509_NAME * name;
		name = X509_get_subject_name(x509);

		X509_NAME_add_entry_by_txt(name, cast(char*)("ST".ptr),  MBSTRING_ASC, cast(ubyte*)("Niedersachsen".ptr), -1, -1, 0);
		X509_NAME_add_entry_by_txt(name, cast(char*)("L".ptr),  MBSTRING_ASC, cast(ubyte*)("Hannover".ptr), -1, -1, 0);
		//OU Filed BREAKS precessing of CSR on LCG. Also see CON-289 - keep info at minimum for reduced size
		//X509_NAME_add_entry_by_txt(name, "OU",  MBSTRING_ASC, (unsigned char *)"IT", -1, -1, 0);
		X509_NAME_add_entry_by_txt(name, cast(char*)("O".ptr),  MBSTRING_ASC, cast(ubyte*)("Vahanus ".ptr), -1, -1, 0);
		X509_NAME_add_entry_by_txt(name, cast(char*)("C".ptr),  MBSTRING_ASC, cast(ubyte*)("DE".ptr), -1, -1, 0);
		X509_NAME_add_entry_by_txt(name, cast(char*)("CN".ptr), MBSTRING_ASC, cast(ubyte*)(dev_serial.toStringz), -1, -1, 0);

		X509_set_issuer_name(x509, name);

		/* Add various extensions: standard extensions */
		add_ext(x509, NID_basic_constraints, "critical,CA:TRUE".dup);
		add_ext(x509, NID_key_usage, "critical,keyCertSign,cRLSign".dup);

		add_ext(x509, NID_subject_key_identifier, "hash".dup);

		/* Some Netscape specific extensions */
		add_ext(x509, NID_netscape_cert_type, "sslCA".dup);

		add_ext(x509, NID_netscape_comment, "example comment extension".dup);

		version(none) {
			/* Maybe even add our own extension based on existing */
			{
				int nid;
				nid = OBJ_create("1.2.3.4", "MyAlias", "My Test Alias Extension");
				X509V3_EXT_add_alias(nid, NID_netscape_comment);
				add_ext(x509, nid, "example comment alias");
			}
		}
		X509_sign(x509, pkey, EVP_sha1());
		return x509;
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
			X509_NAME_add_entry_by_txt(name, cast(char*)("ST".ptr),  MBSTRING_ASC, cast(ubyte*)("Niedersachsen".ptr), -1, -1, 0);
			X509_NAME_add_entry_by_txt(name, cast(char*)("L".ptr),  MBSTRING_ASC, cast(ubyte*)("Hannover".ptr), -1, -1, 0);
			//OU Filed BREAKS precessing of CSR on LCG. Also see CON-289 - keep info at minimum for reduced size
			//X509_NAME_add_entry_by_txt(name, "OU",  MBSTRING_ASC, (unsigned char *)"IT", -1, -1, 0);
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

		/* Code below BREAKS acception of CSR at LCG. Also see CON-289 - minimize cert size, leave it out. */
		version(hasExtentions) {
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
	/* Sick of broken D binding for OpenSSL, I used the stub approach -
	 * just compile it as C and call the functions */

	extern(C) bool C_SSL_OpenLibrary();
	bool SSL_OpenLibrary()
	{
		return C_SSL_OpenLibrary();
	}
	extern(C) void C_SSL_CloseLibrary();
	void SSL_CloseLibrary()
	{
		C_SSL_CloseLibrary();
	}
	extern(C) EVP_PKEY* C_SSL_x509_make_pkey(int bits);
	EVP_PKEY* SSL_x509_make_pkey(int bits)
	{
		return C_SSL_x509_make_pkey(bits);
	}
	extern(C) bool C_add_ext(X509* cert, int nid, char* value);
	private bool add_ext(X509* cert, int nid, char[] value)
	{
		return C_add_ext(cert, nid, cast(char*)(value.toStringz));
	}
	extern(C) X509* C_SSL_x509_make_cert(EVP_PKEY* pkey, char* subject);
	X509* SSL_x509_make_cert(EVP_PKEY* pkey, char[] subject)
	{
		return C_SSL_x509_make_cert(pkey, cast(char*)(subject.toStringz));
	}
	extern(C) X509_REQ* C_SSL_x509_make_csr(EVP_PKEY* pkey, char** domainNames, int domainNamesLength);
	X509_REQ* SSL_x509_make_csr(EVP_PKEY* pkey, string[] domainNames)
	{
		char*[] C_domainNames;
		C_domainNames.length =  domainNames.length;
		foreach(i, ref v; domainNames) C_domainNames[i] = cast(char*)v.toStringz;
		return C_SSL_x509_make_csr(pkey, cast(char**)(C_domainNames.ptr), domainNames.length.to!int);
	}
}


/++
/* Code below commented out, obsolete function */
/** Add extension using V3 code: we can set the config file as null
 * because we wont reference any other sections.
 * @param sk pointer to STACK_OF(X509_EXTENSION
 * @param nid Extention ID
 * @param value value of nid
 * Returns: bool_t: 0 == False, !=0 True
 * @internal
 */
static
bool_t add_req_ext(STACK_OF(X509_EXTENSION) *sk, int nid, cstring_p value)
{
	X509_EXTENSION *ex;
	ex = X509V3_EXT_conf_nid(null, null, nid, value);
	if (!ex)
		return False;
	sk_X509_EXTENSION_push(sk, ex);
	return True;
}
++/

/** Get a CSR as PEM string */
char[] SSL_x509_get_PEM(X509_REQ* x509_req)
{
	BUF_MEM* mem;
	BIO* bio = BIO_new(BIO_s_mem());
	PEM_write_bio_X509_REQ(bio, x509_req);
	BIO_get_mem_ptr(bio, &mem);
	if (null == mem)  {
		return null;
	}
	//cstring_p rs = strndup(mem->data, mem->length);
	char[] rs = mem.data[0..mem.length].dup;
	BIO_free(bio);
	return rs;
}

/** Get a CSR as base64url-encoded DER string */
char[] SSL_x509_get_DER_as_B64URL(X509_REQ* x509_req)
{
	BIO* reqBio = BIO_new(BIO_s_mem());
	if (i2d_X509_REQ_bio(reqBio, x509_req) < 0)	{
		throw new AcmeException("Can't convert CSR to DER.");
	}
	char[] rs = cast(char[])base64EncodeUrlSafe(toVector(reqBio)).to!string;
	BIO_free(reqBio);
	return rs;
}

/** Read a x509 pkey pem string from memory
 */
EVP_PKEY* SSL_x509_read_pkey_memory(const char[] pkeyString, RSA** rsaRef = null)
{
	auto cstr = cast(void*)pkeyString.toStringz;
	EVP_PKEY* privateKey = EVP_PKEY_new();

	BIO* bio = BIO_new_mem_buf(cstr, -1);
	RSA* rsa = PEM_read_bio_RSAPrivateKey(bio, null, null, null);
	if (!rsa) {
		throw new AcmeException("Unable to read private key");
	}
	// rsa will get freed when privateKey_ is freed
	auto rc = !EVP_PKEY_assign_RSA(privateKey, rsa);
	if (rc) {
		throw new AcmeException("Unable to assign RSA to private key");
	}
	if (rsaRef) *rsaRef = rsa;
	return privateKey;
}

/** Save a x509 pkey to a file
 * @param path pathname of file to write
 * @param pkey pointer to pkey struct to store
 * Returns: return value of PEM_write_PrivateKey()
 * @internal
 */
int SSL_x509_write_pkey(char[] path, EVP_PKEY * pkey)
{
	import core.stdc.stdio;
	int rc = -1;
	FILE * f;
	if (path is null) path = "key.pem".dup;
	f = fopen(cast(char*)(path.toStringz), cast(char*)("wb".toStringz));
	if (f !is null) {
		alias cbt = extern(C) int function(char*, int, int, void*);
		rc = PEM_write_PrivateKey(
		        f,                  /* write the key to the file we've opened */
		        pkey,               /* our key from earlier */
		        EVP_des_ede3_cbc(), /* default cipher for encrypting the key on disk */
		        cast(ubyte*)("replace_me".ptr),                /* passphrase required for decrypting the key on disk */
		        10,                                            /* length of the passphrase string */
		        cast(cbt)null,      /* callback for requesting a password */
		        cast(void*)null     /* data to pass to the callback */
		    );
		fclose(f);
	}
	return rc;
}

/** Read a x509 pkey from a file
 * @param path pathname of file to read
 * Returns: pointer to EVP_PKEY, return value of PEM_write_PrivateKey()
 * @internal
 */
EVP_PKEY * SSL_x509_read_pkey(char[] path)
{
	import core.stdc.stdio;
	EVP_PKEY * pkey;
	pkey = EVP_PKEY_new();
	FILE * f;
	if (path is null) path = "key.pem".dup;
	f = fopen(cast(char*)(path.toStringz), cast(char*)("rb".ptr));
	if (f !is null) {
		pkey = PEM_read_PrivateKey(
		        f,                  /* read the key to the file we've opened */
		        &pkey,              /* our key from earlier */
		        null,               /* callback for requesting a password */
		        null                /* data to pass to the callback */
		    );
		fclose(f);
	}
	return pkey;
}

/** Save a x509 cert to a file
 * @param path pathname of file to write
 * @param x509 pointer to x509 struct to store
 * Returns: return value of PEM_write_X509()
 * @internal
 */
int  SSL_x509_write_cert(char[] path, X509* x509)
{
	import core.stdc.stdio;
	int rc = -1;
	FILE * f;
	if (path is null) path = "cert.pem".dup;
	f = fopen(cast(char*)(path.toStringz), cast(char*)("wb".ptr));
	if (f !is null) {
		rc = PEM_write_X509(
		        f,   /* write the certificate to the file we've opened */
		        x509 /* our certificate */
		    );
		fclose(f);
	}
	return rc;
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
	import std.stdio;
	//writeln("Create a SSL pKey.");
	char[] rs;

	EVP_PKEY * pkey = SSL_x509_make_pkey(bits);
	if (null == pkey) {
		stderr.writeln("Can't create a pKey");
	} else {
		BIO *bio = BIO_new(BIO_s_mem());
		if (null == bio) {
			stderr.writeln("Can't create a BIO");
		} else {
			alias cbt = extern(C) int function(char*, int, int, void*);
			int rc = PEM_write_bio_PrivateKey(bio, pkey,
				cast(const(evp_cipher_st)*)null,
				cast(ubyte*)null, 0,
				cast(cbt)null, cast(void*)null);
			if (!rc) {
				stderr.writeln("Can't write pKEY to BIO");
			} else {
				BUF_MEM *mem;
				BIO_get_mem_ptr(bio, &mem);
				if (null == mem)  {
					stderr.writeln("Can't get pointer to BUF_MEM from BIO");
				} else {
					if (mem.data !is null)
						rs = mem.data[0..mem.length];
					if (rs is null || rs.empty)  {
						stderr.writeln("Can't get data from BIO");
					} else {
						rs = (rs).dup;
					}
				}
			}
			BIO_free(bio);
		}
		EVP_PKEY_free(pkey);
	}
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
		char[] tmp = openSSL_CreatePrivateKey();
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
 *   prkey - private key as PEM string
 *   serial - same custom data, e.g. a serial number
 * Returns:
 *   ERROR: pointer to pem encoded string of CSR.
 *   CORRECT: pointer to bas64url encoded DER data! See RFC.
 */
char[] openSSL_CreateCertificateSignRequest(const char[] prkey, string[] domainNames)
{
	BIO *bio;
	int rc;

	//HACK
	const char[] prkey2 = openSSL_CreatePrivateKey();

	/* Get EVP_PKEY from PEM encoded string */
	EVP_PKEY* pkey;
	//pkey = SSL_x509_read_pkey_memory(prkey);
	pkey = SSL_x509_read_pkey_memory(prkey2);

	/* Create CSR from private key and serial number */

	X509_REQ* x509_req = SSL_x509_make_csr(pkey, domainNames);
	assert (x509_req !is null, "Returned empty cert req.");

//	/* Convert to PEM string */
//	auto rs = SSL_x509_get_PEM(x509_req);

	/* Convert to DER data */
	auto rs = SSL_x509_get_DER_as_B64URL(x509_req);
	EVP_PKEY_free(pkey);
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
		char[] tmp = openSSL_CreateCertificateSignRequest(myPKey, [ "bodylove.myds.me" ]);
		assert(tmp !is null && !tmp.empty, "Empty CSR.");
	}
	auto dur = benchmark!(benchCreateCSRStub)(100);
	writeln("Benchmarking 100 calls, duration ", dur);
	stdout.flush;
}

/* ------------------------------------------------------------------------ */

