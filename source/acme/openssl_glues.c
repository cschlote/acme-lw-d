
/* This is a stub C file to call OpenSSL
 *
 * This file is needed, because the OpenSSL bindings seem to
 * broken. At least it wasn't possible to get it working, and
 * a lot of time was wasted with the D binding.
 *
 * At the final end, this stub file was created in less than
 * a quarter hour. It surely matches the installed version of
 * OpenSSL on your system.
 *
 * To put it into other, which even follow the D philosophie:
 * "There is no need to rewrite a well-written C, C++ or ObjC
 *  library. Just call that code."
 *
 * Unfortunatelly OpenSSL is an example, where the Header are
 * very sophisticated work using lots of C prepro macros to do
 * fascinating things. Too bad, it's forming an own 'language'
 * that way, is hard to parse and understand - even for human
 * beings.
 *
 * For such situations it might be more useful to write the
 * interface code in C using the headers as they are. Then
 * call the functions of your C wrapper from D.
 *
 * This approach saves a lot of time, can use examples from the
 * manual.
 */

/* C Runtime Includes - use C99 types */
#include <assert.h>
#include <string.h>

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Include the magic OpenSSL headerfiles as needed */
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

/* Include our interface header to check against code below */
#include "openssl_glues.h"

/* Initialize SSL library */
bool C_SSL_OpenLibrary(void)
{
	/* Load the human readable error strings for libcrypto */
	//ERR_load_crypto_strings();  // OBSOLETE???
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);

	/* Load all digest and cipher algorithms */
	//OpenSSL_add_all_algorithms(); // Is a macro for
	OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS
                      | OPENSSL_INIT_ADD_ALL_DIGESTS
                      | OPENSSL_INIT_LOAD_CONFIG, NULL);
	return true;
}

/* Teardown SSL library */
void C_SSL_CloseLibrary(void)
{
	/* Clean up */
	OPENSSL_cleanup();
}

/** Make a x509 pkey */
EVP_PKEY* C_SSL_x509_make_pkey(int bits)
{
	BIGNUM* e = BN_new();
	if (!BN_set_word(e, RSA_F4)) {
		return NULL;
	}
	RSA * rsa = RSA_new();
	int rc = RSA_generate_key_ex(rsa,
			bits,   /* number of bits for the key - 2048 is a sensible value */
			e,   /* callback - can be NULL if we aren't displaying progress */
			NULL    /* callback argument - not needed in this case */
		);
	if (!rc) return NULL;
	BN_free(e); e = NULL;

	EVP_PKEY * pkey;
	pkey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(pkey, rsa);
	return pkey;
}

/* Add extension using V3 code: we can set the config file as NULL,
 * because we wont reference any other sections.
 */
bool C_add_ext(X509* cert, int nid, char* value)
{
	X509_EXTENSION *ex;
	X509V3_CTX ctx;
	/* This sets the 'context' of the extensions. */
	/* No configuration database */
	X509V3_set_ctx_nodb(&ctx);
	/* Issuer and subject certs: both the target since it is self signed,
	 * no request and no CRL
	 */
	X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
	ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
	if (!ex)
		return false;

	X509_add_ext(cert, ex, -1);
	X509_EXTENSION_free(ex);
	return true;
}

/** Make a x509 cert */
X509* C_SSL_x509_make_cert(EVP_PKEY* pkey, char* subject)
{
	X509 * x509;
	x509 = X509_new();

	ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

	X509_gmtime_adj(X509_get_notBefore(x509), 0); // now!
	X509_gmtime_adj(X509_get_notAfter(x509), 50 * 31536000L); // 99 years

	X509_set_pubkey(x509, pkey);

	X509_NAME * name;
	name = X509_get_subject_name(x509);

	X509_NAME_add_entry_by_txt(name, "ST",  MBSTRING_ASC, (unsigned char *)"Niedersachsen", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "L" ,  MBSTRING_ASC, (unsigned char *)"Hannover", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "OU",  MBSTRING_ASC, (unsigned char *)"IT", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O" ,  MBSTRING_ASC, (unsigned char *)"Vahanus ", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "C" ,  MBSTRING_ASC, (unsigned char *)"DE", -1, -1, 0);

	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)subject, -1, -1, 0);

	X509_set_issuer_name(x509, name);

	/* Add various extensions: standard extensions */
	C_add_ext(x509, NID_basic_constraints, "critical,CA:TRUE");
	C_add_ext(x509, NID_key_usage, "critical,keyCertSign,cRLSign");

	C_add_ext(x509, NID_subject_key_identifier, "hash");

	/* Some Netscape specific extensions */
	C_add_ext(x509, NID_netscape_cert_type, "sslCA");

	C_add_ext(x509, NID_netscape_comment, "example comment extension");

#if 1
	/* Maybe even add our own extension based on existing */
	{
		int nid;
		nid = OBJ_create("1.2.3.4", "MyAlias", "My Test Alias Extension");
		X509V3_EXT_add_alias(nid, NID_netscape_comment);
		C_add_ext(x509, nid, "example comment alias");
	}
#endif
	X509_sign(x509, pkey, EVP_sha1());
	return x509;
}

bool C_add_req_ext(STACK_OF(X509_EXTENSION) *sk, int nid, char* value)
{
	X509_EXTENSION *ex;
	ex = X509V3_EXT_conf_nid(NULL, NULL, nid, value);
	if (!ex)
		return false;
	sk_X509_EXTENSION_push(sk, ex);
	return true;
}

/* Make a x509 CSR (cert signing request) */
X509_REQ* C_SSL_x509_make_csr(EVP_PKEY* pkey, char** domainNames, int domainNamesLength )
{
	char *cnStr = domainNames[0];

	X509_REQ * x509_req;
	x509_req = X509_REQ_new();

	X509_REQ_set_version(x509_req, 1);
	X509_REQ_set_pubkey(x509_req, pkey);

	X509_NAME * name;
	name = X509_REQ_get_subject_name(x509_req);
	assert (name != NULL);

	/* Setup some fields for the CSR */
#if 0
	X509_NAME_add_entry_by_txt(name, "ST",  MBSTRING_ASC, (unsigned char *)"Niedersachsen", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "L" ,  MBSTRING_ASC, (unsigned char *)"Hannover", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "OU",  MBSTRING_ASC, (unsigned char *)"IT", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O" ,  MBSTRING_ASC, (unsigned char *)"Vahanus ", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "C" ,  MBSTRING_ASC, (unsigned char *)"DE", -1, -1, 0);
#endif
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)cnStr, -1, -1, 0);
	/* Add other domainName as extension */
	if (domainNamesLength > 1)
	{
		// We have multiple Subject Alternative Names
		STACK_OF(X509_EXTENSION) *extensions = sk_X509_EXTENSION_new_null();
		assert( extensions != NULL );

		for (int i = 0; i < domainNamesLength; i++)
		{
			char buffer[512]; memset(buffer, 0, sizeof(buffer));
			strncat(buffer,"DNS:", sizeof(buffer));
			strncat(buffer,domainNames[i], sizeof(buffer));

			X509_EXTENSION *nid = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, buffer);
			assert(!sk_X509_EXTENSION_push(extensions, nid));
		}
		assert (X509_REQ_add_extensions(x509_req, extensions) != 1);
		sk_X509_EXTENSION_pop_free(extensions, &X509_EXTENSION_free);
	}

#if 1
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
//	C_add_req_ext(exts, NID_basic_constraints, "CA:FALSE");
//	C_add_req_ext(exts, NID_key_usage, "critical, nonRepudiation, digitalSignature, keyEncipherment");
//	C_add_req_ext(exts, NID_ext_key_usage, "clientAuth, emailProtection");
//	C_add_req_ext(exts, NID_subject_key_identifier, "hash");
//	C_add_req_ext(exts, NID_authority_key_identifier, "keyid,issuer");

	/* Some Netscape specific extensions */
//	C_add_req_ext(exts, NID_netscape_cert_type, "client, email");
	C_add_req_ext(exts, NID_netscape_comment, "OpenSSL Generated Client Certificate");

	X509_REQ_add_extensions(x509_req, exts);

	sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
#endif

	/* Sign the CSR with our PKEY */
	X509_REQ_sign(x509_req, pkey, EVP_sha1());
	return x509_req;
}


ASN1_TIME * C_X509_get_notAfter(char* certPtr, int certLen)
{
	BIO* bio = BIO_new(BIO_s_mem());
	if (BIO_write(bio, certPtr, certLen) <= 0)
		return NULL;
	X509* x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);

	ASN1_TIME * t = X509_get_notAfter(x509);
	BIO_free(bio);
	return t;
}

