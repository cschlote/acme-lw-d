
/* This is a stub C file to call OpenSSL
 *
 * This file is needed, because the OpenSSL bindings seem to be  broken or
 * outdated. At least it wasn't possible to get it working, and
 * a lot of time was wasted with the D binding.
 *
 * At the final end, this stub file was created in less than
 * a quarter hour. It surely matches the installed version of
 * OpenSSL on your system - it's in C and it uses the installed C header
 * files.
 *
 * To put it into other words, which even follow the D philosophie:
 * "There is no need to rewrite a well-written C, C++ or ObjC
 *  library. Just call that code."
 *
 * Unfortunatelly OpenSSL is an example, where the headers are
 * very sophisticated work using lots of C prepro macros to do
 * fascinating things. Too bad, it's forming an own 'language'
 * that way, is hard to parse and understand - even for human
 * beings. Manually maintaining a D-binding instead is very tedious work -
 * and prone to errors of all kind.
 *
 * For such situations it might be more useful to write the
 * interface code in C using the headers as they are. Then
 * call the functions of your C wrapper from D. The prototypes to these C
 * functions can be defined in D and called as needed.
 *
 * This approach saves a lot of time: It can use examples from the
 * OpenSSL manual, it can decode und use the headers directly and without
 * any coversions, an finally also emits 'depricated' notes as rhe libssl
 * API evolves over time.
 */

/* C Runtime Includes - use C99 types please for interfacing with D */

#include <assert.h>
#include <string.h>

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Include the magic OpenSSL headerfiles as needed */

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

/* Include our interface header to check protype against code below */

#include "openssl_glues.h"

/* Library initialisation ------------------------------------------------- */

void stubSSL_OpenLibrary(void)
{
	/* Load the human readable error strings for libcrypto */
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);

	/* Load all digest and cipher algorithms */
	// OpenSSL_add_all_algorithms(); // Is a macro for
	OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS | OPENSSL_INIT_LOAD_CONFIG, NULL);
}

void stubSSL_CloseLibrary(void)
{
	OPENSSL_cleanup();
}

/* BIO related functions -------------------------------------------------- */

BIO *stubSSL_BIO_new_BIO_s_mem()
{
	return BIO_new(BIO_s_mem());
}

int stubSSL_BIO_gets(BIO *b, char *buf, int size)
{
	return BIO_gets(b, buf, size);
}

int stubSSL_BIO_free(BIO *a)
{
	return BIO_free(a);
}

int stubSSL_BIO_read(BIO *bio, void *buffer, int buffer_length)
{
	return BIO_read(bio, buffer, buffer_length);
}

/* ASN access functions --------------------------------------------------- */

int stubSSL_ASN1_TIME_diff(int *pday, int *psec, ASN1_TIME *from, ASN1_TIME *to)
{
	return ASN1_TIME_diff(pday, psec, from, to);
}

BIO *stubSSL_ASN1_TIME_print(const ASN1_TIME *s)
{
	BIO *b = BIO_new(BIO_s_mem());
	assert(ASN1_TIME_print(b, s));
	return b;
}

time_t stubSSL_ASN1_GetTimeT(const ASN1_TIME *time)
{
	struct tm t;
	const char *str = (const char *)time->data;
	size_t i = 0;

	memset(&t, 0, sizeof(t));

	if (time->type == V_ASN1_UTCTIME)
	{ /* two digit year */
		t.tm_year = (str[i++] - '0') * 10;
		t.tm_year += (str[i++] - '0');
		if (t.tm_year < 70)
			t.tm_year += 100;
	}
	else if (time->type == V_ASN1_GENERALIZEDTIME)
	{ /* four digit year */
		t.tm_year = (str[i++] - '0') * 1000;
		t.tm_year += (str[i++] - '0') * 100;
		t.tm_year += (str[i++] - '0') * 10;
		t.tm_year += (str[i++] - '0');
		t.tm_year -= 1900;
	}
	t.tm_mon = (str[i++] - '0') * 10;
	t.tm_mon += (str[i++] - '0') - 1; // -1 since January is 0 not 1.
	t.tm_mday = (str[i++] - '0') * 10;
	t.tm_mday += (str[i++] - '0');
	t.tm_hour = (str[i++] - '0') * 10;
	t.tm_hour += (str[i++] - '0');
	t.tm_min = (str[i++] - '0') * 10;
	t.tm_min += (str[i++] - '0');
	t.tm_sec = (str[i++] - '0') * 10;
	t.tm_sec += (str[i++] - '0');

	/* Note: we did not adjust the time based on time zone information */
	return mktime(&t);
}

/* BIGNUM access functions ------------------------------------------------ */

int stubSSL_BN_print(BIO *fp, const BIGNUM *a)
{
	return BN_print(fp, a);
}

int stubSSL_getBigNumberBytes(const BIGNUM *bn, void *buffer, int buffer_len)
{
	/* Get number of bytes to store a BIGNUM */
	int numBytes = BN_num_bytes(bn);

	assert(numBytes <= buffer_len);

	/* Copy bytes of BIGNUM to our buffer */
	BN_bn2bin(bn, buffer);

	return numBytes;
}

/* RSA access functions --------------------------------------------------- */

#if OPENSSL_VERSION_NUMBER < 0x30000000L
void stubSSL_RSA_Get0_key(RSA *rsa, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
	RSA_get0_key(rsa, n, e, d);
}
#else
void stubSSL_RSA_Get0_key(EVP_PKEY *pkey, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
    // Ensure the EVP_PKEY contains an RSA key
    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA) {
        *n = NULL;
        *e = NULL;
        *d = NULL;
        return;
    }

    // Initialize the BIGNUM pointers to NULL
    *n = NULL;
    *e = NULL;
    *d = NULL;

    // Retrieve the 'n' component of the RSA key
    if (EVP_PKEY_get_bn_param(pkey, "n", (BIGNUM **)n) <= 0) {
        return;
    }

    // Retrieve the 'e' component of the RSA key
    if (EVP_PKEY_get_bn_param(pkey, "e", (BIGNUM **)e) <= 0) {
        BN_free((BIGNUM *)*n);
        *n = NULL;
        return;
    }

    // Retrieve the 'd' component of the RSA key, if available
    if (EVP_PKEY_get_bn_param(pkey, "d", (BIGNUM **)d) <= 0) {
        // 'd' may be NULL if this is a public key
        *d = NULL;
    }
}
#endif

/* EVP_PKEY access functions ---------------------------------------------- */

EVP_PKEY *stubSSL_EVP_PKEY_readPkeyFromMemory(char *pkeyString, RSA **rsaRef)
{
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	EVP_PKEY *privateKey = EVP_PKEY_new();
	BIO *bio = BIO_new_mem_buf(pkeyString, -1);
	RSA *rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
	assert(rsa != NULL);
	// rsa will get freed when privateKey_ is freed
	EVP_PKEY_assign_RSA(privateKey, rsa);
	if (rsaRef)
		*rsaRef = rsa;
	return privateKey;
#else
    EVP_PKEY *privateKey = NULL;
    BIO *bio = NULL;

    // Create a new BIO with the given key string
    bio = BIO_new_mem_buf(pkeyString, -1);
    if (!bio) {
        return NULL;
    }

    // Read private key from BIO
    privateKey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!privateKey) {
        BIO_free(bio);
        return NULL;
    }

    // Free BIO
    BIO_free(bio);

    return privateKey;
#endif
}

EVP_PKEY *stubSSL_EVP_PKEY_makePrivateKey(int bits)
{
#if OPENSSL_VERSION_NUMBER < 0x30000000L

	BIGNUM *e = BN_new();
	if (!BN_set_word(e, RSA_F4))
	{
		return NULL;
	}
	RSA *rsa = RSA_new();
	int rc = RSA_generate_key_ex(rsa,
								 bits, /* number of bits for the key - 2048 is a sensible value */
								 e,	   /* callback - can be NULL if we aren't displaying progress */
								 NULL  /* callback argument - not needed in this case */
	);
	if (!rc)
		return NULL;
	BN_free(e);
	e = NULL;

	EVP_PKEY *pkey;
	pkey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(pkey, rsa);
	return pkey;
#else
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *ctx = NULL;

	// Create context for key generation
	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	if (!ctx)
	{
		// Error handling
		return NULL;
	}

	// Generate key
	if (EVP_PKEY_keygen_init(ctx) <= 0)
	{
		// Error handling
		EVP_PKEY_CTX_free(ctx);
		return NULL;
	}

	if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0)
	{
		// Error handling
		EVP_PKEY_CTX_free(ctx);
		return NULL;
	}

	if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
	{
		// Error handling
		EVP_PKEY_CTX_free(ctx);
		return NULL;
	}

	// Clean up
	EVP_PKEY_CTX_free(ctx);

	return pkey;
#endif
}

void stubSSL_EVP_PKEY_free(EVP_PKEY *pkey)
{
	EVP_PKEY_free(pkey);
}

/* X509_REQ access functions ---------------------------------------------- */

bool stubSSL_addReqExt(STACK_OF(X509_EXTENSION) * sk, int nid, char *value)
{
	X509_EXTENSION *ex;
	ex = X509V3_EXT_conf_nid(NULL, NULL, nid, value);
	if (!ex)
		return false;
	sk_X509_EXTENSION_push(sk, ex);
	return true;
}

X509_REQ *stubSSL_X509_REQ_makeCSR(EVP_PKEY *pkey, char **domainNames, int domainNamesLength)
{
	char *cnStr = domainNames[0];

	X509_REQ *x509_req;
	x509_req = X509_REQ_new();

	X509_REQ_set_version(x509_req, 1);
	X509_REQ_set_pubkey(x509_req, pkey);

	X509_NAME *name;
	name = X509_REQ_get_subject_name(x509_req);
	assert(name != NULL);

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
		assert(extensions != NULL);

		for (int i = 0; i < domainNamesLength; i++)
		{
			char buffer[512];
			memset(buffer, 0, sizeof(buffer));
			strncat(buffer, "DNS:", sizeof(buffer) - 1);
			strncat(buffer, domainNames[i], sizeof(buffer) - 1);

			X509_EXTENSION *nid = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, buffer);
			assert(sk_X509_EXTENSION_push(extensions, nid));
		}
		assert(X509_REQ_add_extensions(x509_req, extensions));
		sk_X509_EXTENSION_pop_free(extensions, &X509_EXTENSION_free);
	}

#if 0
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
//	stubSSL_addReqExt(exts, NID_basic_constraints, "CA:FALSE");
//	stubSSL_addReqExt(exts, NID_key_usage, "critical, nonRepudiation, digitalSignature, keyEncipherment");
//	stubSSL_addReqExt(exts, NID_ext_key_usage, "clientAuth, emailProtection");
//	stubSSL_addReqExt(exts, NID_subject_key_identifier, "hash");
//	stubSSL_addReqExt(exts, NID_authority_key_identifier, "keyid,issuer");

	/* Some Netscape specific extensions */
//	stubSSL_addReqExt(exts, NID_netscape_cert_type, "client, email");
	stubSSL_addReqExt(exts, NID_netscape_comment, "OpenSSL Generated Client Certificate");

	X509_REQ_add_extensions(x509_req, exts);

	sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
#endif

	/* Sign the CSR with our PKEY */
	X509_REQ_sign(x509_req, pkey, EVP_sha1());
	return x509_req;
}

char *stubSSL_X509_REQ_getAsPEM(X509_REQ *x509_req)
{
	BIO *bio = BIO_new(BIO_s_mem());
	PEM_write_bio_X509_REQ(bio, x509_req);

	BUF_MEM *mem;
	BIO_get_mem_ptr(bio, &mem);
	if (NULL == mem)
	{
		return NULL;
	}
	char *rs = strndup(mem->data, mem->length);
	BIO_free(bio);
	return rs;
}

int stubSSL_X509_REQ_getAsDER(X509_REQ *x509_req, void *b, int blen)
{
	int length = 0;
	BIO *reqBio = BIO_new(BIO_s_mem());
	if (i2d_X509_REQ_bio(reqBio, x509_req) < 0)
	{
		return 0;
	}
	BUF_MEM *mem;
	BIO_get_mem_ptr(reqBio, &mem);
	length = mem->length;
	// printf("mem->length = %lx, blen = %x\n\n", mem->length, blen); fflush(stdout);
	assert(mem->length <= blen);
	memcpy(b, mem->data, mem->length);
	BIO_free(reqBio);
	return length;
}

/* X509 access functions -------------------------------------------------- */

ASN1_TIME *stubSSL_X509_getNotAfter(const char *certPtr, int certLen)
{
	BIO *bio = BIO_new(BIO_s_mem());
	if (BIO_write(bio, certPtr, certLen) <= 0)
		return NULL;
	X509 *x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);

	ASN1_TIME *t = X509_get_notAfter(x509);
	BIO_free(bio);
	return t;
}

/* Misc higher level functions (move to D module?) ------------------------ */

EVP_PKEY *stubSSL_EVP_PKEY_readPrivateKey(char *path)
{
	EVP_PKEY *pkey;
	pkey = EVP_PKEY_new();
	FILE *f;
	if (path == NULL)
		path = "key.pem";
	f = fopen(path, "rb");
	if (f != NULL)
	{
		pkey = PEM_read_PrivateKey(
			f,	   /* read the key to the file we've opened */
			&pkey, /* our key from earlier */
			NULL,  /* callback for requesting a password */
			NULL   /* data to pass to the callback */
		);
		fclose(f);
	}
	return pkey;
}

int stubSSL_EVP_PKEY_writePrivateKey(char *path, EVP_PKEY *pkey)
{
	int rc = -1;
	FILE *f;
	if (path == NULL)
		path = "key.pem";
	f = fopen(path, "wb");
	if (f != NULL)
	{
		rc = PEM_write_PrivateKey(
			f,					/* write the key to the file we've opened */
			pkey,				/* our key from earlier */
			EVP_des_ede3_cbc(), /* default cipher for encrypting the key on disk */
			NULL,				/* passphrase required for decrypting the key on disk */
			0,					/* length of the passphrase string */
			NULL,				/* callback for requesting a password */
			NULL				/* data to pass to the callback */
		);
		fclose(f);
	}
	return rc;
}

size_t stubSSL_signDataWithSHA256(char *s, int slen, EVP_PKEY *privateKey, char *sig, int siglen)
{
	size_t signatureLength = 0;
	EVP_MD_CTX *context = EVP_MD_CTX_new();
	const EVP_MD *sha256 = EVP_get_digestbyname("SHA256");
	if (!sha256 ||
		EVP_DigestInit_ex(context, sha256, NULL) != 1 ||
		EVP_DigestSignInit(context, NULL, sha256, NULL, privateKey) != 1 ||
		EVP_DigestSignUpdate(context, s, slen) != 1 ||
		EVP_DigestSignFinal(context, NULL, &signatureLength) != 1)
	{
		return 0;
	}

	if (signatureLength > siglen ||
		EVP_DigestSignFinal(context, (unsigned char *)sig, &signatureLength) != 1)
	{
		return 0;
	}
	return signatureLength;
}

char *stubSSL_createPrivateKey(int bits)
{
	char *rs = NULL;

	EVP_PKEY *pkey = stubSSL_EVP_PKEY_makePrivateKey(bits);
	if (NULL == pkey)
	{
		puts("Can't create a pKey");
	}
	else
	{
		BIO *bio = BIO_new(BIO_s_mem());
		if (NULL == bio)
		{
			puts("Can't create a BIO");
		}
		else
		{
			int rc = PEM_write_bio_PrivateKey(bio, pkey,
											  NULL,
											  NULL, 0,
											  NULL, NULL);
			if (!rc)
			{
				puts("Can't write pKEY to BIO");
			}
			else
			{
				BUF_MEM *mem;
				BIO_get_mem_ptr(bio, &mem);
				if (NULL == mem)
				{
					puts("Can't get pointer to BUF_MEM from BIO");
				}
				else
				{
					if (mem->data != NULL)
						rs = strndup(mem->data, mem->length);
					if (rs == NULL || strlen(rs) == 0)
					{
						puts("Can't get data from BIO");
					}
					else
					{
						rs = rs;
					}
				}
			}
			BIO_free(bio);
		}
		EVP_PKEY_free(pkey);
	}
	return rs;
}

BIO *stubSSL_convertDERtoPEM(const char *der, int der_length)
{
	/* Write DER to BIO buffer */
	BIO *derBio = BIO_new(BIO_s_mem());
	BIO_write(derBio, der, der_length);

	/* Add conversion filter */
	X509 *x509 = d2i_X509_bio(derBio, NULL);

	/* Write DER through filter to as PEM to other BIO buffer */
	BIO *pemBio = BIO_new(BIO_s_mem());
	PEM_write_bio_X509(pemBio, x509);

	/* Output data as data string */
	return pemBio;
}
