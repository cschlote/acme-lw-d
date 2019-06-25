/* DI file to call openssl_glues.c code */
module acme.openssl_glues;
extern(C) :

/* SSL Wrapper - C code to directly interface libssl and libcrypto */

/* Library initialisation ------------------------------------------------- */

/** Open and Initialize the OpenSSL library */
void stubSSL_OpenLibrary();
/** Close the OpenSSL library and free resources */
void stubSSL_CloseLibrary();

/* BIO related functions -------------------------------------------------- */

/** Opaque structure for BIO */
struct BIO;
/** Create new BIO with BIO_s_mem argument */
BIO* stubSSL_BIO_new_BIO_s_mem();
/** Get string from BIO */
int stubSSL_BIO_gets(BIO *b, char *buf, int size);
/** Free a BIO */
int stubSSL_BIO_free(BIO *a);
/** Read data fromm a buffer into BIO */
int stubSSL_BIO_read(BIO* bio, void* buffer, int buffer_length);

/* ASN access functions --------------------------------------------------- */

/** Opaque structure */
struct ASN1_TIME;
/** Get a time difference */
int stubSSL_ASN1_TIME_diff(int *pday, int *psec, ASN1_TIME *from, ASN1_TIME *to);
/** Print human readable */
BIO* stubSSL_ASN1_TIME_print(const ASN1_TIME *s);

/* BIGNUM access functions ------------------------------------------------ */

/** Opaque structure */
struct BIGNUM;
/** Print BIGNUM to BIO */
int stubSSL_BN_print(BIO *fp, const BIGNUM *a);
/** Get BIGNUM bytes */
int stubSSL_getBigNumberBytes(const BIGNUM* bn, void* buffer, int buffer_len);

/* RSA access functions --------------------------------------------------- */

/** Opaque structure */
struct RSA;
/** Get RSA keys */
void stubSSL_RSA_Get0_key(RSA*rsa, const BIGNUM** n, const BIGNUM** e, const BIGNUM** d);

/* EVP_PKEY access functions ---------------------------------------------- */

/** Opaque structure */
struct EVP_PKEY;
/** Read PEM encoded key to memory BIO, optionally get RSA part */
EVP_PKEY* stubSSL_EVP_PKEY_readPkeyFromMemory(char* pkeyString, RSA** rsaRef);
/** Create a new pkey */
EVP_PKEY* stubSSL_EVP_PKEY_makePrivateKey(int bits);
/** Free EVP_PKEY */
void stubSSL_EVP_PKEY_free(EVP_PKEY *key);

/* X509_REQ access functions ---------------------------------------------- */

/** Opaque structure */
struct X509_REQ;
/** Create a CSR with the domainNames */
X509_REQ* stubSSL_X509_REQ_makeCSR(EVP_PKEY* pkey, char** domainNames, int domainNamesLength );
/** Get PEM string from X509 CSR */
char* stubSSL_X509_REQ_getAsPEM(X509_REQ* x509_req);
/** Get DER data from X509 CSR */
int stubSSL_X509_REQ_getAsDER(X509_REQ* x509_req, void*b, int blen);

/* X509 access functions -------------------------------------------------- */

/** Get the time for 'notAfter' */
ASN1_TIME * stubSSL_X509_getNotAfter(const char* certPtr, int certLen);

/* Misc higher level functions (move to D module?) ------------------------ */

/** Read EVP_PKEY from file */
EVP_PKEY * stubSSL_EVP_PKEY_readPrivateKey(char* path);

/** Write EVP_PKEY to file */
int stubSSL_EVP_PKEY_writePrivateKey(char* path, EVP_PKEY * pkey);

/** Sign data */
size_t stubSSL_signDataWithSHA256(char* s, int slen, EVP_PKEY* privateKey, char*sig, int siglen);

/** Create a private key FIXME: dubicate? */
char* stubSSL_createPrivateKey(int bits);

/** Convert from DER to PEM */
BIO* stubSSL_convertDERtoPEM(const char* der, int der_length);
