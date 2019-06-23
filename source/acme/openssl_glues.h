
/** Open and Initialize the OpenSSL library */
bool C_SSL_OpenLibrary(void);
/** Close the OpenSSL library and free resources */
void C_SSL_CloseLibrary(void);

/** Opaque structure */
struct BIGNUM;
/** Create new BIGNUM */
BIGNUM *BN_new();
/** Get RSA keys */
void C_RSA_Get0_key(RSA*rsa, const BIGNUM** n, const BIGNUM** e, const BIGNUM** d);
/** Get BIGNUM bytes */
int C_getBigNumberBytes(const BIGNUM* bn, void* buffer, int buffer_len);

/** Opaque structure */
struct EVP_PKEY;
/** Opaque structure */
struct X509_REQ;
/** Create a new pkey */
EVP_PKEY* C_SSL_x509_make_pkey(int bits);
/** Create a CSR with the domainNames */
X509_REQ* C_SSL_x509_make_csr(EVP_PKEY* pkey, char** domainNames, int domainNamesLength );

/** Opaque structure */
struct ASN1_TIME;
/** Get a time difference */
int C_ASN1_TIME_diff(int *pday, int *psec, ASN1_TIME *from, ASN1_TIME *to);
/** Print human readable */
BIO* C_ASN1_TIME_print(const ASN1_TIME *s);

/** Get the time for 'notAfter' */
ASN1_TIME * C_X509_get_notAfter(const char* certPtr, int certLen);

/** Opaque structure */
struct BIO;
/** Create new BIO with BIO_s_mem */
BIO* C_BIO_new_BIO_s_mem();
/** Get string from BIO */
int C_BIO_gets(BIO *b, char *buf, int size);
/** Print BIGNUMBER to BIO */
int C_BN_print(BIO *fp, const BIGNUM *a);
/** Free a BIO */
int C_BIO_free(BIO *a);
/** Read data into BIO */
int C_BIO_read(BIO* bio, void* buffer, int buffer_length);
/** Convert from DER to PEM */
BIO* C_convertDERtoPEM(const char* der, int der_length);

/** Opaque structure */
struct RSA;
/** Read PEM encoded key to memory BIO */
EVP_PKEY* C_SSL_x509_read_pkey_memory(char* pkeyString, RSA** rsaRef);
/** Sign data */
size_t C_signDataWithSHA256(char* s, int slen, EVP_PKEY* privateKey, char*sig, int siglen);

/** Get PEM string from X509 CSR */
char* C_SSL_x509_get_PEM(X509_REQ* x509_req);
/** Get DER data from X509 CSR */
int C_SSL_x509_get_DER(X509_REQ* x509_req, void*b, int blen);

/** Write EVP_PKEY to file */
int C_SSL_x509_write_pkey(char* path, EVP_PKEY * pkey);
/** Read EVP_PKEY from file */
EVP_PKEY * C_SSL_x509_read_pkey(char* path);
/** Free EVP_PKEY */
void C_EVP_PKEY_free(EVP_PKEY *key);

/** Create a private key FIXME: dubicate? */
char* C_openSSL_CreatePrivateKey(int bits);



