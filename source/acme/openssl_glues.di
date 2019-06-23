module acme.openssl_glues;
extern(C) :

bool C_SSL_OpenLibrary();
void C_SSL_CloseLibrary();

struct BIGNUM;
int C_getBigNumberBytes(const BIGNUM* bn, void* buffer, int buffer_len);
void C_RSA_Get0_key(RSA*rsa, const BIGNUM** n, const BIGNUM** e, const BIGNUM** d);
BIGNUM *BN_new();

EVP_PKEY* C_SSL_x509_make_pkey(int bits);

struct EVP_PKEY;
struct X509_REQ;
X509_REQ* C_SSL_x509_make_csr(EVP_PKEY* pkey, char** domainNames, int domainNamesLength );

struct ASN1_TIME;
ASN1_TIME * C_X509_get_notAfter(char* certPtr, int certLen);

struct BIO;
BIO* C_BIO_new_BIO_s_mem();
int C_BIO_gets(BIO *b, char *buf, int size);
int C_BN_print(BIO *fp, const BIGNUM *a);
int C_BIO_free(BIO *a);
int C_BIO_read(BIO* bio, void* buffer, int buffer_length);
BIO* C_convertDERtoPEM(const char* der, int der_length);

struct EVP_MD_CTX;
EVP_MD_CTX* C_EVP_MD_CTX_new();

struct RSA;
EVP_PKEY* C_SSL_x509_read_pkey_memory(char* pkeyString, RSA** rsaRef);

int C_ASN1_TIME_diff(int *pday, int *psec, ASN1_TIME *from, ASN1_TIME *to);
BIO* C_ASN1_TIME_print(const ASN1_TIME *s);

size_t C_signDataWithSHA256(char* s, int slen, EVP_PKEY* privateKey, char*sig, int siglen);

char* C_SSL_x509_get_PEM(X509_REQ* x509_req);
int C_SSL_x509_get_DER(X509_REQ* x509_req, void*b, int blen);

int C_SSL_x509_write_pkey(char* path, EVP_PKEY * pkey);
EVP_PKEY * C_SSL_x509_read_pkey(char* path);

char* C_openSSL_CreatePrivateKey(int bits);

void C_EVP_PKEY_free(EVP_PKEY *key);


