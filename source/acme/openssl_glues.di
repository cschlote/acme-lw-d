module acme.openssl_glues;
import deimos.openssl.conf;
import deimos.openssl.evp;
import deimos.openssl.err;
import deimos.openssl.pem;
import deimos.openssl.x509;
import deimos.openssl.x509v3;
extern(C) :

bool C_SSL_OpenLibrary(void);
void C_SSL_CloseLibrary(void);

EVP_PKEY* C_SSL_x509_make_pkey();

bool C_add_ext(X509* cert, int nid, char* value);
X509* C_SSL_x509_make_cert(EVP_PKEY* pkey, char* subject);

bool C_add_req_ext(STACK_OF(X509_EXTENSION) *sk, int nid, char* value);
X509_REQ* C_SSL_x509_make_csr(EVP_PKEY* pkey, char** domainNames, int domainNamesLength );

ASN1_TIME * C_X509_get_notAfter(char* certPtr, int certLen);

