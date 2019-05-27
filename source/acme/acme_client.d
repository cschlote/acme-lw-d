
/** Simple client for ACME protocol */
module acme.acme_client;

import std.conv;
import std.datetime;
import std.json;
import std.net.curl;
import std.string;
import std.typecons;

import etc.c.curl;

import deimos.openssl.evp;
import deimos.openssl.pem;
import deimos.openssl.rsa;
import deimos.openssl.x509v3;

import acme.exception;

version (STAGING)
	string directoryUrl = "https://acme-staging.api.letsencrypt.org/directory";
else
	string directoryUrl = "https://acme-v01.api.letsencrypt.org/directory";

/** An openssl certificate */
struct Certificate
{
	string fullchain;
	string privkey;

	// Note that neither of the 'Expiry' calls below require 'privkey'
	// to be set; they only rely on 'fullchain'.

	/**
		Returns the number of seconds since 1970, i.e., epoch time.

		Due to openssl quirkiness there might be a little drift
		from a strictly accurate result, but it should be close
		enough for the purpose of determining whether the certificate
		needs to be renewed.
	*/
	DateTime getExpiry() const
	{
		static const(DateTime) extractor(const ASN1_TIME * t)
		{
			// See this link for issues in converting from ASN1_TIME to epoch time.
			// https://stackoverflow.com/questions/10975542/asn1-time-to-time-t-conversion

			int days, seconds;
			//~ extern(C) int ASN1_TIME_diff(int *pday, int *psec, const ASN1_TIME *from, const ASN1_TIME *to);
			//~ if (!ASN1_TIME_diff(&days, &seconds, null, t))
			//~ {
				//~ throw new AcmeException("Can't get time diff.");
			//~ }
			// Hackery here, since the call to time(0) will not necessarily match
			// the equivilent call openssl just made in the 'diff' call above.
			// Nonetheless, it'll be close at worst.
			auto dt = DateTime( Date(0) );
			dt += dur!"seconds"(seconds + days * 3600 * 24);
			return dt;
		}
	  	return extractExpiryData!(DateTime, extractor)(this);
	}

	/** Returns the 'Not After' result that openssl would display if
		running the following command.

			openssl x509 -noout -in fullchain.pem -text

		For example:

			May  6 21:15:03 2018 GMT
	*/
	string getExpiryDisplay() const
	{
		string extractor(const ASN1_TIME * t)
		{
			BIO* b = BIO_new(BIO_s_mem());
			if (!ASN1_TIME_print(b, t))
			{
				throw new AcmeException("Can't print expiry time.");
			}
			return toString(b);
		}
		return extractExpiryData!(string, extractor)(this);
	}
}

/** A simple ACME client */
class AcmeClient
{
public:
	/**
		The signingKey is the Acme account private key used to sign
		requests to the acme CA, in pem format.
	*/
	this(string signingKey)
	{
		impl_ = new AcmeClientImpl(signingKey);
	}

	/**
		The implementation of this function allows Let's Encrypt to
		verify that the requestor has control of the domain name.

		The callback may be called once for each domain name in the
		'issueCertificate' call. The callback should do whatever is
		needed so that a GET on the 'url' returns the 'keyAuthorization',
		(which is what the Acme protocol calls the expected response.)

		Note that this function may not be called in cases where
		Let's Encrypt already believes the caller has control
		of the domain name.
	*/
	alias Callback =  void function (  string domainName,
								string url,
								string keyAuthorization);

	/**
		Issue a certificate for the domainNames.
		The first one will be the 'Subject' (CN) in the certificate.

		throws std::exception, usually an instance of AcmeException
	*/
	Certificate issueCertificate(string[] domainNames, Callback callback)
	{
		return impl_.issueCertificate(domainNames, callback);
	}

	// Call once before instantiating AcmeClient.
	static void init()
	{
		//initHttp();
		try
		{
			char[] directory = get(directoryUrl);
			auto json = parseJSON(directory);
			newAuthZUrl = json["new-authz"].str;
			newCertUrl = json["new-cert"].str;
		}
		catch (Exception e)
		{
			throw new AcmeException("Unable to initialize endpoints from " ~ directoryUrl ~ ": " ~ e.msg);
		}
	}

	// Call once before application shutdown.
	static void teardown()
	{
		//teardownHttp();
	}
private:
	AcmeClientImpl* impl_;
}


string newAuthZUrl;
string newCertUrl;

//// Smart pointers for OpenSSL types
//template<typename TYPE, void (*FREE)(TYPE *)>
//struct Ptr
//{
//	Ptr()
//		: ptr_(null)
//	{
//	}
//
//	Ptr(TYPE * ptr)
//		: ptr_(ptr)
//	{
//		if (!ptr_)
//		{
//			throw acme.AcmeException("Out of memory?");
//		}
//	}
//
//	~Ptr()
//	{
//		if (ptr_)
//		{
//			FREE(ptr_);
//		}
//	}
//
//	Ptr& operator = (Ptr&& ptr)
//	{
//		if (!ptr.ptr_)
//		{
//			throw acme.AcmeException("Out of memory?");
//		}
//
//		ptr_ = move(ptr.ptr_);
//		ptr.ptr_ = null;
//
//		return *this;
//	}
//
//	bool operator ! () const
//	{
//		return !ptr_;
//	}
//
//	TYPE * operator * () const
//	{
//		return ptr_;
//	}
//
//	void clear()
//	{
//		ptr_ = null;
//	}
//
//private:
//	TYPE * ptr_;
//};
//
//typedef Ptr<BIO, BIO_free_all>                                  BIOptr;
//typedef Ptr<RSA, RSA_free>                                      RSAptr;
//typedef Ptr<BIGNUM, BN_clear_free>                              BIGNUMptr;
//typedef Ptr<EVP_MD_CTX, EVP_MD_CTX_free>                        EVP_MD_CTXptr;
//typedef Ptr<EVP_PKEY, EVP_PKEY_free>                            EVP_PKEYptr;
//typedef Ptr<X509, X509_free>                                    X509ptr;
//typedef Ptr<X509_REQ, X509_REQ_free>                            X509_REQptr;

//template<typename T>
//T toT(const vector<char>& v)
//{
//	return v;
//}
//
//template<>
//string toT(const vector<char>& v)
//{
//	return string(&v.front(), v.size());
//}

char[] toVector(BIO * bio)
{
	enum buffSize = 1024;
	char[buffSize] buffer;
	char[] rc;

	int count = 0;
	do
	{
		count = BIO_read(bio, buffer.ptr, buffSize);
		if (count > 0)
		{
			rc ~= buffer[0..count];
		}
	}
	while (count > 0);

	return rc;
}

auto toString(BIO *bio)
{
	char[] v = toVector(bio);
	return to!string(v);
}

char[] base64Encode(T)(ref T t)
{
	// Use openssl to do this since we're already linking to it.

	// Don't need (or want) a BIOptr since BIO_push chains it to b64
	BIO * bio = BIO_new(BIO_s_mem());
	BIO * b64 = BIO_new(BIO_f_base64());

	// OpenSSL inserts new lines by default to make it look like PEM format.
	// Turn that off.
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	BIO_push(b64, bio);
	if (BIO_write(b64, cast(void*)(&t), t.sizeof.to!int) <= 0 ||
		BIO_flush(b64) < 0)
	{
		throw new AcmeException("Can't encode into base64.");
	}
	return toVector(bio);
}

char[] urlSafeBase64Encode(T)(T t)
{
	char[] s = base64Encode(t);

	// We need url safe base64 encoding and openssl only gives us regular
	// base64, so we convert.
	const size_t len = s.length;
	for (size_t i = 0; i < len; ++i)
	{
		if (s[i] == '+')
		{
			s[i] = '-';
		}
		else if (s[i] == '/')
		{
			s[i] = '_';
		}
		else if (s[i] == '=')
		{
			s.length = i;
			break;
		}
	}
	return s;
}

// Url safe encoding
char[] urlSafeBase64Encode(const BIGNUM * bn)
{
	int numBytes = BN_num_bytes(bn);
	ubyte[] buffer;
	buffer.length = numBytes;
	BN_bn2bin(bn, buffer.ptr);

	return urlSafeBase64Encode(buffer);
}

// returns pair<CSR, privateKey>
Tuple!(string, string) makeCertificateSigningRequest(string[] domainNames)
{
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

	if (domainNames.length > 1)
	{
		// We have multiple Subject Alternative Names
		auto extensions = sk_X509_EXTENSION_new_null();
		if (!extensions)
		{
			throw new AcmeException("Unable to allocate Subject Alternative Name extensions");
		}

		for (int i = 1; i < domainNames.length; i++)
		{
			name = domainNames[i];
			auto cstr = ("DNS:" ~ name).toStringz;
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

	return tuple(urlSafeBase64Encode(toVector(reqBio)).to!string, privateKey);
}

// Convert certificate from DER format to PEM format
char[] DERtoPEM(char[] der)
{
	BIO* derBio = BIO_new(BIO_s_mem());
	BIO_write(derBio, cast(const(void)*)der.ptr, der.length.to!int);
	X509* x509 = d2i_X509_bio(derBio, null);

	BIO* pemBio = BIO_new(BIO_s_mem());
	PEM_write_bio_X509(pemBio, x509);

	return toVector(pemBio);
}

string getIntermediateCertificate(string linkHeader)
{
	import std.regex;
	// Link: <https://acme-v01.api.letsencrypt.org/acme/issuer-cert>;rel="up"
	auto r = regex("^<(.*)>;rel=\"up\"$");
	auto match = matchFirst(linkHeader, r);
	if (match.empty)
	{
		throw new AcmeException("Unable to parse 'Link' header with value " ~ linkHeader);
	}
	char[] url = cast(char[])match[1];
	auto reps = get(url);
	return cast(string)DERtoPEM( cast(char[])reps );
}

char[] sha256(char[] s)
{
	ubyte[SHA256_DIGEST_LENGTH] hash;
	SHA256_CTX sha256;
	if (!SHA256_Init(&sha256) ||
		!SHA256_Update(&sha256, s.ptr, s.length) ||
		!SHA256_Final(hash.ptr, &sha256))
	{
		throw new AcmeException("Error hashing a string");
	}
	return urlSafeBase64Encode(hash);
}

// https://tools.ietf.org/html/rfc7638
char[] makeJwkThumbprint(char[] jwk)
{
	char[] strippedJwk = jwk;
	// strip whitespace
	import std.uni;
	foreach ( i, ref v ; jwk)
		if (!isSpace(v)) strippedJwk ~= v;

	return sha256(strippedJwk);
}

//alias extractorCB = function (const ASN1_TIME *);
//const auto function (const ASN1_TIME *) pure @system
T extractExpiryData(T, alias extractor)(const(Certificate) certificate)
{
	BIO* bio = BIO_new(BIO_s_mem());
	if ( BIO_write(bio, cast(const(void)*) certificate.fullchain.ptr, to!int(certificate.fullchain.length)) <= 0)
	{
		throw new AcmeException("Can't write to BIO struct.");
	}
	X509* x509 = PEM_read_bio_X509(bio, null, null, null);

	ASN1_TIME * t = X509_get_notAfter(x509);

	return extractor(t);
}

/** The implementation of the  AcmeClient */
struct AcmeClientImpl
{
	this(string accountPrivateKey)
	{
		privateKey_ = EVP_PKEY_new();
		// Create the private key and 'header suffix', used to sign LE certs.
		{
			BIO * bio = BIO_new_mem_buf(cast(void*)(accountPrivateKey.toStringz), -1);
			RSA * rsa = PEM_read_bio_RSAPrivateKey(bio, null, null, null);
			if (!rsa)
			{
				throw new AcmeException("Unable to read private key");
			}

			// rsa will get freed when privateKey_ is freed
			if (!EVP_PKEY_assign_RSA(privateKey_, rsa))
			{
				throw new AcmeException("Unable to assign RSA to private key");
			}

			const(BIGNUM)* n, e, d;
			//~ extern(C) void RSA_get0_key(const RSA *r,
                   //~ const BIGNUM **n, const BIGNUM **e, const BIGNUM **d);
			//~ RSA_get0_key(rsa, &n, &e, &d);

			char[] jwkValue = q"( {
									"e":")" ~ urlSafeBase64Encode(e) ~ q"(",
									"kty": "RSA",
									"n":")" ~ urlSafeBase64Encode(n) ~ q"("
								})";
			jwkThumbprint_ = makeJwkThumbprint(jwkValue);

			headerSuffix_ = q"(
					"alg": "RS256",
					"jwk": )" ~ jwkValue ~ "}";
		}
	}

	char[] sign(char[] s)
	{
		// https://wiki.openssl.org/index.php/EVP_Signing_and_Verifying
		size_t signatureLength = 0;

		EVP_MD_CTX* context = null; //EVP_MD_CTX_create();
		const EVP_MD * sha256 = EVP_get_digestbyname("SHA256");
		if (!sha256 ||
			EVP_DigestInit_ex(context, sha256, null) != 1 ||
			EVP_DigestSignInit(context, null, sha256, null, privateKey_) != 1 ||
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

		return urlSafeBase64Encode(signature);
	}

	T sendRequest(T)(string url, string payload, Tuple!(string, string) * header = null)
	{
		char[] protectd = q"({"nonce": ")" ~
									getHeader(directoryUrl, "Replay-Nonce") ~ "\"," ~
									headerSuffix_;

		protectd = urlSafeBase64Encode(protectd);
		char[] payld = urlSafeBase64Encode(payload);

		char[] signature = sign(protectd ~ "." ~ payld);

		char[] body_ = "{" ~
						q"("protected": ")" ~ protectd ~ "\","  ~
						q"("payload": ")" ~ payld ~ "\"," ~
						q"("signature": ")" ~ signature ~ "\"}";

		Response response = doPost(url, cast(string)body_, cast(char*)(header ? (*header)[0] : null));
		if (header)
		{
			(*header)[1] = response.headerValue_;
		}
		return to!T(response.response_);
	}

	// Throws if the challenge isn't accepted (or on timeout)
	void verifyChallengePassed(JSONValue challenge, string keyAuthorization)
	{
		// Tell the CA we're prepared for the challenge.
		string verificationUri = challenge["uri"].str;
		sendRequest!string(verificationUri, q"(  {
														"resource": "challenge",
														"keyAuthorization": ")" ~ keyAuthorization ~ "\"}" );

		// Poll waiting for the CA to verify the challenge
		int counter = 0;
		enum count = 10;
		do
		{
			import core.thread;
			//~ sleep(1_000_000);    // sleep for a second
			char[] response = doGet(cast(char[])verificationUri);
			auto json = parseJSON(response);
			if (json["status"].str == "valid")
			{
				return;
			}
		} while (counter++ < count);

		throw new AcmeException("Failure / timeout verifying challenge passed");
	}

	Certificate issueCertificate(string[] domainNames, AcmeClient.Callback callback)
	{
		if (domainNames.empty())
		{
			throw new AcmeException("There must be at least one domain name in a certificate");
		}

		// Pass any challenges we need to pass to make the CA believe we're
		// entitled to a certificate.
		foreach (domain ; domainNames)
		{
			string payload = q"(
								{
									"resource": "new-authz",
									"identifier":
									{
										"type": "dns",
										"value": ")" ~ domain ~ q"("
									}
								}
								)";
			string response = sendRequest!string(newAuthZUrl, payload);

			auto json = parseJSON(response);

			/**
			 * If you pass a challenge, that's good for 300 days. The cert is only good for 90.
			 * This means for a while you can re-issue without passing another challenge, so we
			 * check to see if we need to validate again.
			 *
			 * Note that this introduces a race since it possible for the status to not be valid
			 * by the time the certificate is requested. The assumption is that client retries
			 * will deal with this.
			 */
			if (json["status"].str != "valid")
			{
				auto challenges = json["challenges"];
			/+	foreach ( challenge ; challenges)
				{
					if (challenge["type"].str == "http-01")
					{
						string token = challenge["token"].str;
						string url = "http://" ~ domain ~ "/.well-known/acme-challenge/" ~ token;
						string keyAuthorization = token ~ "." ~ jwkThumbprint_;
						callback(domain, url, keyAuthorization);
						verifyChallengePassed(challenge, keyAuthorization);
						break;
					}
				} +/
			}
		}

		// Issue the certificate
		auto r = makeCertificateSigningRequest(domainNames);
		string csr = r[0];
		string privateKey = r[1];

		Tuple!(string, string) header = tuple("Link", "");

		auto der = sendRequest!(char[])(newCertUrl,
					q"(   {
								"resource": "new-cert",
								"csr": ")" ~ csr ~ q"("
							 })", &header);

		Certificate cert;
		cert.fullchain = cast(string)DERtoPEM(der) ~ cast(string)getIntermediateCertificate(header[1]);
		cert.privkey = privateKey;
		return cert;
	}

private:
	char[]      headerSuffix_;
	EVP_PKEY*   privateKey_;
	char[]      jwkThumbprint_;
};


void doCurl(CURL* curl, string url)
{
	auto res = curl_easy_perform(curl);
	if (res != CurlError.ok)
	{
		auto str = cast(string)getCurlError(cast(char[])("Failure contacting " ~ url ~ " to read a header."), res);
		throw new AcmeException(str);
	}

	long responseCode;
	curl_easy_getinfo(curl, CurlInfo.response_code, &responseCode);
	if (responseCode / 100 != 2)
	{
		// If it's not a 2xx response code, throw.
		throw new AcmeException("Response code of " ~ to!string(responseCode) ~ " contacting " ~ url);
	}
}

string getHeader(string url, string headerKey)
{
	CURL* curl;
	curl_easy_setopt(curl, CurlOption.url, url.toStringz);

	// Does a HEAD request
	curl_easy_setopt(curl, CurlOption.nobody, 1);

	curl_easy_setopt(curl, CurlOption.headerfunction, &headerCallback);

	Tuple!(string, string) header = tuple(headerKey, "");
	curl_easy_setopt(curl, CURLOPT_HEADERDATA, header);

	doCurl(curl, url);

	return header[1];
}

Response doPost(string url, string postBody, char * headerKey)
{
    Response response;
    CURL* curl;

    curl_easy_setopt(curl, CurlOption.url, url.toStringz);
    curl_easy_setopt(curl, CurlOption.post, 1);
    curl_easy_setopt(curl, CurlOption.postfields, postBody.toStringz);
    curl_easy_setopt(curl, CurlOption.writefunction, &dataCallback);
    curl_easy_setopt(curl, CurlOption.writedata, &response.response_);

    Tuple!(string, string) header;
    if (headerKey)
    {
        curl_easy_setopt(curl, CurlOption.headerfunction, &headerCallback);

        header = tuple!(string,string)(headerKey.to!string, "");
        curl_easy_setopt(curl, CurlOption.headerdata, &header);
    }

    doCurl(curl, url);

    response.headerValue_ = header[1];

    return response;
}

struct Response
{
    char[]   response_;
    string   headerValue_;
};

char[] doGet(char[] url)
{
    char[] response;

    CURL* curl;
    curl_easy_setopt(curl, CurlOption.url, url.toStringz);
    curl_easy_setopt(curl, CurlOption.writefunction, &dataCallback);
    curl_easy_setopt(curl, CurlOption.writedata, &response);

    doCurl(curl, url.to!string);

    return response;
}

size_t dataCallback(void * buffer, size_t size, size_t nmemb, void * response)
{
    char* v = cast(char*)(response);

    size_t byteCount = size * nmemb;
    //~ string s = buffer[0..byteCount];

    //~ size_t initSize = v.length;
    //~ v.resize(v.size() + byteCount);
    //~ memcpy(&v[initSize], buffer, byteCount);

    return byteCount;
}

char[] getCurlError(char[] s, CURLcode c)
{
	import std.format;
    return format( "%s: %s", s, curl_easy_strerror(c)).to!(char[]);
}

size_t headerCallback(void * buffer, size_t size, size_t nmemb, void * h)
{
    // header -> 'key': 'value'
    Tuple!(string, string)* header = cast(Tuple!(string,string) *)(h);

    size_t byteCount = size * nmemb;
/+    if (byteCount >= (*header)[0].length)
    {
        if ((*header)[0] == cast(char *)(buffer)[0..(*header)[0].length])
        {
            string line(reinterpret_cast<const char *>(buffer), byteCount);

            // Header looks like 'X: Y'. This gets the 'Y'
            auto pos = line.find(": ");
            if (pos != string::npos)
            {
                string value = line.substr(pos + 2, byteCount - pos - 2);

                // Trim trailing whitespace
                header.second = value.erase(value.find_last_not_of(" \n\r") + 1);
            }
        }
    }
+/
    return byteCount;
}
