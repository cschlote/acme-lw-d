
/** Simple client for ACME protocol
 *
 * This software provides a simple and minimalistic ACME client. It
 * provides no fancy options, but sticks with the most common settings.
 */
module acme.acme_client;

import std.conv;
import std.datetime;
import std.json;
import std.net.curl;
import std.stdio;
import std.string;
import std.typecons;

import deimos.openssl.asn1;
import deimos.openssl.evp;
import deimos.openssl.pem;
import deimos.openssl.rsa;
import deimos.openssl.x509v3;

import acme;
import acme.exception;
import acme.curl_helpers;
import acme.openssl_helpers;

/* ------------------------------------------------------------------ */

enum directoryUrlProd = "https://acme-v01.api.letsencrypt.org/directory";
enum directoryUrlStaging = "https://acme-staging.api.letsencrypt.org/directory";

version (STAGING)
	string directoryUrlInit = directoryUrlStaging;
else
	string directoryUrlInit = directoryUrlProd;

/* ------------------------------------------------------------------ */

/** This structure stores the resource url of the ACME server
 */
struct AcmeResources
{
	string directoryUrl;     /// Initial config url to directory resource
	JSONValue directoryJson;

	string newAuthZUrl;
	string newCertUrl;
	string newRegUrl;
	string revokeCrtUrl;
	string keyChangeUrl;

	string newNOnceUrl;
	string newAccountUrl;
	string newOrderUrl;

	string metaJson;

	void init(string initstr = directoryUrlInit) {
		directoryUrl = initstr;
	}
	void decodeDirectoryJson(const(char[]) directory)
	{
		directoryJson = parseJSON(directory);
		alias json = directoryJson;
		if ("new-authz" in json) this.newAuthZUrl = json["new-authz"].str;
		if ("new-cert" in json) this.newCertUrl = json["new-cert"].str;
		if ("new-reg" in json) this.newRegUrl = json["new-reg"].str;
		if ("revoke-cert" in json) this.revokeCrtUrl = json["revoke-cert"].str;
		if ("key-change" in json) this.keyChangeUrl = json["key-change"].str;

		if ("new-nonce" in json) this.newNOnceUrl = json["new-nonce"].str;
		if ("new-account" in json) this.newAccountUrl = json["new-account"].str;
		if ("new-order" in json) this.newOrderUrl = json["new-order"].str;

		if ("meta" in json) this.metaJson = json["meta"].toJSON;
	}
	void getResources()
	{
		try
		{
			char[] directory = get(this.directoryUrl);
			decodeDirectoryJson(directory);
		}
		catch (Exception e)
		{
			string msg = "Unable to initialize resource url from " ~ this.directoryUrl ~ ": " ~ e.msg;
			throw new AcmeException(msg, __FILE__, __LINE__, e );
		}
	}
}

unittest
{
	string dirTestData = q"({
    "GGCJr9XCH_k": "https:\/\/community.letsencrypt.org\/t\/adding-random-entries-to-the-directory\/33417",
    "key-change": "https:\/\/acme-staging.api.letsencrypt.org\/acme\/key-change",
    "meta": {
        "caaIdentities": [
            "letsencrypt.org"
        ],
        "terms-of-service": "https:\/\/letsencrypt.org\/documents\/LE-SA-v1.2-November-15-2017.pdf",
        "website": "https:\/\/letsencrypt.org\/docs\/staging-environment\/"
    },
    "new-account": "https:\/\/acme-staging.api.letsencrypt.org\/acme\/new-account",
    "new-authz": "https:\/\/acme-staging.api.letsencrypt.org\/acme\/new-authz",
    "new-cert": "https:\/\/acme-staging.api.letsencrypt.org\/acme\/new-cert",
    "new-nonce": "https:\/\/acme-staging.api.letsencrypt.org\/acme\/new-nonce",
    "new-order": "https:\/\/acme-staging.api.letsencrypt.org\/acme\/new-order",
    "new-reg": "https:\/\/acme-staging.api.letsencrypt.org\/acme\/new-reg",
    "revoke-cert": "https:\/\/acme-staging.api.letsencrypt.org\/acme\/revoke-cert"
})";
	void testcode(string url, bool dofullasserts = false )
	{
		AcmeResources test;
		if (url is null) {
			test.init();
			test.decodeDirectoryJson(dirTestData);
		} else {
			test.init(url);
			test.directoryUrl = url;
			test.getResources();
		}
		writeln("Received directory data :\n", test.directoryJson.toPrettyString);
		assert( test.directoryUrl !is null, "Shouldn't be null");
		assert( test.newAuthZUrl !is null, "Shouldn't be null");
		assert( test.newCertUrl !is null, "Shouldn't be null");
		assert( test.newRegUrl !is null, "Shouldn't be null");
		assert( test.revokeCrtUrl !is null, "Shouldn't be null");
		assert( test.keyChangeUrl !is null, "Shouldn't be null");
		if (dofullasserts) {
			assert( test.newNOnceUrl !is null, "Shouldn't be null");
			assert( test.newAccountUrl !is null, "Shouldn't be null");
			assert( test.newOrderUrl !is null, "Shouldn't be null");
			assert( test.metaJson !is null, "Shouldn't be null");
		}
	}
	writeln("**** Testing AcmeResources : Decode test vector");
	testcode(null, true);
	writeln("**** Testing AcmeResources : Use staging server : ", directoryUrlStaging);
	testcode(directoryUrlStaging);
	writeln("**** Testing AcmeResources : Use production server : ", directoryUrlProd);
	testcode(directoryUrlProd);
}

/* ------------------------------------------------------------------ */

/** An openssl certificate */
struct Certificate
{
	/** The full CA chain with cert */
	string fullchain;
	/** The private key to sign requests */
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
			if (!ASN1_TIME_diff(&days, &seconds, null, t))
			{
				throw new AcmeException("Can't get time diff.");
			}
			// Hackery here, since the call to time(0) will not necessarily match
			// the equivilent call openssl just made in the 'diff' call above.
			// Nonetheless, it'll be close at worst.
			auto dt = DateTime( Date(0) );
			dt += dur!"seconds"(seconds + days * 3600 * 24);
			return dt;
		}
	  	return extractExpiryData!(DateTime, extractor)(this.fullchain);
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
		return extractExpiryData!(string, extractor)(this.fullchain);
	}
}

/** A simple ACME client */
class AcmeClient
{
public:
	AcmeResources* getAcmeRes()
	{
		return &(impl_.acmeRes);
	}

	/** Instanciate a AcmeClient using a private key for signing

		Param:
		   signingKey - The signingKey is the Acme account private
		   		key used to sign requests to the acme CA, in pem format.
		Throws: an instance of AcmeException on fatal or unexpected errors.
	*/
	this(string signingKey)
	{
		impl_ = new AcmeClientImpl(signingKey);
	}

	/** Expected response setup callback

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
	alias Callback =
		void function (
			string domainName,
			string url,
			string keyAuthorization);

	/** Issue a certificate for the domainNames.
	 *
	 * The first one will be the 'Subject' (CN) in the certificate.
	 * Params:
	 *   domainNames - list of domains
	 *   callback - pointer to function to setup expected response
	 *              on given URL
	 * Returns: A Certificate object or null.
	 * Throws: an instance of AcmeException on fatal or unexpected errors.
	 */
	Certificate issueCertificate(string[] domainNames, Callback callback)
	{
		return impl_.issueCertificate(domainNames, callback);
	}

	/// Call once before instantiating AcmeClient to setup endpoints
	void setupEndpoints()
	{
		impl_.acmeRes.getResources();
	}

private:
	AcmeClientImpl* impl_;
}

/* ----------------------------------------------------------------------- */




/** The implementation of the AcmeClient
 *
 * This structure implements the basic steps to renew a certificate
 * with the ACME protocol.
 *
 * See: https://tools.ietf.org/html/rfc8555
 *      Automatic Certificate Management Environment (ACME)
 */
struct AcmeClientImpl
{
private:
	EVP_PKEY*   privateKey_;     // Copy of private key as ASC PEM
	JSONValue   jwkData_;        // JWK object as JSONValue tree
	string      jwkString_;      // JWK as plain JSON string
	ubyte[]     jwkSHAHash_;     // The SHA256 hash value of jwkString_
	string      jwkThumbprint_;  // Base64 url-safe string of jwkSHAHash_

public:
	AcmeResources acmeRes;

	/** Construct the AcmeClient
	 *
	 * Param:
	 *   accountPrivateKey - the privat key for the operations
	 */
	this(string accountPrivateKey)
	{
		acmeRes.init();

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

			// https://tools.ietf.org/html/rfc7638
			// JSON Web Key (JWK) Thumbprint
			JSONValue jvJWK;
			jvJWK["e"] = getBigNumberBytes(rsa.e).base64EncodeUrlSafe;
			jvJWK["kty"] = "RSA";
			jvJWK["n"] = getBigNumberBytes(rsa.n).base64EncodeUrlSafe;
			jwkData_ = jvJWK;
			jwkString_ = jvJWK.toJSON;
			jwkSHAHash_ = sha256Encode( jwkString_ );
			jwkThumbprint_ = jwkSHAHash_.base64EncodeUrlSafe.idup;
		}
	}

	/** Sign a given string with an SHA256 hash
	 *
	 * Param:
	 *  s - string to sign
	 *  Returns:
	 *    A SHA256 signature on provided data
	 * See: https://wiki.openssl.org/index.php/EVP_Signing_and_Verifying
	 */
	char[] signDataWithSHA256(char[] s)
	{
		size_t signatureLength = 0;

		EVP_MD_CTX* context = EVP_MD_CTX_create();
		const EVP_MD * sha256 = EVP_get_digestbyname("SHA256");
		if ( !sha256 ||
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

		return base64EncodeUrlSafe(signature);
	}

	/// Tuple for filtering of RequestHeaders
	alias sendRequestTuple = Tuple!(string, "key", string, "value");

	/** Send a JWS request with payload to a CA server
	 *
	 * Params:
	 *  url - Url to post to
	 *  payload - data to send
	 *  header - Pointer to RequestHeader filter tuple, containing key
	 *     to find and value to store the matched result, if any.
	 *
	 * See: https://tools.ietf.org/html/rfc7515
	 */
	T sendRequest(T)(string url, string payload, sendRequestTuple * header = null)
	{
		/* Get a NOnce number from server */
		auto nonce = getHeader(acmeRes.directoryUrl, "Replay-Nonce");
		assert(nonce !is null, "Can't get the NOnce from " ~ acmeRes.directoryUrl);

		// Create protection data
		JSONValue jvReqHeader;
		jvReqHeader["nonce"] = nonce;
		jvReqHeader["alg"] = "RS256";
		jvReqHeader["jwk"] = jwkData_;
		char[] protectd = jvReqHeader.toJSON.dup;

		protectd = base64EncodeUrlSafe(protectd);

		char[] payld = base64EncodeUrlSafe(payload);

		auto signData = protectd ~ "." ~ payld;
		writefln("Data to sign: %s", signData);
		char[] signature = signDataWithSHA256(signData);
		writefln("Signature: %s", signature);

		JSONValue jvBody;
		jvBody["protected"] = protectd;
		jvBody["payload"] = payld;
		jvBody["signature"] = signature;
		char[] body_ = jvBody.toJSON.dup;
		writefln("Body: %s", jvBody.toPrettyString);

		char[] headerkey;
		if (header !is null) headerkey = (*header).key.dup;
		doPostTuple response = doPost(url, body_, headerkey);
		if (header)
		{
			(*header).value = response.headerValue;
		}
		return to!T(response.response);
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
			// sleep for a second
			import core.thread;
			Thread.sleep(dur!"seconds"(1));

			// get response from verification URL
			char[] response = get(verificationUri);
			auto json = parseJSON(response);
			if (json["status"].str == "valid")
			{
				return;
			}
		} while (counter++ < count);

		throw new AcmeException("Failure / timeout verifying challenge passed");
	}

	/** Issue a certificate request for a set of domains

	Params:
	  domainNames - a list of domain name, first one is cert subject.
	Returns:
	  A filled Certificate object.
	*/
	Certificate issueCertificate(string[] domainNames, AcmeClient.Callback callback)
	{
		if (domainNames.empty)
		{
			throw new AcmeException("There must be at least one domain name in a certificate");
		}

		/* Pass any challenges we need to pass to make the CA believe we're entitled to a certificate. */
		foreach (domain ; domainNames)
		{
			JSONValue jvPayload, jvPayload2;
			jvPayload2["type"] = "dns";
			jvPayload2["value"] = domain;
			jvPayload["resource"] = "new-authz";
			jvPayload["identifier"] = jvPayload2;
			string payload = jvPayload.toString;

			string response = sendRequest!string(acmeRes.newAuthZUrl, payload);

			auto json = parseJSON(response);

			/* If you pass a challenge, that's good for 300 days. The cert is only good for 90.
			 * This means for a while you can re-issue without passing another challenge, so we
			 * check to see if we need to validate again.
			 *
			 * Note that this introduces a race since it possible for the status to not be valid
			 * by the time the certificate is requested. The assumption is that client retries
			 * will deal with this.
			 */
			writeln(json.toPrettyString);
			if ( ("status" in json) &&
			     (json.type == JSONType.string) &&
			     (json["status"].str != "valid") )
			{
				if ("challenges" in json) {
					auto challenges = json["challenges"];
					foreach ( i, challenge ; challenges.array)
					{
						if ( ("type" in challenge) && (challenge["type"].str == "http-01") )
						{
							string token = challenge["token"].str;
							string url = "http://" ~ domain ~ "/.well-known/acme-challenge/" ~ token;
							string keyAuthorization = token ~ "." ~ jwkThumbprint_.to!string;
							callback(domain, url, keyAuthorization);
							verifyChallengePassed(challenge, keyAuthorization);
							break;
						}
					}
				}
			} else {
				writefln("Send payload: \n%s", jvPayload.toPrettyString);
				writefln("Got failure response:\n%s", json.toPrettyString);
				throw new AcmeException(json.toPrettyString);
			}
		}

		// Issue the certificate
		auto r = makeCertificateSigningRequest(domainNames);
		string csr = r.csr;
		string privateKey = r.pkey;

		// Send CSRs and get the intermediate certs
		sendRequestTuple header = tuple("Link", "");

		JSONValue ncrs;
		ncrs["resource"] = "new-cert";
		ncrs["csr"] = csr;

		auto der = sendRequest!(char[])(acmeRes.newCertUrl, ncrs.toJSON, &header);

		// Create a container object
		Certificate cert;
		cert.fullchain = convertDERtoPEM(der) ~ cast(string)getIntermediateCertificate(header[1]);
		cert.privkey = privateKey;
		return cert;
	}
}

/** Get the issuer certificate from a 'Link' response header
 *
 * Param:
 *  linkHeader - ResponseHeader Line of the form
 *               Link: <https://acme-v01.api.letsencrypt.org/acme/issuer-cert>;rel="up"
 *
 * Returns:
 *   Pem-encoded issuer certificate string
 */
string getIntermediateCertificate(string linkHeader)
{
	/* Extract the URL from the Header */
	import std.regex;
	// Link: <https://acme-v01.api.letsencrypt.org/acme/issuer-cert>;rel="up"
	auto r = regex("^<(.*)>;rel=\"up\"$");
	auto match = matchFirst(linkHeader, r);
	if (match.empty)
	{
		throw new AcmeException("Unable to parse 'Link' header with value " ~ linkHeader);
	}
	char[] url = cast(char[])match[1];

	/* Download the issuer certificate */
	auto reps = get(url);
	auto rstr = convertDERtoPEM( reps );
	return rstr;
}
