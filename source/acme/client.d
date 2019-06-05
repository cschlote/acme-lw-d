
/** Simple client for ACME protocol
 *
 * This software provides a simple and minimalistic ACME client. It
 * provides no fancy options, but sticks with the most common settings.
 */
module acme.client;

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

/* ------------------------------------------------------------------------ */

enum directoryUrlProd = "https://acme-v02.api.letsencrypt.org/directory";
enum directoryUrlStaging = "https://acme-staging-v02.api.letsencrypt.org/directory";

version (STAGING)
	enum directoryUrlInit = directoryUrlStaging;
else
	enum directoryUrlInit = directoryUrlProd;

/* ------------------------------------------------------------------------ */

/** This structure stores the resource url of the ACME server
 */
struct AcmeResources
{
	string nonce;            /// The Nonce for the next JWS transfer

	string directoryUrl;     /// Initial config url to directory resource
	JSONValue directoryJson; /// JSON string returned returned from directoryURL

	string newNOnceUrl;      /// Url to newNonce resource
	string newAccountUrl;    /// Url to newAccount resource
	string newOrderUrl;      /// Url to newOrder resource
	string newAuthZUrl;      /// Url to newAuthz resource
	string revokeCrtUrl;     /// Url to revokeCert resource
	string keyChangeUrl;     /// Url to keyChange resource

	string metaJson;         /// Metadata as JSON string (undecoded)

	// FIXME
	string accountUrl;       /// Account Url for a JWK.
	string newCertUrl;
	string newRegUrl;

	void init(string initstr = directoryUrlInit) {
		directoryUrl = initstr;
	}
	void decodeDirectoryJson(const(char[]) directory)
	{
		directoryJson = parseJSON(directory);
		alias json = directoryJson;
		if ("keyChange" in json) this.keyChangeUrl = json["keyChange"].str;
		if ("newAccount" in json) this.newAccountUrl = json["newAccount"].str;
		if ("newNonce" in json) this.newNOnceUrl = json["newNonce"].str;
		if ("newOrder" in json) this.newOrderUrl = json["newOrder"].str;
		if ("revokeCert" in json) this.revokeCrtUrl = json["revokeCert"].str;

		if ("newAuthz" in json) this.newAuthZUrl = json["newAuthz"].str;
		if ("newCert" in json) this.newCertUrl = json["newCert"].str;
		if ("newReg" in json) this.newRegUrl = json["newReg"].str;

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
    "Ca1Xc_O0Nwk": "https:\/\/community.letsencrypt.org\/t\/adding-random-entries-to-the-directory\/33417",
    "keyChange": "https:\/\/acme-staging-v02.api.letsencrypt.org\/acme\/key-change",
    "meta": {
        "caaIdentities": [
            "letsencrypt.org"
        ],
        "termsOfService": "https:\/\/letsencrypt.org\/documents\/LE-SA-v1.2-November-15-2017.pdf",
        "website": "https:\/\/letsencrypt.org\/docs\/staging-environment\/"
    },
    "newAccount": "https:\/\/acme-staging-v02.api.letsencrypt.org\/acme\/new-acct",
    "newAuthz": "https:\/\/acme-staging-v02.api.letsencrypt.org\/acme\/new-authz",
    "newNonce": "https:\/\/acme-staging-v02.api.letsencrypt.org\/acme\/new-nonce",
    "newOrder": "https:\/\/acme-staging-v02.api.letsencrypt.org\/acme\/new-order",
    "revokeCert": "https:\/\/acme-staging-v02.api.letsencrypt.org\/acme\/revoke-cert"
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

		assert( test.keyChangeUrl !is null, "Shouldn't be null");
		assert( test.newAccountUrl !is null, "Shouldn't be null");
		assert( test.newNOnceUrl !is null, "Shouldn't be null");
		assert( test.newOrderUrl !is null, "Shouldn't be null");
		assert( test.revokeCrtUrl !is null, "Shouldn't be null");
		assert( test.metaJson !is null, "Shouldn't be null");
		if (dofullasserts) {
			assert( test.newAuthZUrl !is null, "Shouldn't be null");
		}
	}
	writeln("**** Testing AcmeResources : Decode test vector");
	testcode(null, true);
	writeln("**** Testing AcmeResources : Use staging server : ", directoryUrlStaging);
	testcode(directoryUrlStaging);
	writeln("**** Testing AcmeResources : Use production server : ", directoryUrlProd);
	testcode(directoryUrlProd);
}

/* ------------------------------------------------------------------------ */

// Missing in D binding?
extern(C) int ASN1_TIME_diff(int *pday, int *psec, const ASN1_TIME *from, const ASN1_TIME *to);

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
		DateTime rc = extractExpiryData!(DateTime, extractor)(this.fullchain);
		return rc;
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

/* ------------------------------------------------------------------------ */

/** A simple ACME v2 client
 *
 * This class implements the ACME v2 protocol to obtain signed SSL
 * certificates.
 */
class AcmeClient
{
private:
	EVP_PKEY*   privateKey_;     /// Copy of private key as ASC PEM

	JSONValue   jwkData_;        /// JWK object as JSONValue tree
	string      jwkString_;      /// JWK as plain JSON string
	ubyte[]     jwkSHAHash_;     /// The SHA256 hash value of jwkString_
	string      jwkThumbprint_;  /// Base64 url-safe string of jwkSHAHash_

	/** Create and send a JWS request with payload to a ACME enabled CA server
	 *
	 * Still unfinished template to build the JWS object. This code must be
	 * refactored later.
	 *
	 * Params:
	 *  T - return type
	 *  useKID - useKID
	 *  url - Url to post to
	 *  payload - data to send
	 *  status - pointer to StatusLine
	 *  rheaders - Pointer to ResponseHeaders received from server, or null
	 *
	 * See: https://tools.ietf.org/html/rfc7515
	 */
	T sendRequest(T, bool useKID = true)(string url, string payload, HTTP.StatusLine* status = null, string[string]* rheaders = null)
			if ( is(T : string) || is(T : char[]) || is(T : ubyte[]))
	{
		string nonce = this.acmeRes.nonce;
		assert(nonce !is null && !nonce.empty, "Invalid Nonce value.");
		writeln("Using NOnce: ", nonce);

		/* Create protection data */
		JSONValue jvReqHeader;
		jvReqHeader["alg"] = "RS256";
		static if (useKID)
			jvReqHeader["kid"] = acmeRes.accountUrl;
		else
			jvReqHeader["jwk"] = jwkData_;
		jvReqHeader["nonce"] = nonce;
		jvReqHeader["url"] = url;
		char[] protectd = jvReqHeader.toJSON.dup;

		protectd = base64EncodeUrlSafe(protectd);

		char[] payld = base64EncodeUrlSafe(payload);

		auto signData = protectd ~ "." ~ payld;
		//writefln("Data to sign: %s", signData);
		char[] signature = signDataWithSHA256(signData, privateKey_);
		//writefln("Signature: %s", signature);

		JSONValue jvBody;
		jvBody["protected"] = protectd;
		jvBody["payload"] = payld;
		jvBody["signature"] = signature;
		char[] body_ = jvBody.toJSON.dup;
		//writefln("Body: %s", jvBody.toPrettyString);

		auto response = doPost(url, body_, status, rheaders, &(acmeRes.nonce));
		if (rheaders) {
			writeln( "ResponseHeaders: ");
			foreach( v ; (*rheaders).byKey) {
				writeln("  ", v, " : ", (*rheaders)[v]);
				//~ if (v.toLower == "replay-nonce") {
					//~ acmeRes.nonce = (*rheaders)[v];
					//~ writeln("Setting new NOnce: ", acmeRes.nonce);
				//~ }
			}
		}
		//writeln( "Response: ", response);

		return to!T(response);
	}

public:
	AcmeResources acmeRes;       // The Url to the ACME resources


	/** Instanciate a AcmeClient using a private key for signing
	 *
	 *  Param:
	 *     accountPrivateKey - The signingKey is the Acme account private
	 *     		key used to sign requests to the acme CA, in pem format.
	 *  Throws: an instance of AcmeException on fatal or unexpected errors.
	 */
	this(string accountPrivateKey)
	{
		acmeRes.init();
		SSL_OpenLibrary();

		/* Create the private key */
		RSA* rsa;
		privateKey_ = SSL_x509_read_pkey_memory(accountPrivateKey, &rsa);

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
	~this () {
		SSL_CloseLibrary();
	}

	/** Call once after instantiating AcmeClient to setup parameters
	 *
	 * This function will fetch the directory from the ACME CA server and
	 * extracts the Urls.
	 *
	 * Also fetches the initial NOnce value for the next JWS transfer.
	 */
	void setupClient()
	{
		acmeRes.getResources();
		// Get initial Nonce
		this.getNonce();

	}

	/** Get a fresh and new Nonce from server
	 *
	 * To start the communication with JWS, an initial Nonce value must be
	 * fetched from the server.
	 *
	 * The Nonce returned is internally store in the AcmeResource structure.
	 *
	 * Note:
	 *   Use the Nonce of a JWS response header to update the Nonce for the
	 *   next transfer! So, only a single call to this function is needed to
	 *   setup the initial transfer.
	 *
	 * Returns:
	 *   a fresh and new Nonce value.
	 */
	string getNonce()
	{
		/* Get a NOnce number from server */
		auto nonce = getResponseHeader(acmeRes.newNOnceUrl, "Replay-Nonce");
		acmeRes.nonce = nonce;
		return nonce;
	}

	/** Create a new account and bind a key pair to it.
	 *
	 * Before we can do anything, we need to register an account and
	 * bind a RSA/EC keypair to it, which is used for signatures in
	 * JWS and to create the CSR.
	 *
	 * Params:
	 *   contacts - list of contacts for the account
	 *   tosAgreed - set this to true, when user ack on commandline. otherwise
	 *               the default is false, and the CA server might refuse to
	 *               operate in this case.
	 *   onlyReturnExisting - do not create a new account, but only reuse an
	 *                 existing one. Defaults to false. When set to true, an
	 *                 account is never created, but only existing accounts are
	 *                 returned.
	 *
	 * Note: tosAgreed must be queried from user, e.g. by setting a commandline
	 *       option. This is required by the RFC8555.
	 * Note: Usually there is no need to set useExisting to false. If set to
	 *       true, an existing account for a JWK is returned or new one
	 *       is created and returned.
	 */
	bool createNewAccount(string[] contacts, bool tosAgreed = false, bool onlyReturnExisting = false)
	{
		bool rc;
		/* Create newAccount payload */
		JSONValue jvPayload;
		jvPayload["termsOfServiceAgreed"] = tosAgreed;
		JSONValue jvContact = contacts;
		jvPayload["contact"] = jvContact;

		string payload = jvPayload.toJSON;

		string[string] rheaders;
		import std.net.curl : HTTP;
		HTTP.StatusLine statusLine;
		string response = sendRequest!(string,false)(acmeRes.newAccountUrl, payload, &statusLine, &rheaders);
		if (statusLine.code / 100 == 2)
		{
			acmeRes.accountUrl = rheaders["location"];
			writeln("Account Location : ", acmeRes.accountUrl);

			auto json = parseJSON(response);
			writeln("Account Creation : ", json["createdAt"]);
			// ...
			rc = true;
		}
		else {
			writeln("Got http error: ", statusLine);
			writeln("Got response:\n", response);
			// FIXME handle different error types...
		}
		return rc;
	}

	/** Authorization setup callback
	*
	*   The implementation of this function allows Let's Encrypt to
	*   verify that the requestor has control of the domain name.
	*
	*   The callback may be called once for each domain name in the
	*   'issueCertificate' call. The callback should do whatever is
	*   needed so that a GET on the 'url' returns the 'keyAuthorization',
	*   (which is what the Acme protocol calls the expected response.)
	*
	*   Note that this function may not be called in cases where
	*   Let's Encrypt already believes the caller has control
	*   of the domain name.
	*/
	alias Callback =
		int function (
			string domainName,
			string url,
			string keyAuthorization);

	/** Issue a certificate for domainNames
	 *
	 * The client begins the certificate issuance process by sending a POST
	 * request to the server's newOrder resource.  The body of the POST is a
	 * JWS object whose JSON payload is a subset of the order object defined
	 * in Section 7.1.3, containing the fields that describe the certificate
	 * to be issued.
	 *
	 * Params:
	 *   domainNames - list of domains
	 *   callback - pointer to function to setup expected response
	 *              on given URL
	 * Returns: A Certificate object or null.
	 * Throws: an instance of AcmeException on fatal or unexpected errors.
	 */
	Certificate issueCertificate(string domainKeyData, string[] domainNames, Callback callback)
	{
		if (domainNames.empty)
			throw new AcmeException("There must be at least one domain name in a certificate");

		/* Pass any challenges we need to pass to make the CA believe we're entitled to a certificate. */
		JSONValue[] jvIdentifiers;
		jvIdentifiers.length = domainNames.length;
		foreach (i, domain ; domainNames)
		{
			jvIdentifiers[i]["type"] = "dns";
			jvIdentifiers[i]["value"] = domain;
		}
		JSONValue jvIdentifiersArray;
		jvIdentifiersArray.array = jvIdentifiers;

		JSONValue jvPayload;
		// ISSUE: https://community.letsencrypt.org/t/notbefore-and-notafter-are-not-supported/54712
		version (boulderHasBeforeAfter) {
			jvPayload["notBefore"] = "2016-01-01T00:04:00+04:00";  // FIXME - use DateTime.to...()
			jvPayload["notAfter"]  = "2020-01-01T00:04:00+04:00";  // FIXME - use DateTime.to...()
		}
		jvPayload["identifiers"]  = jvIdentifiersArray;

		string payload = jvPayload.toJSON;
writeln("Payload : ", jvPayload.toPrettyString);
		HTTP.StatusLine statusLine;
		string response = sendRequest!string(acmeRes.newOrderUrl, payload, &statusLine);

		if (statusLine.code / 100 != 2) {
			writeln("Got http error: ", statusLine);
			writeln("Got response:\n", response);
			throw new AcmeException("Issue Request failed.");
			//return cast(Certificate)null;
		}
		auto json = parseJSON(response);
		writeln(json.toPrettyString);

		/* If you pass a challenge, that's good for 300 days. The cert is only good for 90.
		 * This means for a while you can re-issue without passing another challenge, so we
		 * check to see if we need to validate again.
		 *
		 * Note that this introduces a race since it possible for the status to not be valid
		 * by the time the certificate is requested. The assumption is that client retries
		 * will deal with this.
		 */
		if ( ("status" in json) &&
			 (json["status"].type == JSONType.string) &&
			 (json["status"].str != "valid") )
		{
			if ("authorizations" in json) {
				auto authorizations = json["authorizations"];
				foreach ( i, authorizationUrl ; authorizations.array)
				{
					string authurl = authorizationUrl.str;
					string response2 = sendRequest!string(authurl, "", &statusLine);
					if (statusLine.code / 100 != 2) {
						writeln("Got http error: ", statusLine);
						writeln("Got response:\n", response2);
						stdout.flush;
						throw new AcmeException("Auth Request failed.");
						//return cast(Certificate)null;
					}
					auto json2 = parseJSON(response2);
					writeln(json2.toPrettyString);

					if ("challenges" in json2)
					{
						auto domain = json2["identifier"]["value"].str;
						auto challenges = json2["challenges"];
						foreach (j, challenge; challenges.array)
						{
							if ( ("type" in challenge) &&
							     (challenge["type"].str == "http-01") )
							{
								string token = challenge["token"].str;
								string url = "http://" ~ domain ~ "/.well-known/acme-challenge/" ~ token;
								string keyAuthorization = token ~ "." ~ jwkThumbprint_.to!string;
								auto rc = callback(domain, url, keyAuthorization);
								if (rc != 0)
									throw new AcmeException("challange setup script failed.");
								verifyChallengePassed(authorizationUrl.str, challenge);
								break;
							}
						}
					}
				}
			}
		} else {
			writefln("Send payload: \n%s", jvPayload.toPrettyString);
			writefln("Got failure response:\n%s", json.toPrettyString);
			throw new AcmeException(json.toPrettyString);
		}

		// Issue the certificate
		// auto r = makeCertificateSigningRequest(domainNames);
		// string csr = r.csr;
		// string privateKey = r.pkey;
		const char[] privateKey = domainKeyData /* openSSL_CreatePrivateKey() */;
		const char[] csr = openSSL_CreateCertificateSignRequest(privateKey, domainNames);

		writeln("CSR:\n", csr);

		/* Send CSRs and get the intermediate certs */
		string[string] rheaders;

		JSONValue ncrs;
		ncrs["csr"] = csr;

		auto finalizeUrl = json["finalize"].str;
		auto finalizePayLoad = ncrs.toJSON;
		auto finalizeResponseStr = sendRequest!(char[])(finalizeUrl, finalizePayLoad, &statusLine, &rheaders);
		if (statusLine.code / 100 != 2) {
				writeln("Got http error: ", statusLine);
				writeln("Got response:\n", finalizeResponseStr);
				stdout.flush;
				throw new AcmeException("Verification for passed challange failed.");
		}
		auto finalizeResponseJV = parseJSON(finalizeResponseStr);
		writeln(finalizeResponseJV.toPrettyString);

		/* Download the certificate (via POST-as-GET) */
		auto certificateUrl = finalizeResponseJV["certificate"].str;
		auto crtpem = sendRequest!(char[])(certificateUrl, "", &statusLine, &rheaders);
		writeln(crtpem);

		/* Create a container object */
		Certificate cert;
		//~ cert.fullchain = convertDERtoPEM(der) ~ cast(string)getIntermediateCertificate(rheaders["Link"]);
		cert.fullchain = crtpem.to!string;
		cert.privkey = privateKey.idup;
		return cert;
	}

	/** Acknowledge to CA server that a Auth is setup for check.
	 *
	 * Params:
	 *  authorizationUrl - url to a auth job
	 *  challenge - the current challange for reference
	 *
	 * Throws if the challenge isn't accepted (or on timeout)
	 */
	void verifyChallengePassed(string authorizationUrl, JSONValue challenge)
	{
		string verificationUri = challenge["url"].str;

		import std.net.curl : HTTP;
		HTTP.StatusLine statusLine;
		string response = sendRequest!string(verificationUri, q"({})", &statusLine );
		if (statusLine.code / 100 != 2) {
			writeln("Got http error: ", statusLine);
			writeln("Got response:\n", response);
			stdout.flush;
			throw new AcmeException("Verification for passed challange failed.");
			//return cast(Certificate)null;
		}
		// Poll waiting for the CA to verify the challenge
		int counter = 0;
		enum count = 10;
		do
		{
			// sleep for a second
			import core.thread : Thread;
			Thread.sleep(dur!"seconds"(2));

			// get response from verification URL
			response = sendRequest!string(authorizationUrl, "", &statusLine);
			if (statusLine.code / 100 != 2) {
				writeln("Got http error: ", statusLine);
				writeln("Got response:\n", response);
				stdout.flush;
				throw new AcmeException("Verification for passed challange failed.");
			}
			else {
				writeln(response);
				auto json = parseJSON(response);
				//writeln(json.toPrettyString);
				if (json["status"].str == "valid")
				{
					writeln("challange valid. Continue.");
					return;
				}
			}
		} while (counter++ < count);

		throw new AcmeException("Failure / timeout verifying challenge passed");
	}
}

/* ------------------------------------------------------------------------ */
/* --- Helper Functions --------------------------------------------------- */
/* ------------------------------------------------------------------------ */

/** Get the issuer certificate from a 'Link' response header
 *
 * Param:
 *  linkHeader - ResponseHeader Line of the form
 *               Link: <https://acme-v01.api.letsencrypt.org/acme/issuer-cert>;rel="up"
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
