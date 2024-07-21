
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

import acme;

/** By default, we always use the staging and test server. */
bool useStagingServer = true;

/* ------------------------------------------------------------------------ */

/** Url to official v2 API of letsencrypt */
enum directoryUrlProd = "https://acme-v02.api.letsencrypt.org/directory";
/** Url to official v2 staging API of letsencrypt */
enum directoryUrlStaging = "https://acme-staging-v02.api.letsencrypt.org/directory";

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

	string accountUrl;       /// Account Url for a JWK.
	// FIXME Are these members obsolete or from V1 API?
	//string newCertUrl;
	//string newRegUrl;

	/** Init the Resource with a ACME directory URL */
	void initClient(string initstr = directoryUrlStaging) {
		directoryUrl = initstr;
	}
	/** Decode a ACME directory JSON */
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
		/* Are the following fields obsolete or v1? */
		//if ("newCert" in json) this.newCertUrl = json["newCert"].str;
		//if ("newReg" in json) this.newRegUrl = json["newReg"].str;

		if ("meta" in json) this.metaJson = json["meta"].toJSON;
	}
	void getResources()
	{
		try
		{
			auto conn = HTTP(this.directoryUrl);
			conn.setUserAgent = "acme-lw-d/" ~ acmeClientVersion ~ " " ~ HTTP.defaultUserAgent();
			conn.method = HTTP.Method.get;
			debug { conn.verifyPeer = false; }
			char[] directory = std.net.curl.get(this.directoryUrl, conn);
			decodeDirectoryJson(directory);
		}
		catch (Exception e)
		{
			string msg = "Unable to initialize resource url from " ~
				this.directoryUrl ~ ": (" ~ typeof(e).stringof ~ ")" ~ e.msg;
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
	void testcode(string url, bool dofullasserts = false, char[] dldtxt = null )
	{
		AcmeResources test;
		if (url is null) {
			test.initClient();
			if (dldtxt is null)
			{
				writeln("Decode downloaded directroy JSON.");
				test.decodeDirectoryJson(dirTestData);
			}
			else
			{
				writeln("Decode provided directroy JSON.");
				test.decodeDirectoryJson(dldtxt);
			}
		} else {
			writeln("Call getResource() for object.");
			test.initClient(url);
			test.directoryUrl = url;
			test.getResources();
		}
		//writeln("Received directory data :\n", test.directoryJson.toPrettyString);
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

	writeln("**** Testing AcmeResources : Decode external test vector");
	{
		auto downloadedDirectory = get(directoryUrlStaging);
		testcode(null, false, downloadedDirectory);
	}
	writeln("**** Testing AcmeResources : Decode internal test vector");
	testcode(null, true);
	writeln("**** Testing AcmeResources : Use staging server : ", directoryUrlStaging);
	testcode(directoryUrlStaging);
	writeln("**** Testing AcmeResources : Use production server : ", directoryUrlProd);
	testcode(directoryUrlProd);
}

/* ------------------------------------------------------------------------ */


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
		import openssl_glues : ASN1_TIME, stubSSL_ASN1_TIME_diff;
		static const(DateTime) extractor(const(ASN1_TIME) * t)
		{
			import openssl_glues;
			import core.stdc.time;
			time_t unixTime = stubSSL_ASN1_GetTimeT(cast(ASN1_TIME*)t);
			auto stdTime = unixTimeToStdTime(unixTime);
			const auto st = SysTime(stdTime);
			auto dt = cast(DateTime)st;
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
		import openssl_glues : ASN1_TIME, stubSSL_ASN1_TIME_print, BIO, stubSSL_BIO_free;
		string extractor(const ASN1_TIME * t)
		{
			BIO* b = stubSSL_ASN1_TIME_print(cast(ASN1_TIME*)t);
			scope(exit) stubSSL_BIO_free(b);
			return b.toVector.to!string;
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
	import openssl_glues : EVP_PKEY;
	EVP_PKEY*   privateKey_;     /// Copy of private key as ASC PEM

	JSONValue   jwkData_;        /// JWK object as JSONValue tree
	string      jwkString_;      /// JWK as plain JSON string
	ubyte[]     jwkSHAHash_;     /// The SHA256 hash value of jwkString_
	string      jwkThumbprint_;  /// Base64 url-safe string of jwkSHAHash_

	bool		beVerbose_;      /// Be verbose

	void myLog(alias fun = writeln, T...)(T args)
	{
		if (beVerbose_) {
			fun(args);
			stdout.flush;
		}
	}

	/** Create and send a JWS request with payload to a ACME enabled CA server
	 *
	 * Still unfinished template to build the JWS object. This code must be
	 * refactored later.
	 *
	 * Params:
	 *  T = return type
	 *  useKID = useKID
	 *  url = Url to post to
	 *  payload = data to send
	 *  status = pointer to StatusLine
	 *  rheaders = Pointer to ResponseHeaders received from server, or null
	 *
	 * See: https://tools.ietf.org/html/rfc7515
	 */
	T sendRequest(T, bool useKID = true)
		(string url, string payload, HTTP.StatusLine* status = null, string[string]* rheaders = null)
			if ( is(T : string) || is(T : char[]) || is(T : ubyte[]))
	{
		string nonce = this.acmeRes.nonce;
		assert(nonce !is null && !nonce.empty, "Invalid Nonce value.");
		myLog("Using NOnce: ", nonce);

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
		myLog(protectd);
		protectd = base64EncodeUrlSafe(protectd);

		const char[] payld = base64EncodeUrlSafe(payload);

		auto signData = protectd ~ "." ~ payld;
		myLog!writefln("Data to sign: %s", signData);
		char[] signature = signDataWithSHA256(signData, privateKey_);
		myLog!writefln("Signature: %s", signature);

		JSONValue jvBody;
		jvBody["protected"] = protectd;
		jvBody["payload"] = payld;
		jvBody["signature"] = signature;
		char[] body_ = jvBody.toJSON.dup;
		myLog!writefln("Body: %s", jvBody.toPrettyString);

		auto response = doPost(url, body_, status, rheaders, &(acmeRes.nonce));
		if (rheaders) {
			myLog( "ResponseHeaders: ");
			foreach( v ; (*rheaders).byKey) {
				myLog("  ", v, " : ", (*rheaders)[v]);
				//~ if (v.toLower == "replay-nonce") {
					//~ acmeRes.nonce = (*rheaders)[v];
					//~ myLog("Setting new NOnce: ", acmeRes.nonce);
				//~ }
			}
		}
		myLog( "Response: ", response);

		return to!T(response);
	}

public:
	AcmeResources acmeRes;       /// The Urls to the ACME resources


	/** Instanciate a AcmeClient using a private key for signing
	 *
	 *  Param:
	 *     accountPrivateKey = The signingKey is the Acme account private
	 *     		key used to sign requests to the acme CA, in pem format.
	 *  Throws: an instance of AcmeException on fatal or unexpected errors.
	 */
	this(string accountPrivateKey, bool beVerbose = false)
	{
		import openssl_glues : RSA, BIGNUM, stubSSL_RSA_Get0_key;
		beVerbose_ = beVerbose;

		acmeRes.initClient( useStagingServer ? directoryUrlStaging : directoryUrlProd);
		openSSL_OpenLibrary();

		/* Create the private key */
		RSA* rsa;
		privateKey_ = openSSL_x509_read_pkey_memory( cast(const(char[]))accountPrivateKey, &rsa);

		BIGNUM* n;
		BIGNUM* e;
		BIGNUM* d;
		stubSSL_RSA_Get0_key(rsa, &n, &e, &d);

		// https://tools.ietf.org/html/rfc7638
		// JSON Web Key (JWK) Thumbprint
		JSONValue jvJWK;
		jvJWK["e"] = getBigNumberBytes(e).base64EncodeUrlSafe;
		jvJWK["kty"] = "RSA";
		jvJWK["n"] = getBigNumberBytes(n).base64EncodeUrlSafe;
		jwkData_ = jvJWK;
		jwkString_ = jvJWK.toJSON;
		jwkSHAHash_ = sha256Encode( jwkString_ ).dup;
		jwkThumbprint_ = jwkSHAHash_.base64EncodeUrlSafe.idup;
		//myLog("JWK:\n", jvJWK.toPrettyString);
		myLog("JWK:\n", jvJWK.toJSON);
		myLog("SHA of JWK:\n", jwkSHAHash_);
		myLog("Thumbprint of JWK:\n", jwkThumbprint_);
	}
	~this () {
		openSSL_CloseLibrary();
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
	 *   contacts = list of contacts for the account
	 *   tosAgreed = set this to true, when user ack on commandline. otherwise
	 *               the default is false, and the CA server might refuse to
	 *               operate in this case.
	 *   onlyReturnExisting = do not create a new account, but only reuse an
	 *                 existing one. Defaults to false. When set to true, an
	 *                 account is never created, but only existing accounts are
	 *                 returned. Useful to lookup the accountUrl of an key.
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
		/* Do not create new account? Used for lookups of accountURL */
		if (onlyReturnExisting)
			jvPayload["onlyReturnExisting"] = true;
		const JSONValue jvContact = contacts;
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
			if ("createdAt" in json)
				writeln("Account Creation : ", json["createdAt"]);
			// ...
			rc = true;
		}
		else {
			stderr.writeln("Got http error: ", statusLine);
			stderr.writeln("Got response:\n", response);
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
	 *   domainKeyData = the private PEM-encoded key
	 *   domainNames = list of domains
	 *   callback = pointer to function to setup expected response
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
		myLog("Payload : ", jvPayload.toPrettyString);
		HTTP.StatusLine statusLine;
		string response = sendRequest!string(acmeRes.newOrderUrl, payload, &statusLine);

		if (statusLine.code / 100 != 2) {
			stderr.writeln("Got http error: ", statusLine);
			stderr.writeln("Got response:\n", response);
			throw new AcmeException("Issue Request failed.");
		}
		auto json = parseJSON(response);
		myLog(json.toPrettyString);

		/* If you pass a challenge, that's good for 300 days. The cert is only good for 90.
		 * This means for a while you can re-issue without passing another challenge, so we
		 * check to see if we need to validate again.
		 *
		 * Note that this introduces a race since it possible for the status to not be valid
		 * by the time the certificate is requested. The assumption is that client retries
		 * will deal with this.
		 */
		static if (!is(JSONType)) {
			pragma(msg,"Has no public JSONType - skip test");
			enum bool typeTestOk = true;
		} else {
			const bool typeTestOk = json["status"].type == JSONType.string;
		}
		if ( ("status" in json) &&
			 (typeTestOk) &&
			 (json["status"].str != "valid") )
		{
			if ("authorizations" in json) {
				auto authorizations = json["authorizations"];
				foreach ( i, authorizationUrl ; authorizations.array)
				{
					string authurl = authorizationUrl.str;
					string response2 = sendRequest!string(authurl, "", &statusLine);
					if (statusLine.code / 100 != 2) {
						stderr.writeln("Got http error: ", statusLine);
						stderr.writeln("Got response:\n", response2);
						stdout.flush;
						throw new AcmeException("Auth Request failed.");
						//return cast(Certificate)null;
					}
					auto json2 = parseJSON(response2);
					myLog(json2.toPrettyString);

					if ("challenges" in json2)
					{
						auto domain = json2["identifier"]["value"].str;
						auto challenges = json2["challenges"];
						foreach (j, challenge; challenges.array)
						{
							if ( ("type" in challenge) &&
							     (challenge["type"].str == "http-01") )
							{
								const string token = challenge["token"].str;
								string url = "http://" ~ domain ~ "/.well-known/acme-challenge/" ~ token;
								string keyAuthorization = token ~ "." ~ jwkThumbprint_.to!string;
								const auto rc = callback(domain, url, keyAuthorization);
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

		myLog("CSR:\n", csr);

		/* Send CSRs and get the intermediate certs */
		string[string] rheaders;

		JSONValue ncrs;
		ncrs["csr"] = csr;

		auto finalizeUrl = json["finalize"].str;
		auto finalizePayLoad = ncrs.toJSON;
		auto finalizeResponseStr = sendRequest!(char[])(finalizeUrl, finalizePayLoad, &statusLine, &rheaders);
		if (statusLine.code / 100 != 2) {
				stderr.writeln("Got http error: ", statusLine);
				stderr.writeln("Got response:\n", finalizeResponseStr);
				stdout.flush;
				throw new AcmeException("Verification for passed challange failed.");
		}
		auto finalizeResponseJV = parseJSON(finalizeResponseStr);
		myLog(finalizeResponseJV.toPrettyString);

		/* Download the certificate (via POST-as-GET) */
		auto certificateUrl = finalizeResponseJV["certificate"].str;
		auto crtpem = sendRequest!(char[])(certificateUrl, "", &statusLine, &rheaders);
		myLog(crtpem);

		/* Create a container object */
		Certificate cert;
		cert.fullchain = crtpem.to!string;
		cert.privkey = privateKey.idup;
		return cert;
	}

	/** Acknowledge to CA server that a Auth is setup for check.
	 *
	 * Params:
	 *  authorizationUrl = url to a auth job
	 *  challenge = the current challange for reference
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
			stderr.writeln("Got http error: ", statusLine);
			stderr.writeln("Got response:\n", response);
			stdout.flush;
			throw new AcmeException("Verification for passed challange failed.");
			//return cast(Certificate)null;
		}

		// Poll waiting for the CA to verify the challenge
		int counter = 0;
		enum loopDelay = 2;
		enum maxRetryCount = 60;
		writefln("Waiting for valid http-01 challange. (%d times a %d seconds)", maxRetryCount, loopDelay);
		do
		{
			// sleep for a second
			import core.thread : Thread;
			Thread.sleep(dur!"seconds"(loopDelay));

			// get response from verification URL
			response = sendRequest!string(authorizationUrl, "", &statusLine);
			if (statusLine.code / 100 != 2) {
				stderr.writeln("Got http error: ", statusLine);
				stderr.writeln("Got response:\n", response);
				stdout.flush;
				throw new AcmeException("Verification for passed challange failed.");
			}
			else {
				myLog(response);
				auto json = parseJSON(response);
				myLog(json.toPrettyString);
				if (json["status"].str == "valid")
				{
					writeln("Challange valid. Continue.");
					return;
				}
				else
					myLog!writefln("Waiting for http-01 challange to be valid (%d/%d)", counter, maxRetryCount);
			}
		} while (counter++ < maxRetryCount);

		throw new AcmeException("Failure / timeout verifying challenge passed");
	}
}
