/** This is commandline tool of the ACME v2 client
 *
 * This tool implements a ACME V2 compatible client, which allows to setup
 * an account on the LetsEncrypt ACME server, to open an order for a new
 * certificate, to setup the challanges and finally downloads the certificate.
 *
 * See:
 *   RFC8555 - Describes the ACME Protokol, version 2
 */
module app;

/* Imports */

import std.file;
import std.getopt;
import std.json;
import std.stdio;

import acme;

/* Decoded Commandline Options */

string argPrivateKeyFile;    /// The path to the private key for the ACME account
string argDomainKeyFile;     /// The path to the private key for the certs and csr
string argOutputFile;        /// The output path for the downloaded cert.
string argChallangeScript;   /// Name of challange script to call
string[] argDomainNames;     /// The list of domain names
string[] argContacts;        /// The list of account names
/// Supported key sizes
enum ArgRSABitsEnum {
	rsa2048 = 2048,
	rsa4096 = 4096
}
ArgRSABitsEnum argRSABits;   /// Select the number of bit by the enum name
bool argVerbose;             /// Verbosity mode?
bool argUseStaging;          /// Use staging server
bool argTosAgree;            /// Agree to Terms of Service

/** Long Help text and example */
enum helpLongText = q"(
Example:
  $ ./acme-lw-d -k key.pem -p domain.key -o domain.pem \
       -d your-domain.net -d www.your-domain.net \
       -c "mailto:webmaster@domain.net" \
       -w "./examples/setupChallange.sh" \
       -y -v -b {rsa2048|rs4096}

  RS keys will be created on first run and stored on disk. They are reused
  when existing.

  The setup-challange script is called with the challange type, the filename
   and token. Right new, only http challange is supported (FIXME).
)";


/** Call-out to setup the ACME
 *
 * Params:
 *   domain - domain identifier
 *   url - the url to prepare
 *   keyAuthorization - the token to return
 * Returns:
 *   A shell return value (0 means success)
 */
private
int handleChallenge(string domain, string url, string keyAuthorization)
{
	import std.format : format;
	string cmd = format("%s %s %s %s", argChallangeScript, domain, url, keyAuthorization);
	writefln("Running command '%s'", cmd); stdout.flush;

	import std.process : executeShell;
	auto rc = executeShell(cmd);
	writeln(rc.output);
	writefln("Command returned status %d (sucess=%s)", rc.status, rc.status == 0 ? true : false);
	return rc.status;
}

/** Programm Main
 *
 * Param:
 *   args - array of command line args
 * Return:
 *   shell error code
 */
int main(string[] args)
{
	if (args.length <= 1) args ~= "-h";
	auto helpInformation = getopt(
		args,
		std.getopt.config.required,
		"key|k",     "The path to private key of ACME account. (PEM file)", &argPrivateKeyFile,
		std.getopt.config.required,
		"domainkey|p",     "The path to your private key for X509 certificates (PEM file)", &argDomainKeyFile,
		std.getopt.config.required,
		"domain|d",  "A domain name. Can be given multiple times. First entry will be subject name.", &argDomainNames,
		std.getopt.config.required,
		"contact|c", "A contact for the account. Can be given multiple times.", &argContacts,
		std.getopt.config.required,
		"output|o",  "The output file for the PEM encoded X509 cert", &argOutputFile,
		std.getopt.config.required,
		"setupchallange|w",  "Programm to call to setup a challange", &argChallangeScript,
		"bits|b",    "RSA bits to use for keys. Used on new key creation", &argRSABits,
		"agree|y",   "Agree to TermsOfService, when creating the account.", &argTosAgree,
		"staging|s", "Use the staging server for initial testing or developing", &argUseStaging,
		"verbose|v", "Verbose output", &argVerbose);
	if (helpInformation.helpWanted)
	{
		defaultGetoptPrinter("Usage: acme_client <options>",
			helpInformation.options);
		writeln(helpLongText);
		return 1;
	}
	assert(argPrivateKeyFile !is null, "The path should be set?!");
	assert(argDomainKeyFile !is null, "The path should be set?!");
	assert(argDomainNames.length >= 1, "No domain names found?!");
	assert(argContacts.length >= 1, "No contacts found?!");

	if (argUseStaging) {
		writeln("Note: Running against staging environment!");
		useStagingServer = true;
	} else {
		writeln("Note: Running against production environment!");
		useStagingServer = false;
	}

	/* -- Read the keys from disk ---------------------------------------- */
	string privateKeyData;
	if (exists(argPrivateKeyFile)) {
		privateKeyData = std.file.readText(argPrivateKeyFile);
		if (argVerbose) writefln("Read private key for ACME account from %s.", argPrivateKeyFile);
	} else {
		import acme.openssl_helpers : openSSL_CreatePrivateKey;
		privateKeyData = openSSL_CreatePrivateKey(argRSABits).idup;
		std.file.write(argPrivateKeyFile, privateKeyData);
		if (argVerbose) writeln("Created private key for ACME account.");
	}

	string domainKeyData;
	if (exists(argDomainKeyFile)) {
		domainKeyData = std.file.readText(argDomainKeyFile);
		if (argVerbose) writefln("Read private key for csr from %s.", argDomainKeyFile);
	}
	else {
		import acme.openssl_helpers : openSSL_CreatePrivateKey;
		domainKeyData = openSSL_CreatePrivateKey(argRSABits).idup;
		std.file.write(argDomainKeyFile, domainKeyData);
		if (argVerbose) writeln("Created private key for ACME account.");
	}

	/* -- ACME V2 process starts below ----------------------------------- */

	int exitStatus = -1;
	try
	{
		curlBeVerbose = argVerbose;

		/* --- Create the ACME client object ----------------------------- */
		AcmeClient acmeClient = new AcmeClient(privateKeyData, argVerbose);

		acmeClient.setupClient();
		if (argVerbose) {
			writeln( "URL for ACME directory : ", acmeClient.acmeRes.directoryUrl);
			writeln( acmeClient.acmeRes.directoryJson.toPrettyString() );
		}
		/* --- Create a new account/Use existing account  ----------------- */
		const bool nwaccrc = acmeClient.createNewAccount(argContacts, argTosAgree);
		if (!nwaccrc) {
			stdout.writeln("Failed to create new or obtain exiting account.");
			return exitStatus;
		}

		/* --- Issue a new cert process ----------------------------------- */
		Certificate certificate;
		certificate = acmeClient.issueCertificate(domainKeyData, argDomainNames, &handleChallenge);

		/* --- Write out file --------------------------------------------- */
		std.file.write(argOutputFile, certificate.fullchain);
		std.file.write(argDomainKeyFile, certificate.privkey);
		writefln( "Files '%s' and '%s' have been written.", argOutputFile, argDomainKeyFile);

		/* Get the expiry date from cert */
		auto expdate = certificate.getExpiryDisplay();
		writeln( "Certificate expires on " ~ expdate);

		exitStatus = 0;
	}
	catch (AcmeException e)
	{
		writeln( "Failed with error: " ~ e.msg );
	}
	return exitStatus;
}

