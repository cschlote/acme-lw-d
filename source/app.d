
/**
 * This is commandline tool of the ACME v2 client
 */
module app;

import std.file;
import std.getopt;
import std.json;
import std.stdio;

import acme;
import acme.acme_client;
import acme.exception;

/* Decoded Commandline Options */
string argPrivateKeyFile;    /// The path to the private key for the ACME account
string argDomainKeyFile;     /// The path to the private key for the certs and csr
string argOutputFile;        /// The output path for the downloaded cert.
string[] argDomainNames;     /// The list of domain names
string[] argContacts;        /// The list of account names
/// Supported key sizes
enum argRSABitsEnum {
	rsa2048 = 2048,
	rsa4096 = 4096
};
argRSABitsEnum argRSABits;
bool argVerbose;             /// Verbosity mode?
bool argTosAgree;            /// Agree to Terms of Service

/** Programm Main */
int main(string[] args)
{
	version (STAGING)
		writeln("Running against staging environment.");

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
		"bits|b",    "RSA bits to use for keys. Used on new key creation", &argRSABits,
		"agree|y",   "Agree to TermsOfService", &argTosAgree,
		"verbose|v", "Verbose output", &argVerbose);
	if (helpInformation.helpWanted)
	{
		defaultGetoptPrinter("Usage: acme_client <options>",
			helpInformation.options);
		return 1;
	}
	assert(argPrivateKeyFile !is null, "The path should be set?!");
	//assert(argDomainKeyFile !is null, "The path should be set?!");
	assert(argDomainNames.length >= 1, "No domain names found?!");
	assert(argContacts.length >= 1, "No contacts found?!");

	/* -- Read the keys from disk ---------------------------------------- */
	string privateKeyData;
	if (exists(argPrivateKeyFile)) {
		privateKeyData = std.file.readText(argPrivateKeyFile);
		if (argVerbose) writefln("Read private key for ACME account from %s.", argPrivateKeyFile);
	} else {
		import acme.openssl_helpers : openSSL_CreatePrivateKey;
		privateKeyData = openSSL_CreatePrivateKey().idup;
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
		domainKeyData = openSSL_CreatePrivateKey().idup;
		std.file.write(argDomainKeyFile, domainKeyData);
		if (argVerbose) writeln("Created private key for ACME account.");
	}

	/* -- ACME V2 process starts below ----------------------------------- */

	int exitStatus = -1;
	try
	{
		/* --- Create the ACME client object ----------------------------- */
		AcmeClient acmeClient = new AcmeClient(privateKeyData);

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

/* Expected response callback */
private
void handleChallenge(string domain, string url, string keyAuthorization)
{
	writeln("To verify ownership of " ~ domain ~ " make\n\n"
			~ "\t" ~ url ~ "\n\nrespond with this\n\n"
			~ "\t" ~ keyAuthorization ~ "\n\n"
			~ "Hit any key when done");
	import std.string;
	string filename = (url.split("/"))[$-1];
	string cmd = "rsh raspi3 \"echo " ~ keyAuthorization ~ " > /var/www/html/.well-known/acme-challenge/" ~ filename ~ "\"";
	writeln(cmd);
	stdout.flush;

	import std.process : executeShell;
	executeShell(cmd);

	//getchar();
	writeln( "\n***\n" );
}
