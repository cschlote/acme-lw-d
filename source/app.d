
import std.file;
import std.getopt;
import std.json;
import std.stdio;

import acme;
import acme.acme_client;
import acme.exception;

/* Decode Commandline Options */
string argPrivateKeyFile;    /// The path to the private key
string[] argDomainNames;     /// The list of domain names
string[] argContacts;        /// The list of account names
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
		"key|k",     "The path to your private key PEM file", &argPrivateKeyFile,
		std.getopt.config.required,
		"domain|d",  "A domain name. Can be given multiple times. First entry will be subject name.", &argDomainNames,
		std.getopt.config.required,
		"contact|c", "A contact for the account. Can be given multiple times.", &argContacts,
		"agree|y",   "Agree to TermsOfService", &argTosAgree,
		"verbose|v", "Verbose output", &argVerbose);
	if (helpInformation.helpWanted)
	{
		defaultGetoptPrinter("Usage: acme_client -k <keyfile> -d example.com,",
		helpInformation.options);
		return 1;
	}
	assert(argPrivateKeyFile !is null, "The path should be set?!");
	assert(argDomainNames.length >= 1, "No domain names found?!");

	string privateKeyData;
	if (exists(argPrivateKeyFile))
	{
		privateKeyData = std.file.readText(argPrivateKeyFile);
	}
	else {
		writefln("No private keyfile found at %s.", argPrivateKeyFile);
		return -1;
	}

	/* -------------------------------------------------------------- */

	int exitStatus = -1;
	try
	{
		Certificate certificate;

		/* --- Create the ACME client object ------------------------ */
		AcmeClient acmeClient = new AcmeClient(privateKeyData);

		acmeClient.setupClient();
		writeln( "Directory for ACME url ", acmeClient.acmeRes.directoryUrl);
		writeln( acmeClient.acmeRes.directoryJson.toPrettyString() );

		/* --- Create a new account --------------------------------- */
		const bool nwaccrc = acmeClient.createNewAccount(argContacts, argTosAgree);
		if (!nwaccrc) {
			writeln("Failed to create new or obtain exiting account.");
			goto bailout;
		}

		/* --- Issue a new cert process ----------------------------- */
		certificate = acmeClient.issueCertificate(argDomainNames, &handleChallenge);

		std.file.write("fullchain.pem", certificate.fullchain);
		std.file.write("privkey.pem", certificate.privkey);

		writeln( "Files 'fullchain.pem' and 'privkey.pem' have been written to the current directory.");
		writeln( "Certificate expires on " ~ certificate.getExpiryDisplay() );
	bailout:
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
	getchar();
	writeln( "\n***\n" );
}
