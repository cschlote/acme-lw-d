
import std.file;
import std.getopt;
import std.stdio;

//import acme;
import acme.acme_client;
import acme.exception;

/* Decode Commandline Options */
string argPrivateKeyFile;    /// The path to the private key
string[] argDomainNames;     /// The list of domain names
bool argVerbose;             /// Verbosity mode?

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

	int exitStatus = -1;
	try
	{
		AcmeClient.setupEndpoints();
		writeln( "Auth URL: ", newAuthZUrl);
		writeln( "Cert URL: ", newCertUrl);

		AcmeClient acmeClient = new AcmeClient(privateKeyData);
		Certificate certificate = acmeClient.issueCertificate(argDomainNames, &handleChallenge);

		std.file.write("fullchain.pem", certificate.fullchain);
		std.file.write("privkey.pem", certificate.privkey);

		writeln( "Files 'fullchain.pem' and 'privkey.pem' have been written to the current directory.");
		writeln( "Certificate expires on " ~ certificate.getExpiryDisplay() );

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
