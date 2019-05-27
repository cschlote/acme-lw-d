
import std.stdio;
import std.file;

//import acme;
import acme.acme_client;
import acme.exception;

void handleChallenge(string domain, string url, string keyAuthorization)
{
    writeln("To verify ownership of " ~ domain ~ " make\n\n"
            ~ "\t" ~ url ~ "\n\nrespond with this\n\n"
            ~ "\t" ~ keyAuthorization ~ "\n\n"
            ~ "Hit any key when done");
    getchar();
    writeln( "\n***\n" );
}

int main(string[] args)
{
	version (STAGING)
		writeln("Running against staging environment.");

	if (args.length < 3)
	{
		writeln("Usage is 'acme_lw_client <file-name>, <domain-name>, <domain-name>, ...'\n" ~
				"  * <file-name> holds the account private key in pem format\n" ~
				"  * there must be at least one <domain-name>; the first will be the 'Subject' of the certificate\n");
		return -1;
	}
	int exitStatus = -1;
	try
	{
		AcmeClient.init();

		char[] privatekey = cast(char[])std.file.read(args[1]);
		AcmeClient acmeClient = new AcmeClient(cast(string)privatekey);

		string[] domainNames;
		for(int i = 2; i < args.length; ++i)
		{
			domainNames ~= args[i];
		}

			Certificate certificate = acmeClient.issueCertificate(domainNames, &handleChallenge);

			std.file.write("fullchain.pem", certificate.fullchain);
			std.file.write("privkey.pem", certificate.privkey);

		writeln( "Files 'fullchain.pem' and 'privkey.pem' have been written to the current directory.");
		writeln( "Certificate expires on " ~ certificate.getExpiryDisplay() );
	}
	catch (Exception e)
	{
			writeln( "Failed with error: " ~ e.msg );
			exitStatus = 0;
	}

	// Should be called to free resources allocated in AcmeClient::init
	AcmeClient.teardown();

	return exitStatus;
}
