#!/usr/bin/env rdmd
/*
 * This is some simple example script, on how you could setup a Raspberry
 * PI, which is used as a web-server for home network.
 *
 * The raspi3 is Raspian based, and has just NGinx installed. The domestic
 * router is forwarding port 80 and 443 to it.
 *
 * The script will remote access the device and sets up the desired url and
 * token.
 */

import std.stdio;

int main(string[] args)
{
	int rc = -1;
	if (args.length != 4)
		writefln("Call programm as follows:\nsetupChallange.d domain url keyAuth");
	else
		rc = setupChallenge(args[1], args[2], args[3]);
	return rc;
}

/* Setup the ACME Web Challange */
private
int setupChallenge(string domain, string url, string keyAuthorization)
{
	writeln("Setup ACME Web Challange Demo Script\n");
	writefln("Setup URl '%s'\n to respond with '%s'\n to proof ownership of domain '%s'.\n",
		url, keyAuthorization, domain);

	/* Setup command string */
	import std.string;
	string filename = (url.split("/"))[$-1];
	string cmd = "rsh raspi3 \"echo " ~ keyAuthorization ~ " > /var/www/html/.well-known/acme-challenge/" ~ filename ~ "\"";
	stdout.flush;

	/* Execute the command */
	writefln("Running cmd '%s'", cmd);
	import std.process : executeShell;
	auto rc = executeShell(cmd);
	writeln(rc.output);
	writefln("Command returned status %d (sucess=%s)", rc.status, rc.status == 0 ? true : false);
	return rc.status;
}
