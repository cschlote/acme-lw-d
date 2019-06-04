
/** Small helpers for libCURL
 *
 * This module contains all the CURL related helpers.
 */
module acme.curl_helpers;

import etc.c.curl;

import std.conv;
import std.net.curl;
import std.stdio;
import std.string;
import std.typecons;

/** Current release number - FIXME Derive this from Git Tag. How in D? */
enum acmeClientVersion = "0.0.1";

/** Compose an error msg from custom and CURL error
 *
 * Params:
 *  msg - custom message
 */
string getCurlError(string s, CURLcode c)
{
	import std.format;
	auto errorstring = curl_easy_strerror(c).to!string;
	auto resultstring = format( "%s\nErrorcode: %d (%s)", s, c, errorstring);
    return resultstring;
}

/* ---------------------------------------------------------------------------- */

/** Get just the http receive headers with a given name from an URL

	Params:
	  url - Url to query
	  headerKey - headerline to query
	Returns:
	  the value of a given header or null
 */
string getResponseHeader(string url, string headerKey)
{
	string headerVal;

	auto http = HTTP(url);
	http.setUserAgent = "acme-lw-d/" ~ acmeClientVersion ~ " " ~ HTTP.defaultUserAgent();
	http.method = HTTP.Method.head;
	http.onReceiveHeader =
		(in char[] key, in char[] value)
			{
				writeln( "Response Header : ", key, " = ", value);
				if (key.toLower == headerKey.toLower)
					headerVal = value.idup;
			};
	http.perform();
	return headerVal;
}

/* ---------------------------------------------------------------------------- */

/** Do some posting, filter for some headerkey
 *
 * Params:
 *  url - url to pst to
 *  postBody - data to post
 *  rheaders - responseheader to return
 *  nonce - pointer to nonce string, so that we can update it.
 *
 * Returns:
 *   the received payload of the POST operation
 */
string doPost(string url, char[] postBody, HTTP.StatusLine* status,
	string[string]* rheaders,
	string* nonce)
{
	string response;
	string headerVal;

	auto http = HTTP(url);
	http.setUserAgent = "acme-lw-d/" ~ acmeClientVersion ~ " " ~ HTTP.defaultUserAgent();
	http.verbose = true;
	http.method = HTTP.Method.post;
	http.addRequestHeader("Content-Type", "application/jose+json");

	http.onReceiveHeader =
		(in char[] key, in char[] value)
			{
				if (key.toLower == "replay-nonce") {
					*nonce = value.idup;
					writeln("Setting new NOnce: ", *nonce);
				}
			};
	http.onReceive =
		(ubyte[] data)
			{
				//writefln( "data: %s", to!string(data));
				response ~= data;
				return data.length;
			};
	http.postData = postBody;

	http.perform();

	if (status !is null) *status = http.statusLine;

	if (rheaders !is null)
		*rheaders = http.responseHeaders;

	return response;
}

/* ---------------------------------------------------------------------------- */

