
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
string getHeader(string url, string headerKey)
{
	string headerVal;

	auto http = HTTP(url);
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

alias doPostTuple = Tuple!(char[], "response", string, "headerValue");

doPostTuple doPost(string url, char[] postBody, char[] headerKey)
{
    doPostTuple response;
	string headerVal;

	auto http = HTTP(url);
	http.method = HTTP.Method.post;
	if (headerKey.empty == false)
		http.onReceiveHeader =
			(in char[] key, in char[] value)
				{
					writeln( "Response Header : ", key, " = ", value);
					if (key.toLower == headerKey.toLower)
						headerVal = value.idup;
				};
	http.onReceive =
		(ubyte[] data)
			{
				writefln( "data: %s", to!string(data));
				response.response ~= data;
				return data.length;
			};
	http.postData = postBody;
	http.verbose = true;
	http.perform();

	response.headerValue = headerVal;
	return response;
}

