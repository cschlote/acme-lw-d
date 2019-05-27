
module acme.exception;

import std.exception;

class AcmeException : Exception
{
    mixin basicExceptionCtors;
}
