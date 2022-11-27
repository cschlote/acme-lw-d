/// Module to define a custom exception
module acme.exception;

import std.exception;

/// A custom execption
class AcmeException : Exception
{
    mixin basicExceptionCtors;
}
