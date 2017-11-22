Ever needed to know which CA certificate signed an SSL certificate?  This utility will tell you just that!  And nothing more.

Usage:

    whichca /path/to/cert/bundle.crt
    

If all goes well, it will spit out the PEM encoded version of the chain leading to the root certificate, minus
the certificate and intermediates found in the passed file.

