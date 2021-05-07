This is a utility for
- Verifying a website presents enough information to validate a chain of trust
- Failing said verification, determine which intermediate certs (if any) 
  could be added to the CA bundle to get it to a verified chain
- Can be used to download a CA bundle from the web (defaults to 
  curl.se's mozilla bundle)
- Can determine what the minimum CA bundle a client would need to verify
  a site / list of sites or certificate bundle files.
- Can dump the system's default CA bundle (see limitations below)  


#### Usage:

### Subcommands:

## check

This is to check a site or a pem certificate file to see if it is trusted
against either the system default CA bundle (default) or a CA bundle file specified
with the -ca option. This will also provide an option to dump any missing 
intermediates needed to correct the configuration.

    (njohnson@greyeagle:~)% whichca check -hp google.com:443 -hp bing.com:443
    *.google.com is good!
    www.bing.com is good!
    (njohnson@greyeagle:~)%

## fetchca

This is to download and (optionally) verify a PEM CA bundle from a remote website
.  It defaults to the mozilla PEM bundle provided by curl.se.  Please don't
script this in such a way that it downloads the file more than once a day, but
since I actually default to stdout I don't have a good way to check file age
and do any attempt to enforce this.

    (njohnson@greyeagle:~)% whichca fetchca -out ca.pem
    verified 129 certificates in bundle downloaded from https://curl.se/ca/cacert.pem
    (njohnson@greyeagle:~)%

Note this verification is only that the certificates are parsable and valid.
## minca

This is a command for determining the minimum CA bundle needed to validate a list
of certificate bundles or websites.

For a local certificate bundle:

    whichca minca -p /path/to/cert/bundle.crt

or for a remote certificate at a given hostname:port

    whichca minca -hp host.whatever.com:443

If all goes well, it will spit out the PEM encoded version of the chain leading to the root certificate, minus the
certificate and intermediates found in the cert bundle(s) passed.

### dumpca

Additionally, on platforms that aren't Windows-based and when compiled against golang 1.15.* or earlier, it can be used
to get a full dump of the default system certificate bundle, with the following:

    whichca dumpca

The reason this only works for golang 1.15 or earlier is because with go 1.16
they changed the internal structure of the x509.CertPool, and I'm using
reflection to access an unexported field that no longer exists with go 1.16,
and there doesn't seem to be any workaround without a ton of work.  I guess it
was just a matter of time until the leopards ate *my* face.  For this reason, 
most of the binary releases are compiled with the latest golang 1.15.* toolchain,
except for darwin/arm64, which needs 1.16 to be able to support that platform.

## Flags

You can mix and match host:port and pathspec definitions on the same command, 
specifying any number of each

For example, this is valid:

    whichca minca -hp host.whatever.com:443,host2.whatever.com:443 -p '/path/to/*.crt' -p ./mycert.crt

Note the single quotes around the wildcard above. This is necessary to keep the shell from intercepting the wildcard
character.

To install, download a release binary from the releases page on github (preferred),
or to install from source simply:

    go get github.com/nathanejohnson/whichca
    
