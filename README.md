This is a utility for
- Verifying a website presents enough information to validate a chain of trust
- Failing said verification, determine which intermediate certs (if any) 
  could be added to the server config to get it to a verified chain
- Can be used to download a CA bundle from the web (defaults to 
  curl.se's mozilla bundle)
- Can determine what the minimum CA bundle a client would need to verify
  a site / list of sites or certificate bundle files.
- Can dump the system's default CA bundle, including admin / user added certs
- Can convert and describe certificates the way `openssl x509` does


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

Only missing *intermediates* are reported. A server isn't expected to send its
root, so a self signed certificate encountered while walking up the chain isn't
a misconfiguration and won't be listed or written to the `-out` bundle.

### Dumping what the server sent

`-dump` shows exactly what the server returned -- the leaf plus any
intermediates it sent -- and nothing else. It is not a dump of what's missing;
those are written to `-out` (stdout by default) under their own banner, so when
both land on the same stream you can still tell them apart:

    #  ----------  intermediates to add     ----------
    # YR2
    -----BEGIN CERTIFICATE-----
    ...
    #  ---------- dumping return from server ----------
    #  ----------         leaf               ----------
    # *.badssl.com
    ...

`-dump-pretty` prints the same certificates as text instead, in the style of
`openssl x509 -noout -text`:

    (njohnson@greyeagle:~)% whichca check -hp google.com:443 -dump-pretty
    Certificate:
        Data:
            Version: 3 (0x2)
            Serial Number:
                ec:93:4f:15:80:11:38:30:12:47:ba:39:ec:e9:43:bb
            Signature Algorithm: ecdsa-with-SHA256
            Issuer: C=US, O=Google Trust Services, CN=WE2
    ...

A few extensions that go's x509 package doesn't decode -- signed certificate
timestamps, certificate policy qualifiers -- are printed as a hex dump rather
than broken out into fields.

Status messages go to stderr and certificate data goes to stdout, so you can
redirect a dump to a file and still watch the results scroll by.

### -system-verify

By default `check` builds an explicit root bundle and hands it to go's
verifier. `-system-verify` instead leaves the root pool empty, which is what
tells go to defer to the platform verifier.

That distinction matters on macOS and Windows, because those platform
verifiers chase the AIA extension and download missing intermediates
themselves. A server that never sends its intermediate will still verify --
which is convenient for a browser and useless for finding a misconfiguration.

Running both ways tells the two cases apart:

    (njohnson@greyeagle:~)% whichca check -hp incomplete-chain.badssl.com:443 -q
    *.badssl.com is not good :(
    YR2 is missing

    (njohnson@greyeagle:~)% whichca check -hp incomplete-chain.badssl.com:443 -q -system-verify
    *.badssl.com is good! :)

The second result is the OS papering over the problem. Any client that doesn't
fetch intermediates -- most non-browser TLS stacks -- sees the first result.

On Linux there's no separate platform verifier, so the flag makes no
difference there. It also conflicts with `-ca`, since an explicit bundle and
the platform's own roots are mutually exclusive.

## x509

Converts and displays certificates, along the lines of the `openssl x509`
command.

    -in       input file, '-' or unset reads stdin
    -out      output file, '-' or unset writes stdout
    -inform   PEM or DER.  detected from the input when unset
    -outform  PEM or DER, defaults to PEM
    -text     print the certificate in text form
    -noout    don't output the encoded certificate

With no arguments at all it reads a certificate from stdin and describes it,
which is the thing you usually want when you've just pasted something into a
terminal:

    (njohnson@greyeagle:~)% whichca x509 < cert.pem
    Certificate:
        Data:
            Version: 3 (0x2)
    ...

Otherwise it follows openssl's behavior: the encoded certificate goes to the
output unless `-noout`, and `-text` puts the text form in front of it.

`-inform` is optional because PEM and DER are trivial to tell apart, but it's
there if you want to be explicit.  Converting between the two:

    whichca x509 -in cert.pem -outform DER -out cert.der
    whichca x509 -in cert.der -outform PEM -out cert.pem

Both directions produce byte for byte the same output as the equivalent
`openssl x509` invocation.

Unlike `openssl x509`, which stops after the first certificate, this reads
every certificate in the input.  That makes it useful on bundles, and it
composes with the other subcommands:

    whichca check -hp badssl.com:443 -q -dump | whichca x509 -text -noout

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

So if a server sends its intermediates, they're left out -- you don't need them
in a bundle, the server hands them over. If it's missing one, that intermediate
is fetched and included, since without it the bundle can't reach the leaf.

Where a root is cross signed the leaf verifies by more than one path, and every
path is kept. Which one a given client can actually use depends on what its
trust store already has, and that's the whole point of the cross signature.

## dumpca

Dumps the system certificate bundle:

    whichca dumpca

Add `-csv` to get the metadata as CSV instead of PEM.

Only certificates the platform actually trusts are dumped.  That distinction
matters on macOS, where a keychain stores certificates whether they're
trust anchors: intermediates you've collected, a root someone imported and
never trusted, certificates trusted only for S/MIME or code signing.  Pass
`-untrusted` to get everything that's merely present as well.  On Windows and
other \*nix platforms the flag does nothing, since the stores those read expose
trust anchors only.

How the certificates get collected depends on the platform:

**macOS** uses the `security find-certificate -ap` utility, which is what golang
did under the covers until recently when they decided to defer to the darwin keychain api
for verification.  It reads both the roots apple ships and the keychains on the
default search list, so admin and user installed roots -- MDM, corporate
filters, debugging proxies -- show up alongside the shipped ones.  Results are
deduplicated, since the same root often sits in more than one keychain, and
leaf identities in those keychains are skipped so the output stays a CA bundle.

That call returns certificates regardless of trust, so the results are checked
against the platform's trust settings, read from `security
trust-settings-export`.  The user, admin and system domains are consulted in
that order and the first one holding an entry for a certificate decides, which
is how a locally installed root overrides what apple ships.  A certificate no
domain mentions is present in a keychain but not an anchor, and is dropped
unless you asked for `-untrusted`.  Settings scoped to unrelated policies --
S/MIME, code signing -- don't count towards trusting a root here.

There are some caveats here, one being that the darwin keychain
is more lax than the golang x509 parser, so some certs in the keychain might not get
parsed correctly by golang.  In the case it finds one of these, it will print the
certificate in PEM form on stderr with a warning in the comments.  See
[here](https://github.com/golang/go/issues/47689) for details.  All
verified certificates will be printed on stdout.

**Windows** enumerates the `ROOT` system store through the CryptoAPI.  Note that
windows populates that store on demand via Windows Update, so this returns the
roots currently cached on the machine rather than every root windows would
eventually be willing to trust.

`x509.SystemCertPool` is no help on either of those two platforms: it hands back
an empty pool flagged as a system pool, which only tells `Verify` to delegate to
the OS rather than exposing any certificates.

**Other \*nix platforms** call `x509.SystemCertPool` and do some reflect nastiness
to ferret out the certs.

## Flags

You can mix and match host:port and pathspec definitions on the same command, 
specifying any number of each

For example, this is valid:

    whichca minca -hp host.whatever.com:443,host2.whatever.com:443 -p '/path/to/*.crt' -p ./mycert.crt

Note the single quotes around the wildcard above. This is necessary to keep the shell from intercepting the wildcard
character.

To install, download a release binary from the releases page on github (preferred),
or to install from source simply:

    go install github.com/nathanejohnson/whichca@latest
    
