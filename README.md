Ever wanted to determine what the minimum CA bundle one would need to validate a given site(s)? Then this is for you!

#### Usage:

For a local certificate bundle:

    whichca minca -p /path/to/cert/bundle.crt

or for a remote certificate at a given hostname:port

    whichca minca -hp host.whatever.com:443

If all goes well, it will spit out the PEM encoded version of the chain leading to the root certificate, minus the
certificate and intermediates found in the cert bundle(s) passed.

#### Flags

You can mix and match host:port and pathspec definitions on the same command, specifying any number of each, and the
resulting output will be the minimum CA bundle of all certificates specified. Multiple path specs or hostport can be
specified either as a comma separated list, with wildcard globbing (in -p only), or with multiple occurrences of the -p
/ -hp flags.

For example, this is valid:

    whichca minca -hp host.whatever.com:443,host2.whatever.com:443 -p '/path/to/*.crt' -p ./mycert.crt

Note the single quotes around the wildcard above. This is necessary to keep the shell from intercepting the wildcard
character.

#### Dump CA command

Additionally, on platforms that aren't Windows-based and when compiled against golang 1.15.* or earlier, it can be used
to get a full dump of the default system certificate bundle, with the following:

    whichca dumpca

To install, simply:

    go get github.com/nathanejohnson/whichca
    
