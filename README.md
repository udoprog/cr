Challenge Response Tool
===

*cr* is a simple tool for creating signature from rsa private keys.

The general idea is dead simple.

    #> cr sign -priv ~/.ssh/id_rsa -in data.txt -out signature.txt
    #> cr verify -priv ~/.ssh/id_rsa -in data.txt -sig signature.txt
    VERIFY SUCCESS

*cr* requires openssl, it's built using make.

    #> make

Have fun, this is the beginning of something interesting.
