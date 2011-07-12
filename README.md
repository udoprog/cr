Challenge Response Tool
===

**cr** is a simple tool for creating signature from rsa private keys.

The general idea is dead simple.

    #> cr sign -priv ~/.ssh/id_rsa -in data.txt -out signature.txt
    #> cr verify -priv ~/.ssh/id_rsa -in data.txt -sig signature.txt
    or
    #> cr verify -pub ~/.ssh/id_rsa.pem -in data.txt -sig signature.txt
    VERIFY SUCCESS

**cr** requires openssl, it's built using make.

    #> make

**cr** can use both DSA and RSA keys, in the format in which they are generated
by using _ssh-keygen_ or _openssl genrsa_.

This is how you extract your ssh public key from your private.

    #> openssl rsa -in ~/.ssh/id_rsa -pubout -out ~/.ssh/id_rsa.pem
    or
    #> openssl dsa -in ~/.ssh/id_dsa -pubout -out ~/.ssh/id_dsa.pem

Private key decryption is not yet supported.

Upcoming
---

* ssh-agent integration
* pageant integration
* firefox plugin (!)

Have fun, this is the beginning of something interesting.
