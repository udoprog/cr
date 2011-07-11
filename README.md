Challenge Response Tool
===

cr is a simple tool for creating signature from rsa private keys.

The general idea is dead simple.
  #> cr sign -I ~/.ssh/id_rsa -i data.txt -o signature.txt
  #> cr verify -I ~/.ssh/id_rsa -i data.txt -s signature.txt
  VERIFY SUCCESS

cr requires openssl, it's built using make.
  #> make

Have fun, this is the beginning of something interesting.
