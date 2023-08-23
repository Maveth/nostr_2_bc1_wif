# nostr_2_bc1_wif
Python Code to convert any public key to a bc1 address, or private key to wif wallet. with nostr npub-nsec
This is provided as is, it works for me
You may have to install some dependancies

You can use either a pub hexkey or a npub key from nostr to get a bc1 bitcoin address
This should be the same address you get when you use your private key
the private key will also print the legacy addresses, but the bc1 should be the same
this will also print a wif (wallet import), tested on bluewallet and electrum
you will will want to select the type, PK2WPKH for the bc1

if you use the following public key:
d4d4fdde8ab4924b1e452e896709a3bd236da4c0576274b52af5992d4d34762c
it will give you this address:
bc1q95xv5qm0uu7wzpaun7ayz7dgt9zcmxun7m58vs

and if you look that address in blockexplorer or mempool you will see a transaction.

technically with this, anyone using a nostr account also has a bitcoin account, as long as they access to private key they can access the funds.

** this might be a good account verification model, if an account has funds it has skin in the game

confirm it all works first with your info, but it should
Might update later
