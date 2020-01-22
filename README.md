# Bitcoin-Blockchain

Collection of python scripts on bitcoin

## References
 * Doing key conversions/generations on a web page with javascript 
   * https://iancoleman.io/bitcoin-key-compression/
   * https://gobittest.appspot.com/
 * Private Keys https://en.bitcoin.it/wiki/Private_key
 * Steps how to create a BTC address from Private Key: https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
 * Information on Base58 Encoding https://en.bitcoin.it/wiki/Base58Check_encoding
 
## Prerequisites
 * Python3 (python 3.7.3 in my case)
 * Library
   * ecdsa (pip3 install ecdsa)

## Disclaimer
Keys and addresses are the same I found on another page (https://www.freecodecamp.org/news/how-to-create-a-bitcoin-wallet-address-from-a-private-key-eca3ddd9c05f/).
 * I'm using GPL3, please read COPYING before you consider using this code for more than education
 * NEVER, EVER use the keys and addresses from this example productively!!
 * Should you consider using these scripts productively, you should know, what you're doing!

## key_address.py
### what is the script doing

We assign a 32 bytes integer number as our private key

```python
if __name__ == '__main__':
    # assign *some* private key as integer (we use hex here)
    # I used the value from this page: 
    # https://www.freecodecamp.org/news/how-to-create-a-bitcoin-wallet-address-from-a-private-key-eca3ddd9c05f/
    privkey = 0x60cf347dbc59d31c1358c8e5cf5e45b822ab85b79cb32a9f3d98184779a9efc2
    print('Private Key: 0x{:x}'.format(privkey))
```

We convert the private key into the so called Wallet Import format, which you can use on most tools handling them.

```python
    # new we convert it to the 'Wallet Import Format'(WIF) you can use
    # with Web Pages, Wallet Applications & stuff
    # The steps are described here: https://en.bitcoin.it/wiki/Wallet_import_format
    privkey_wif = generate_privkey_wif(hex(privkey))
    print('Private Key (WIF): {:s}'.format(privkey_wif))
```
For educational purpose, we convert the WIF formatted key back to the integer number:

```python
    # for educational purpose, we convert the wif formatted private key back into the hex form
    privkey_edu = decode_privkey_wif(privkey_wif)
    print('Re-Converted Private Key: 0x{:x}'.format(privkey_edu))
```
Now, the public key and the address

```python
    # we generate a public key, which is apparently rarely used, but is 
    # the first step from the private key to the bitcoin address
    pubkey = generate_pubkey(hex(privkey))
    print('Public Key: {:s}'.format(pubkey))

    # we only generate the compressed key as this is the 'default'
    pubkey_compressed = generate_compressed_pubkey(hex(privkey))
    print('Public Key Compressed: {:s}'.format(pubkey_compressed))

    # and finally the address
    address = generate_address(pubkey_compressed)
    print('Address: {:s}'.format(address))
```
## what the tests are doing
A test with takes the same key as in key_address.py and does a conversion into WIF and back checking the results.

```python
def test_privkey_wif():
    """
    Testing the conversion of private keys to WIF and back.
    """
    privkey = 0x60cf347dbc59d31c1358c8e5cf5e45b822ab85b79cb32a9f3d98184779a9efc2
    # testing conversion into WIF
    privkey_wif = key_address.generate_privkey_wif(hex(privkey))
    assert privkey_wif == 'KzTtuNKTTUeS186RqeFtQ7WzVYagcT46ojzEhoudUiwwsWtvokhD'
    # testing the conversion back
    privkey_int = key_address.decode_privkey_wif(privkey_wif)
    assert privkey_int == privkey
```

A test producing a 'Vanity Key' which is mostly for entertaining and educational reasons. Generating a readable private key has no benefit and should NEVER be used productively.

```python
def test_vanity_key():
    """
    We create a 'Vanity Key' and play around with it a little bit
    """
    # we assign a WIF encoded private key with a nice readable text in the middle
    # of course, only the Base58 alphabet is allowed.
    # Note: this string contains an invalid checksum at the end, so the final
    # private key will have a different suffix (with a fixed checksum)
    privkey_wif = 'KzXLF42sprivatekeyFtQ7WzVYagcT46ojzEhoudUiwwsCHCKSUM'
    # testing the conversion back
    privkey = key_address.decode_privkey_wif(privkey_wif)
    privkey_wif = key_address.generate_privkey_wif(hex(privkey))
    assert privkey_wif == 'KzXLF42sprivatekeyFtQ7WzVYagcT46ojzEhoudUiwwsCQkPe65'
``