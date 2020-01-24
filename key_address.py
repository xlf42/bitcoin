#!/usr/bin/env python

'''
    Bitcoin-Blockchain Implementation
    Copyright (C) 2020  Alex Hoffmann

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

'''

import codecs
import ecdsa
import hashlib


def base58_encode(data):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    b58_string = ''

    # in case we receive a string, we assume it would be a
    # hex number in a string and convert it. We will count leading
    # zeros as well to have it added to the encoded base58 string
    # more information: https://en.bitcoin.it/wiki/Base58Check_encoding
    if isinstance(data, str):
        # Get the number of leading zeros
        zeros = len(data) - len(data.lstrip('0'))
        # Convert hex to decimal
        data_int = int(data, 16)
    else:
        zeros = 0
        data_int = data

    # Append digits to the start of string
    while data_int > 0:
        digit_char = alphabet[data_int % 58]
        b58_string = digit_char + b58_string
        data_int //= 58
    # Add ‘1’ for each 2 leading zeros
    ones = zeros // 2
    for one in range(ones):
        b58_string = '1' + b58_string
    return b58_string


def base58_decode(s):
    """
    We get a base58 encoded string and return the corresponding integer number
    """
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    num = 0

    # we loop over each character and construct the integer number
    for c in s:
        num = num * 58 + alphabet.index(c)

    return num


def sha256_checksum(data):
    # Double SHA256 to get checksum
    sha256 = hashlib.sha256(data)
    sha256_digest = sha256.digest()
    sha256_2 = hashlib.sha256(sha256_digest)
    sha256_2_digest = sha256_2.digest()
    sha256_2_hex = codecs.encode(sha256_2_digest, 'hex')
    checksum = sha256_2_hex[:8]
    return checksum


def generate_privkey_wif(privkey):
    # first, we need to add the Private Key prefix 0x80 and suffix with
    # 0x01 to indicate a compressed public key (and resulting address)
    privkey_hex = '80' + privkey[2:] + '01'
    checksum = sha256_checksum(codecs.decode(privkey_hex, 'hex'))
    privkey_checksum_hex = privkey_hex + checksum.decode('utf-8')
    privkey_wif = base58_encode(privkey_checksum_hex)
    return privkey_wif


def decode_privkey_wif(privkey_wif, verify_checksum=True):
    """ We decode a wif-encoded private key back to the hex number.
    In case the checksum doesn't match, we return None """
    # first a simple base58 decoding
    privkey_wif_int = base58_decode(privkey_wif)
    print('privkey_wif_hex: 0x{:x}'.format(privkey_wif_int))
    # the last four bytes are the checksum
    privkey_checksum = privkey_wif_int % 0xFFFFFFFF
    # TODO: We need to do the checksum-check
    pass
    # now we remove the checksum we hardcode the removal of the
    # 'compression byte' and the prefix 0x80 (in a real implementation,
    # we should only remove the compression byte if it was there) we 'cheat'
    # by doing these operations on a hex string instead of doing the
    # integer arithmetics
    privkey_s = hex(privkey_wif_int)[4:-10]
    # now returning the key as an integer
    return int(privkey_s, 16)


def generate_pubkey(privkey):
    # we expect the privkey to be a string containing the
    # private key as 'normal' hex (prefixed with '0x')
    # stolen from
    # https://github.com/Destiner/blocksmith/blob/master/blocksmith/bitcoin.py
    privkey_bytes = codecs.decode(privkey[2:], 'hex')
    # Get ECDSA public key
    key = ecdsa.SigningKey.from_string(privkey_bytes, curve=ecdsa.SECP256k1).verifying_key
    key_bytes = key.to_string()
    key_hex = codecs.encode(key_bytes, 'hex')
    # Add bitcoin byte
    bitcoin_byte = b'04'
    pubkey = bitcoin_byte + key_hex
    return '0x' + pubkey.decode('ascii')


def generate_compressed_pubkey(privkey):
    # we expect the privkey to be a string containing the private key
    # as 'normal' hex (prefixed with '0x')
    # stolen from
    # https://github.com/Destiner/blocksmith/blob/master/blocksmith/bitcoin.py
    privkey_bytes = codecs.decode(privkey[2:], 'hex')
    # Get ECDSA public key
    key = ecdsa.SigningKey.from_string(privkey_bytes, curve=ecdsa.SECP256k1).verifying_key
    key_bytes = key.to_string()
    key_hex = codecs.encode(key_bytes, 'hex')
    # up to here, we do the same as we did for the 'uncompressed' key,
    # now we only store half of the key
    key_string = key_hex.decode('utf-8')
    half_len = len(key_hex) // 2
    key_half = key_hex[:half_len]
    # Add bitcoin byte: 0x02 if the last digit is even,
    # 0x03 if the last digit is odd
    last_byte = int(key_string[-1], 16)
    bitcoin_byte = b'02' if last_byte % 2 == 0 else b'03'
    pubkey = bitcoin_byte + key_half
    return '0x' + pubkey.decode('ascii')


def generate_address(pubkey):
    # stolen from
    # https://github.com/Destiner/blocksmith/blob/master/blocksmith/bitcoin.py
    pubkey_bytes = codecs.decode(pubkey[2:], 'hex')
    # Run SHA256 for the public key
    sha256_bpk = hashlib.sha256(pubkey_bytes)
    sha256_bpk_digest = sha256_bpk.digest()
    # Run ripemd160 for the SHA256
    ripemd160_bpk = hashlib.new('ripemd160')
    ripemd160_bpk.update(sha256_bpk_digest)
    ripemd160_bpk_digest = ripemd160_bpk.digest()
    ripemd160_bpk_hex = codecs.encode(ripemd160_bpk_digest, 'hex')
    # Add network byte
    network_byte = b'00'
    network_bitcoin_public_key = network_byte + ripemd160_bpk_hex
    network_bitcoin_public_key_bytes =\
        codecs.decode(network_bitcoin_public_key, 'hex')
    # Double SHA256 to get checksum
    checksum = sha256_checksum(network_bitcoin_public_key_bytes)
    # Concatenate public key and checksum to get the address
    address_hex = (network_bitcoin_public_key + checksum).decode('utf-8')
    wallet = base58_encode(address_hex)
    return wallet


if __name__ == '__main__':
    # assign *some* private key as integer (we use hex here)
    # I used the value from this page:
    # https://www.freecodecamp.org/news/how-to-create-a-bitcoin-wallet-address-from-a-private-key-eca3ddd9c05f/
    privkey =\
        0x60cf347dbc59d31c1358c8e5cf5e45b822ab85b79cb32a9f3d98184779a9efc2
    print('Private Key: 0x{:x}'.format(privkey))

    # new we convert it to the 'Wallet Import Format'(WIF) you can use
    # with Web Pages, Wallet Applications & stuff
    # The steps are described here:
    # https://en.bitcoin.it/wiki/Wallet_import_format
    privkey_wif = generate_privkey_wif(hex(privkey))
    print('Private Key (WIF): {:s}'.format(privkey_wif))

    # for educational purpose, we convert the wif formatted private key back
    # into the hex form
    privkey_edu = decode_privkey_wif(privkey_wif)
    print('Re-Converted Private Key: 0x{:x}'.format(privkey_edu))

    # we generate a public key, which is apparently rarely used, but is
    # the first step from the private key to the bitcoin address
    # here, we generate an uncompressed public key, which is rarely used
    pubkey = generate_pubkey(hex(privkey))
    print('Public Key: {:s}'.format(pubkey))

    # we only generate the compressed key as this is the 'default'
    pubkey_compressed = generate_compressed_pubkey(hex(privkey))
    print('Public Key Compressed: {:s}'.format(pubkey_compressed))

    # and finally the address
    address = generate_address(pubkey_compressed)
    print('Address: {:s}'.format(address))
