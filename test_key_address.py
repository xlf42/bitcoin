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

import key_address


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


def test_vanity_key():
    """
    We create a 'Vanity Key' and play around with it a little bit
    """
    # we assign a WIF encoded private key with a nice readable text in the middle
    # of course, only the Base58 alphabet is allowed.
    # Note: this string contains an invalid checksum at the end, so the final
    # private key will have a different suffix (with a fixed checksum)
    privkey_wif = 'KzXLF42sprivatekeyFtQ7WzVYagcT46ojzEhoudUiwwsCHCKSUM'
    # testing the conversion back, it should fail in case we verify the checksum
    privkey = key_address.decode_privkey_wif(privkey_wif, verify_checksum=True)
    assert privkey == None
    # testing the conversion back, it should fail in case we verify the checksum
    privkey = key_address.decode_privkey_wif(privkey_wif, verify_checksum=False)
    assert privkey == 44587851312071854085406562145079607654624912002403596259516646850170878049971
    privkey_wif = key_address.generate_privkey_wif(hex(privkey))
    assert privkey_wif == 'KzXLF42sprivatekeyFtQ7WzVYagcT46ojzEhoudUiwwsCQkPe65'


def test_address_generation():
    """
    We start from a private key and generate an address
    """
    privkey = 0x60cf347dbc59d31c1358c8e5cf5e45b822ab85b79cb32a9f3d98184779a9efc2
    # we only generate the compressed key as this is the 'default'
    pubkey_compressed = key_address.generate_compressed_pubkey(hex(privkey))
    assert pubkey_compressed == '0x031e7bcc70c72770dbb72fea022e8a6d07f814d2ebe4de9ae3f7af75bf706902a7'
    # and finally the address
    address = key_address.generate_address(pubkey_compressed)
    assert address == '17JsmEygbbEUEpvt4PFtYaTeSqfb9ki1F1'
