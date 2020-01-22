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
    privkey_wif = key_address.generate_privkey_wif(hex(privkey))
    assert privkey_wif == 'KzTtuNKTTUeS186RqeFtQ7WzVYagcT46ojzEhoudUiwwsWtvokhD'

    privkey_int = key_address.decode_privkey_wif(privkey_wif)
    assert privkey_int == 0x60cf347dbc59d31c1358c8e5cf5e45b822ab85b79cb32a9f3d98184779a9efc2

