"""
The MIT License

Copyright (c) 2007-2010 Leah Culver, Joe Stump, Mark Paschal, Vic Fryzel

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

import base64
import urllib
import time
import random
import urlparse
import hmac
import binascii
import httplib2

try:
    from urlparse import parse_qs
    parse_qs # placate pyflakes
except ImportError:
    # fall back for Python 2.5
    from cgi import parse_qs

try:
    from hashlib import sha1
    sha = sha1
except ImportError:
    # hashlib was added in Python 2.5
    import sha

import _version

__version__ = _version.__version__


from .conf import OAUTH_VERSION, HTTP_METHOD, SIGNATURE_METHOD
from .exc import Error, MissingSignature
from .helper import build_authenticate_header, escape, \
                    generate_timestamp, generate_nonce, generate_verifier, \
                    setter
from .xoauth import build_xoauth_string

from .charset import to_unicode, to_utf8, \
                     to_unicode_if_string, to_utf8_if_string, \
                     to_unicode_optional_iterator, to_utf8_optional_iterator

# classes
from .consumer import Consumer
from .token import Token
from .request import Request
from .client import Client
from .server import Server
from .signature import SignatureMethod, \
                       SignatureMethod_HMAC_SHA1, SignatureMethod_PLAINTEXT
# exc

# helper
# xoauth
# helper

# consumer


# token

# helper

# request

# client

# server

# signature
