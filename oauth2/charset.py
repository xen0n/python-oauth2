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

def to_unicode(s):
    """ Convert to unicode, raise exception with instructive error
    message if s is not unicode, ascii, or utf-8. """
    if not isinstance(s, unicode):
        if not isinstance(s, str):
            raise TypeError('You are required to pass either unicode or'
                            ' string here, not: %r (%s)' % (type(s), s)
                            )
        try:
            s = s.decode('utf-8')
        except UnicodeDecodeError, le:
            raise TypeError('You are required to pass either a unicode object'
                            ' or a utf-8 string here. You passed a Python'
                            ' string object which contained non-utf-8: %r.'
                            ' The UnicodeDecodeError that resulted from'
                            ' attempting to interpret it as utf-8 was: %s'
                            % (s, le,)
                            )
    return s

def to_utf8(s):
    return to_unicode(s).encode('utf-8')

def to_unicode_if_string(s):
    if isinstance(s, basestring):
        return to_unicode(s)
    else:
        return s

def to_utf8_if_string(s):
    if isinstance(s, basestring):
        return to_utf8(s)
    else:
        return s

def to_unicode_optional_iterator(x):
    """
    Raise TypeError if x is a str containing non-utf8 bytes or if x is
    an iterable which contains such a str.
    """
    if isinstance(x, basestring):
        return to_unicode(x)

    try:
        l = list(x)
    except TypeError, e:
        assert 'is not iterable' in str(e)
        return x
    else:
        return [ to_unicode(e) for e in l ]

def to_utf8_optional_iterator(x):
    """
    Raise TypeError if x is a str or if x is an iterable which
    contains a str.
    """
    if isinstance(x, basestring):
        return to_utf8(x)

    try:
        l = list(x)
    except TypeError, e:
        assert 'is not iterable' in str(e)
        return x
    else:
        return [ to_utf8_if_string(e) for e in l ]

