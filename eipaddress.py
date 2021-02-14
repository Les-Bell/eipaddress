"""A faster, lightweight IPv4/IPv6 manipulation library in Python.

This module is used to create/poke/manipulate IPv4 and IPv6 addresses
and networks.
"""

from collections import deque

# =============================================================================
# Module specific constants
# =============================================================================

__version__ = '0.1.0'

# IP version numbers
IPV4 = 4
IPV6 = 6

# IP address length, in bits
IPV4LENGTH = 32
IPV6LENGTH = 128

# Max IP address integer
MAX_IPV4 = 2**IPV4LENGTH - 1
MAX_IPV6 = 2**IPV6LENGTH - 1

# =============================================================================
# Module specific exceptions
# =============================================================================

class AddressValueError(ValueError):
    """A Value Error related to the address."""

class NetmaskValueError(ValueError):
    """A Value Error related to the netmask."""

# =============================================================================
# Factory functions
# =============================================================================

def ip_address(address):
    """Take an IP string/int and return an object of the correct type.

    Args:
        address: A string or integer, the IP address.  Either IPv4 or
            IPv6 addresses may be supplied; integers less than 2**32
            will be considered to be IPv4 by default.

    Returns:
        An IPv4Address or IPv6Address object.

    Raises:
        ValueError: if address is not a v4 or a v6 address
    """
    try:
        return IPv4Address(address)
    except (AddressValueError, NetmaskValueError):
        pass
    try:
        return IPv6Address(address)
    except (AddressValueError, NetmaskValueError):
        pass
    raise AddressValueError('%r is not an IPv4 or IPv6 address' % address)

def ip_network(address, strict=True):
    """Take an IP string/int and return an object of the correct type.

    Args:
        address: A string, integer, or a tuple of strings or integers
            representing the IP network as an IP address and optional
            prefix.

        strict: A boolean. If True, ensure that the IP address is a
          true network address, i.e. the host bits (after the prefix)
          must all be zero.

    Returns:
        An IPv4Network or IPv6Network object.

    Raises:
        ValueError: if address is not a v4 or a v6 network,
            or if it has host bits set and strict is True.
    """
    try:
        return IPv4Network(address, strict)
    except (AddressValueError, NetmaskValueError):
        pass
    try:
        return IPv6Network(address, strict)
    except (AddressValueError, NetmaskValueError):
        pass
    raise AddressValueError('%r is not an IPv4 or IPv6 network' % address)

def ip_interface(address):
    """Take an IP string/int and return an object of the correct type.

    Args:
        address: A string, integer, or a tuple of strings or integers
            representing the IP interface as an IP address and optional
            network prefix.

    Returns:
        An IPv4Interface or IPv6Interface object.

    Raises:
        ValueError: if address is not a v4 or a v6 address

    Notes:
        The IPv?Interface classes describe an Address on a particular
        Network, so they're basically a combination of both the Address
        and Network classes.
    """
    try:
        return IPv4Interface(address)
    except (AddressValueError, NetmaskValueError):
        pass
    try:
        return IPv6Interface(address)
    except (AddressValueError, NetmaskValueError):
        pass
    raise AddressValueError('%r is not an IPv4 or IPv6 address' % address)

# =============================================================================
# Utility functions
# =============================================================================

_HEX_DIGITS = frozenset('0123456789ABCDEFabcdef')

def ishexdigit(txt):
    """Returns True if all characters are hex digits"""
    for digit in txt:
        if digit not in _HEX_DIGITS:
            return False
    # an empty string is not hex
    return txt != ''

def v4_int_to_packed(address):
    """Represent an address as 4 packed bytes in network (big-endian) order.

    Args:
        address: An integer representation of an IPv4 IP address.

    Returns:
        The 4-byte packed integer address in network (big-endian) order.

    Raises:
        ValueError: If address is negative or too large for an IPv4 address.
    """
    try:
        return address.to_bytes(4, 'big')
    except OverflowError:
        raise ValueError('Address negative or too large for IPv4')

def v6_int_to_packed(address):
    """Represent an address as 16 packed bytes in network (big-endian) order.

    Args:
        address: An integer representation of an IPv6 IP address.

    Returns:
        The 16-byte packed integer address in network (big-endian) order.

    Raises:
        ValueError: If address is negative or too large for an IPv6 address.
    """
    try:
        return address.to_bytes(16, 'big')
    except OverflowError:
        raise ValueError('Address negative or too large for IPv6')

def _count_righthand_zero_bits(number, bits):
    """Count the number of zero bits on the right hand side.

    Args:
        number: An integer.
        bits: Maximum number of bits to count.

    Returns:
        The number of zero bits on the right hand side of the number.
    """
    if number == 0:
        return bits
    return min(bits, (~number & (number - 1)).bit_length())

def _summarize_address_range(first, last, net_class):
    """Summarize a network range from the first and last address integers.

    This internal method assumes all validation has already been done.

    Example:
        >>> list(_summarize_address_range(int(IPv4Address('192.0.2.0')),
        ...                               int(IPv4Address('192.0.2.130'))))
        [IPv4Network('192.0.2.0/25'), IPv4Network('192.0.2.128/31'),
         IPv4Network('192.0.2.130/32')]

    Args:
        first: The first integer address in the range.
        last: The last integer address in the range.
        net_class: the class of the network objects to return

    Returns:
        An iterator of the summarized IPv(4|6) network objects.
    """
    ip_bits = net_class._address_len
    while first <= last:
        nbits = min(_count_righthand_zero_bits(first, ip_bits),
                    (last - first + 1).bit_length() - 1)
        net = net_class((first, ip_bits - nbits))
        yield net
        first += 1 << nbits
        if first - 1 == net_class._max_address:
            break

def summarize_address_range(first, last):
    """Summarize a network range given the first and last IP addresses.

    Example:
        >>> list(summarize_address_range(IPv4Address('192.0.2.0'),
        ...                              IPv4Address('192.0.2.130')))
        [IPv4Network('192.0.2.0/25'), IPv4Network('192.0.2.128/31'),
         IPv4Network('192.0.2.130/32')]

    Args:
        first: The first IPv4Address or IPv6Address in the range.
        last: The last IPv4Address or IPv6Address in the range.

    Returns:
        An iterator of the summarized IPv(4|6) network objects.

    Raises:
        TypeError:
            If first and last are not IP addresses of the same version.
        ValueError:
            If the last object is not greater than the first.
    """
    if (not isinstance(first, _BaseIPAddress) or
            not isinstance(first, last.__class__)):
        raise TypeError('first (%r) and last (%r) must be IP addresses '
                        'of the same type' % (first, last))
    if first > last:
        raise ValueError('first address is greater than last' % (first, last))
    return _summarize_address_range(first._ip, last._ip, last._network_class)

def collapse_addresses(addresses):
    """Collapse a list of IP objects.

    Example:
        collapse_addresses([IPv4Network('192.0.2.0/25'),
                            IPv4Network('192.0.2.128/25')]) ->
                           [IPv4Network('192.0.2.0/24')]

    Args:
        addresses: An iterator of IPv4Network or IPv6Network objects.

    Returns:
        An iterator of the collapsed IPv(4|6)Network objects.

    Raises:
        TypeError: If passed a list of mixed version objects.
    """
    # sort nets so we only have to check each net against the previous one
    nets = sorted(addresses, key=get_mixed_type_key)
    first, last = None, None
    for net in nets:
        if isinstance(net, _BaseIPAddress):
            net = net._network_class(net._ip)
        elif (not isinstance(net, _BaseIPNetwork) or
              net.version != nets[0].version):
            raise TypeError('%r and %r must be networks or addresses '
                            'of the same IP version' % (nets[0], net))
        if first is None:
            first, last = net._ip, net._broadcast_int
        elif net._ip == last + 1:
            # net is adjacent, merge with the previous range
            last = net._broadcast_int
        elif net._ip > last:
            # net is not adjacent, yield the previous range
            yield from _summarize_address_range(first, last, net.__class__)
            first, last = net._ip, net._broadcast_int
    # add the final range
    if first is not None:
        yield from _summarize_address_range(first, last, net.__class__)

def get_mixed_type_key(obj):
    """Get a key suitable for sorting IP networks and addresses.

    Address, Network and Interface objects are not sortable by default;
    they are fundamentally different, so the expression

        IPv4Address('192.0.2.0') <= IPv4Network('192.0.2.0/24')

    does not make any sense.  However, if you wish to sort mixed types
    anyway, you may use this function as the key= argument to sorted().

    Args:
        obj: Either a Network, Interface or Address object.

    Returns:
        The key value, or NotImplemented if obj does not support it.
    """
    try:
        return obj._get_mixed_type_key()
    except AttributeError:
        return NotImplemented

# =============================================================================
# IP Base classes for addresses and networks
# =============================================================================

class _BaseIP:
    """A base class for IP addresses and networks.

    The following attributes must be provided by derived classes:
        _version        The IP version number, IPV4 or IPV6
        _address_len    The address length, in bits
    The following methods must be implemented in derived classes:
        __str__         Return the value as a string
    """

    __slots__ = ()

    def __repr__(self):
        """A string representation of this object."""
        return "%s('%s')" % (self.__class__.__name__, self.__str__())

    @property
    def version(self):
        """The IP version of this object."""
        return self._version

    @property
    def max_prefixlen(self):
        """Returns the maximum prefix length for networks of this type."""
        return self._address_len

    @property
    def compressed(self):
        """The short string representation of this object."""
        return self.__str__()

class _BaseIPv4:
    """A base class mix-in for IPv4 classes."""

    __slots__ = ()

    _version = IPV4
    _max_address = MAX_IPV4
    _address_len = IPV4LENGTH

    @property
    def exploded(self):
        """The fully expanded string representation of this object"""
        return self.__str__()

    @property
    def reverse_pointer(self):
        """The name of the reverse DNS pointer for the IP address.

        As described in RFC3596 2.5.  e.g:
            >>> ip_address("127.0.0.1").reverse_pointer
            '1.0.0.127.in-addr.arpa'
        """
        reverse_octets = self.__str__().split('.')[::-1]
        return '.'.join(reverse_octets) + '.in-addr.arpa'

class _BaseIPv6:
    """A Base class mix-in for IPv6 classes."""

    __slots__ = ()

    _version = IPV6
    _max_address = MAX_IPV6
    _address_len = IPV6LENGTH

    @property
    def reverse_pointer(self):
        """The name of the reverse DNS pointer for the IP address.

        As described in RFC3596 2.5.  e.g:
            >>> ip_address("2001:db8::1").reverse_pointer
            '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa'
        """
        reverse_chars = self.exploded[::-1].replace(':', '')
        return '.'.join(reverse_chars) + '.ip6.arpa'

# =============================================================================
# IP Address classes
# =============================================================================

_address_fmt_re = None

class _BaseIPAddress(_BaseIP):
    """A base class for an IP Address, do not instantiate directly.

    The following attributes must be provided by derived classes:
        _version        The IP version number, IPV4 or IPV6
        _address_len    The address length, in bits
    The following methods must be implemented in derived classes:
        __str__         Return the value as a string
    """

    __slots__ = ()

    def __int__(self):
        """The IP address as an integer."""
        return self._ip

    def __add__(self, delta):
        """Get a new IP address whose integer value is self._ip+delta.

        Args:
            delta: The integer to add to this IP address.

        Returns:
            A new IP address (of the same type as this).
        """
        if not isinstance(delta, int):
            return NotImplemented
        return self.__class__(self._ip + delta)

    def __sub__(self, delta):
        """Get a new IP address whose integer value is self._ip-delta.

        Args:
            delta: The integer to subtract from this IP address.

        Returns:
            A new IP address (of the same type as this).
        """
        if not isinstance(delta, int):
            return NotImplemented
        return self.__class__(self._ip - delta)

    def __format__(self, fmt):
        """Returns an IP address as a formatted string.

        Supported presentation types are:
        's': returns the IP address as a string (default)
        'b': converts to binary and returns a zero-padded string
        'X' or 'x': converts to upper- or lower-case hex and returns a
            zero-padded string
        'n': the same as 'b' for IPv4 and 'x' for IPv6

        For binary and hex presentation types, the alternate form
        specifier '#' and the grouping option '_' are supported.

        Args:
            fmt: The format string.
        """
        # Support string formatting
        if not fmt or fmt[-1] == 's':
            return format(self.__str__(), fmt)
        # From here on down, support for 'bnXx'
        global _address_fmt_re
        if _address_fmt_re is None:
            import re
            _address_fmt_re = re.compile('(#?)(_?)([xbnX])')
        m = _address_fmt_re.fullmatch(fmt)
        if not m:
            return super().__format__(fmt)
        alternate, grouping, fmt_base = m.groups()
        # Set some defaults
        if fmt_base == 'n':
            # Binary is default for IPv4; hex for IPv6.
            fmt_base = 'b' if self._version == IPV4 else 'x'
        padlen = self._address_len
        if fmt_base != 'b':
            padlen //= 4
        if grouping:
            padlen += padlen // 4 - 1
        if alternate:
            padlen += 2  # 0b or 0x
        return format(self._ip, f'{alternate}0{padlen}{grouping}{fmt_base}')

    @property
    def is_reserved(self):
        """Test if the address is otherwise IETF reserved.

        Returns:
            A boolean, True if the address is within one of the
            reserved IPv6 Network ranges.
        """
        for net in self._constants._reserved_nets:
            if net._contains(self._ip):
                return True
        return False

    @property
    def is_private(self):
        """Test if this address is allocated for private networks.

        Returns:
            A boolean, True if the address is reserved per
            iana-ipv4-special-registry / iana-ipv6-special-registry.
        """
        if self._private is None:
            self._private = False
            for net in self._constants._private_nets:
                if net._contains(self._ip):
                    self._private = True
                    break
        return self._private

    @property
    def is_multicast(self):
        """Test if the address is reserved for multicast use.

        Returns:
            A boolean, True if the address is multicast.
            See RFC 3171 for details (IPv4) or RFC 2373 2.7 (IPv6).
        """
        return self._constants._multicast_net._contains(self._ip)

    @property
    def is_unspecified(self):
        """Test if the address is unspecified.

        Returns:
            A boolean, True if this is the unspecified address,
            as defined in RFC 5735 3 (IPv4) or RFC 2373 2.5.2 (IPv6).
        """
        return self._ip == 0

    @property
    def is_link_local(self):
        """Test if the address is reserved for link-local.

        Returns:
            A boolean, True if the address is link-local per
            RFC 3927 (IPv4) or RFC 4291 (IPv6).
        """
        return self._constants._linklocal_net._contains(self._ip)

# =============================================================================

class IPv4Address(_BaseIPAddress, _BaseIPv4):
    """An IPv4 Address."""

    __slots__ = ('_ip', '_private')

    @staticmethod
    def from_string(txt):
        """Convert an IPv4 address string to an integer.

        The string format is "a.b.c.d", where a, b, c and d are decimal
        integers in the range 0 to 255, inclusive.  Spaces, or leading
        zeros, are not permitted.

        Args:
            txt: An IPv4 address string

        Returns:
            The IPv4 address as an integer

        Raises:
            AddressValueError if the string is not a valid IPv4 address.
        """
        words = txt.split('.')
        if len(words) != 4:
            raise AddressValueError('IPv4 string is not n.n.n.n: %r' % (txt,))
        ip = 0
        for word in words:
            if not word.isdigit():
                raise AddressValueError('non-decimal word: %r' % (txt,))
            if word[0] == '0' and len(word) != 1:
                raise AddressValueError('leading zero not allowed: %r' % (txt,))
            val = int(word, 10)
            if val > 255:
                raise AddressValueError('value too big: %r' % (txt,))
            ip = (ip << 8) + val
        return ip

    @staticmethod
    def _to_string(ip):
        """Convert an integer to an IPv4 address string.

        Args:
            ip: The address integer

        Returns:
            The address string
        """
        return '%s.%s.%s.%s' % (ip >> 24 & 0xff, ip >> 16 & 0xff,
                                ip >>  8 & 0xff, ip >>  0 & 0xff)

    @classmethod
    def to_string(cls, ip):
        """Convert an integer to an IPv4 address string.

        Args:
            ip: The address integer

        Returns:
            The address string

        Raises:
            AddressValueError if the ip address is not valid
        """
        if not 0 <= ip <= MAX_IPV4:
            raise AddressValueError('IPv4 integer out of range: %r' % (ip,))
        return cls._to_string(ip)

    to_string_exploded = to_string

    def __init__(self, address):
        """Instantiate a new IP address.

        The string format is "a.b.c.d", where a, b, c and d are decimal
        integers in the range 0 to 255, inclusive.  Spaces, or leading
        zeros, are not permitted.

        Integer values must be in the range 0 to 2**32 - 1, inclusive.

        Args:
            address: The address value as a string, an integer or bytes
        """
        if isinstance(address, int):
            self._ip = address
        elif isinstance(address, bytes):
            self._ip = int.from_bytes(address, 'big')
        elif isinstance(address, str):
            self._ip = self.from_string(address)
        else:
            raise AddressValueError('invalid address: %r' % (address,))
        if not 0 <= self._ip <= self._max_address:
            raise AddressValueError('invalid address: %r' % (address,))
        self._private = None

    def __str__(self):
        return self._to_string(self._ip)

    def __reduce__(self):
        return self.__class__, (self._ip,)

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self._ip == other._ip

    def __ne__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self._ip != other._ip

    def __lt__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self._ip < other._ip

    def __le__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self._ip <= other._ip

    def __gt__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self._ip > other._ip

    def __ge__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self._ip >= other._ip

    def __hash__(self):
        return hash(self._ip)

    @property
    def packed(self):
        """The binary representation of this address."""
        return self._ip.to_bytes(4, 'big')

    @property
    def is_global(self):
        return not (self._constants._public_net._contains(self._ip) or
                    self.is_private)

    @property
    def is_loopback(self):
        """Test if the address is a loopback address.

        Returns:
            A boolean, True if the address is a loopback per RFC 3330.
        """
        return self._constants._loopback_net._contains(self._ip)

    def _get_mixed_type_key(self):
        """Return a value suitable for mixed type ordering."""
        return self._version, self._ip

# =============================================================================

class IPv6Address(_BaseIPAddress, _BaseIPv6):
    """An IPv6 Address."""

    __slots__ = ('_ip', '_private', '_scope')

    @staticmethod
    def from_string(txt):
        """Convert an IPv6 address string to an integer.

        The string format is "n1:n2:n3:n4:n5:n6:n7:n8", where n1 to n8
        are hexadecimal integers in the range 0 to FFFF, inclusive.  A
        single sequence of consecutive words with a value of 0 may be
        represented as '::'.

        The last two hexadecimal integers, n7 and n8, may alternatively
        be expressed as an IPv4 address in the format "a.b.c.d", where
        a, b, c and d are decimal integers in the range 0 to 255,
        inclusive.  Leading zeros are permitted in n1 to n8, up to a
        maximum of 4 hex digits.  Leading zeros are not permitted in a
        to d.

        Spaces are not permitted anywhere in the string.

        Args:
            txt: An IPv6 address string

        Returns:
            The IPv4 address as an integer

        Raises:
            AddressValueError if the string is not a valid IPv6 address.
        """
        parts = txt.split('::')
        numparts = len(parts)
        if numparts > 2:
            raise AddressValueError('multiple "::" ranges: %r' % (txt,))
        # store lists of values before (head) and after (tail) the '::'
        head, tail = [], []
        values = head
        ipv4_part = None
        for i in range(numparts):
            if parts[i]:
                for word in parts[i].split(':'):
                    if ipv4_part is not None:
                        # nothing allowed after the IPv4 part of the address
                        raise AddressValueError('invalid address: %r' % (txt,))
                    if not ishexdigit(word):
                        if i + 1 == numparts:
                            # an IPv4 address may be at the end of the last part
                            try:
                                ipv4_part = IPv4Address.from_string(word)
                            except AddressValueError:
                                raise AddressValueError(
                                        'invalid address: %r' % (txt,))
                            # valid IPv4 address
                            values.extend([ipv4_part >> 16, ipv4_part & 0xffff])
                            continue
                        raise AddressValueError('invalid address: %r' % (txt,))
                    if len(word) > 4:
                        raise AddressValueError('invalid address: %r' % (txt,))
                    val = int(word, 16)
                    values.append(val)
            values = tail
        # build a single list of values, filling the gap with 0's
        if numparts == 2:
            numwords = len(head) + len(tail)
            if numwords >= 8:
                raise AddressValueError('too many words: %r' % (txt,))
            # extend the head values with the missing 0's and the tail
            head.extend([0] * (8 - numwords))
            head.extend(tail)
        elif len(head) != 8:
            raise AddressValueError('too many/few words: %r' % (txt,))
        ip = 0
        for val in head:
            ip = (ip << 16) + val
        return ip

    @classmethod
    def from_string_with_scope(cls, txt):
        """Convert an IPv6 address string to an integer and scope_id.

        The string format is "n1:n2:n3:n4:n5:n6:n7:n8%s", where n1 to n8
        are hexadecimal integers in the range 0 to FFFF, inclusive, and
        s is the scope_id.  A single sequence of consecutive words (in
        n1 to n8) with a value of 0 may be represented as '::'.  The
        scope_id is an arbitrary string.

        The last two hexadecimal integers, n7 and n8, may alternatively
        be expressed as an IPv4 address in the format "a.b.c.d", where
        a, b, c and d are decimal integers in the range 0 to 255,
        inclusive.  Leading zeros are permitted in n1 to n8, up to a
        maximum of 4 hex digits.  Leading zeros are not permitted in a
        to d.

        Spaces are not permitted anywhere in the string.

        Args:
            txt: An IPv6 address string

        Returns:
            A tuple of the IPv6 address integer and the scope_id string

        Raises:
            AddressValueError if the string is not a valid IPv6 address.
        """
        parts = txt.split('%')
        if len(parts) == 1:
            scope = None
        elif len(parts) == 2:
            scope = parts[1]
        else:
            raise AddressValueError('multiple scopes: %r' % (txt,))
        return cls.from_string(parts[0]), scope

    @staticmethod
    def _to_string(ip, scope=None):
        """Convert an integer to an IPv6 address string.

        Args:
            ip: The address integer
            scope: The scope_id string, or None

        Returns:
            The address string
        """
        words = (ip >> 112 & 0xffff,
                 ip >>  96 & 0xffff,
                 ip >>  80 & 0xffff,
                 ip >>  64 & 0xffff,
                 ip >>  48 & 0xffff,
                 ip >>  32 & 0xffff,
                 ip >>  16 & 0xffff,
                 ip >>   0 & 0xffff)
        # find the longest sequence of zeros (start, length)
        zeros = 0, 0
        start, length, index = 0, 0, 0
        for word in words:
            if word == 0:
                if length == 0:
                    start = index
                length += 1
            elif length > 0:
                if length > zeros[1]:
                    zeros = start, length
                length = 0
            index += 1
        # compress the (first) longest zero sequence
        if length <= zeros[1]:
            start, length = zeros
        if length > 1:
            # replace longest zero sequence with '::'
            head = ':'.join(('%x' % x for x in words[:start]))
            tail = ':'.join(('%x' % x for x in words[start + length:]))
            _str = '::'.join([head, tail])
        else:
            # no zero sequence
            _str = ':'.join(('%x' % x for x in words))
        return _str if not scope else '%'.join((_str, scope))

    @classmethod
    def to_string(cls, ip, scope=None):
        """Convert an integer to an IPv6 address string.

        Args:
            ip: The address integer
            scope: The scope_id string, or None

        Returns:
            The address string

        Raises:
            AddressValueError if the ip address is not valid
        """
        if not 0 <= ip <= MAX_IPV6:
            raise AddressValueError('IPv6 integer out of range: %r' % (ip,))
        return cls._to_string(ip, scope)

    @staticmethod
    def _to_string_exploded(ip, scope=None):
        """Convert an integer to an exploded IPv6 address string.

        Args:
            ip: The address integer
            scope: The scope_id string, or None

        Returns:
            The address string
        """
        _str = '%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x' % (ip >> 112 & 0xffff,
                                                            ip >>  96 & 0xffff,
                                                            ip >>  80 & 0xffff,
                                                            ip >>  64 & 0xffff,
                                                            ip >>  48 & 0xffff,
                                                            ip >>  32 & 0xffff,
                                                            ip >>  16 & 0xffff,
                                                            ip >>   0 & 0xffff)
        if scope:
            _str = '%'.join((_str, scope))
        return _str

    @classmethod
    def to_string_exploded(cls, ip, scope=None):
        """Convert an integer to an exploded IPv6 address string.

        Args:
            ip: The address integer
            scope: The scope_id string, or None

        Returns:
            The address string

        Raises:
            AddressValueError if the ip address is not valid
        """
        if not 0 <= ip <= MAX_IPV6:
            raise AddressValueError('IPv6 integer out of range: %r' % (ip,))
        return cls._to_string_exploded(ip, scope)

    def __init__(self, address):
        """Instantiate a new IP address.

        Args:
            address: The address value as a string, an integer or bytes.
        """
        self._scope = self._private = None
        if isinstance(address, int):
            self._ip = address
        elif isinstance(address, bytes):
            self._ip = int.from_bytes(address, 'big')
        elif isinstance(address, str):
            self._ip, self._scope = self.from_string_with_scope(address)
        else:
            raise AddressValueError('invalid address: %r' % (address,))
        if not 0 <= self._ip <= self._max_address:
            raise AddressValueError('invalid address: %r' % (address,))

    def __str__(self):
        return self._to_string(self._ip, self._scope)

    @property
    def exploded(self):
        """The fully expanded string representation of the IP address."""
        return self._to_string_exploded(self._ip, self._scope)

    def __reduce__(self):
        arg = self._ip if self._scope is None else self.__str__()
        return self.__class__, (arg,)

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self._ip == other._ip and self._scope == other._scope

    def __ne__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self._ip != other._ip or self._scope != other._scope

    def __lt__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        self_scope = '' if self._scope is None else self._scope
        other_scope = '' if other._scope is None else other._scope
        return (self._ip < other._ip or
                (self._ip == other._ip and self_scope < other_scope))

    def __le__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        self_scope = '' if self._scope is None else self._scope
        other_scope = '' if other._scope is None else other._scope
        return (self._ip < other._ip or
                (self._ip == other._ip and self_scope <= other_scope))

    def __gt__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        self_scope = '' if self._scope is None else self._scope
        other_scope = '' if other._scope is None else other._scope
        return (self._ip > other._ip or
                (self._ip == other._ip and self_scope > other_scope))

    def __ge__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        self_scope = '' if self._scope is None else self._scope
        other_scope = '' if other._scope is None else other._scope
        return (self._ip > other._ip or
                (self._ip == other._ip and self_scope >= other_scope))

    def __hash__(self):
        return hash((self._ip, self._scope))

    @property
    def scope_id(self):
        """Identifier of a particular zone of the address's scope.

        See RFC 4007 for details.

        Returns:
            A string identifying the zone of the address, if specified,
            else None.
        """
        return self._scope

    @property
    def packed(self):
        """The binary representation of this address."""
        return self._ip.to_bytes(16, 'big')

    @property
    def ipv4_mapped(self):
        """Return the IPv4 mapped address, if there is one, or None."""
        if self._ip >> 32 == 0xffff:
            return IPv4Address(self._ip & 0xffffffff)
        return None

    @property
    def teredo(self):
        """Return the teredo server and obfuscated client address, or None."""
        if self._ip >> 96 == 0x20010000:
            return (IPv4Address(self._ip >> 64 & 0xffffffff),
                    IPv4Address(self._ip & 0xffffffff))
        return None

    @property
    def sixtofour(self):
        """Return the IPv4 6to4 mapped address, if there is one, or None."""
        if self._ip >> 112 == 0x2002:
            return IPv4Address(self._ip >> 80 & 0xffffffff)
        return None

    @property
    def is_global(self):
        """Test if this address is allocated for public networks.

        Returns:
            A boolean, true if the address is not reserved per
            iana-ipv6-special-registry.
        """
        return not self.is_private

    @property
    def is_loopback(self):
        """Test if the address is a loopback address.

        Returns:
            A boolean, True if the address is a loopback address as
            defined in RFC 2373 2.5.3.
        """
        return self._ip == 1

    @property
    def is_site_local(self):
        """Test if the address is reserved for site-local.

        Note that the site-local address space has been deprecated by
        RFC 3879.  Use is_private to test if this address is in the
        space of unique local addresses as defined by RFC 4193.

        Returns:
            A boolean, True if the address is reserved per RFC 3513 2.5.6.
        """
        return self._constants._sitelocal_net._contains(self._ip)

    def _get_mixed_type_key(self):
        """Return a value suitable for mixed type ordering."""
        scope = '' if self._scope is None else self._scope
        return self._version, self._ip, scope

# =============================================================================
# IP Network classes
# =============================================================================

class _BaseIPNetwork(_BaseIP):
    """A base class for an IP Network, do not instantiate directly.

    The following attributes must be provided by derived classes:
        _version        The IP version number, IPV4 or IPV6
        _max_address    The maximum integer value for this address type
        _address_len    The address length, in bits
        _address_class  The class for addresses of the same IP version
    """

    __slots__ = ()

    @classmethod
    def _prefix_from_string(cls, txt):
        """Convert an IPv4/6 prefix string to a prefix length.

        Acceptable strings are a decimal integer in the range 0 to 32;
        or a network mask expressed as an IPv4/6 address 'a.b.c.d'
        where: a to d are decimal integers in the range 0 to 255,
        leading zeros and spaces are not permitted.

        Args:
            txt: A prefix string, e.g. '24' or '255.255.255.0'

        Returns:
            the prefix length as an integer

        Raises:
            NetmaskValueError if the string is not a valid prefix.
        """
        if txt.isdigit():
            if txt[0] == '0' and len(txt) != 1:
                raise NetmaskValueError('leading zero in prefix: %r' % (txt,))
            preflen = int(txt)
            if not preflen <= cls._address_len:
                raise NetmaskValueError('prefix length too big: %r' % (txt,))
        else:
            try:
                addr = cls._address_class(txt)
            except AddressValueError:
                raise NetmaskValueError('invalid prefix: %r' % (txt,))
            hostlen = _count_righthand_zero_bits(addr._ip, cls._address_len)
            preflen = cls._address_len - hostlen
            size = 2**(cls._address_len - preflen)
            netmask = cls._max_address - size + 1
            if addr._ip & netmask != netmask:
                raise NetmaskValueError('%r (%x) is not a valid netmask value' %
                                        (txt, addr._ip))
        return preflen

    @classmethod
    def from_string(cls, txt):
        """Convert a string to an IPv4/6 integer value and prefix length.

        Acceptable strings are in the format "a.b.c.d/p", where: a to d
        are decimal integers in the range 0 to 255, inclusive; and p is
        a decimal integer in the range 0 to 32, inclusive, or a network
        mask expressed as an IPv4/6 address (m1.m2.m3.m4).
        Spaces and leading zeros are not permitted.

        Args:
            txt: An IPv4/6 address/prefix string, e.g. '1.2.3.0/24'

        Returns:
            The IPv4/6 network and prefix length, as integers

        Raises:
            AddressValueError if the address is not valid.
            NetmaskValueError if the prefix is not valid.
        """
        words = txt.split('/')
        numwords = len(words)
        if numwords > 2:
            raise AddressValueError('invalid network: %r' % (txt,))
        ip = cls._address_class.from_string(words[0])
        if numwords == 2:
            preflen = cls._prefix_from_string(words[1])
        else:
            preflen = cls._address_len
        return ip, preflen

    @classmethod
    def _to_string(cls, ip, preflen, scope=None):
        """Convert an integer IP address & prefix length to a string.

        Args:
            ip: The network integer
            preflen: The prefix length
            scope: The scope_id string, or None

        Returns:
            The IPv4/6 network as a string, e.g. '1.2.3.0/24'
        """
        if not scope:
            return f'{cls._address_class._to_string(ip)}/{preflen}'
        return f'{cls._address_class._to_string(ip)}%{scope}/{preflen}'

    @classmethod
    def to_string(cls, ip, preflen, scope=None):
        """Convert an integer IP address & prefix length to a string.

        Args:
            ip: The network integer
            preflen: The prefix length
            scope: The scope_id string, or None

        Returns:
            The IPv4/6 network as a string, e.g. '1.2.3.0/24'

        Raises:
            AddressValueError if the ip address is not valid
            NetmaskValueError if the prefix length is not valid
        """
        if not 0 <= ip <= cls._max_address:
            raise AddressValueError('IPv6 integer out of range: %r' % (ip,))
        if not 0 <= preflen <= cls._address_len:
            raise NetmaskValueError('invalid prefix length: %r' % (preflen,))
        if scope and cls.version == IPV4:
            raise AddressValueError(f'scope ({scope}) is not valid for IPv4')
        return cls._to_string(ip, preflen, scope)

    to_string_exploded = to_string

    def __iter__(self):
        """Iterate over the IP addresses in this network."""
        for i in range(self._ip, self._ip + self._size):
            yield self._address_class(i)

    def __getitem__(self, n):
        """Get an indexed IP address within this network.

        Args:
            n: The integer index of the IP address to return

        Returns:
            An IPv4Address/IPv6Address for the indexed IP address

        Slice index notation is not supported
        """
        if not isinstance(n, int):
            raise TypeError('invalid index type: %r' % (n,))
        i = n if n >= 0 else self._size + n
        if 0 <= i < self._size:
            return self._address_class(self._ip + i)
        raise IndexError('IP network index out of range: %r' % (n,))

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self._ip == other._ip and self._size == other._size

    def __ne__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self._ip != other._ip or self._size != other._size

    def __lt__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return (self._ip < other._ip or
                (self._ip == other._ip and self._size < other._size))

    def __le__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return (self._ip < other._ip or
                (self._ip == other._ip and self._size <= other._size))

    def __gt__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return (self._ip > other._ip or
                (self._ip == other._ip and self._size > other._size))

    def __ge__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return (self._ip > other._ip or
                (self._ip == other._ip and self._size >= other._size))

    def _contains(self, ip_int):
        """Check if IP integer value is in this network.

        Args:
            ip_int: the IP integer to check

        Returns:
            True if ip_int is in this network; otherwise False
        """
        return self._ip == ip_int & self._netmask

    def _contains_net(self, net):
        """Check if an IP network, is contained in this network.

        Args:
            net: the IP network, or address, to check

        Returns:
            True if net is in this network; otherwise False
        """
        return (self._prefixlen <= net._prefixlen and
                self._ip == net._ip & self._netmask)

    def __contains__(self, net):
        """Check if IP address, or another network, is in this network.

        Args:
            net: the IP network, or address, to check

        Returns:
            True if net is in this network; otherwise False
        """
        if isinstance(net, self._address_class):
            return self._ip == net._ip & self._netmask
        if isinstance(net, self.__class__):
            return (self._ip == net._ip & self._netmask and
                    self._prefixlen <= net._prefixlen)
        return False

    def overlaps(self, other):
        """Check if another IP network, or address, overlaps this one.

        Args:
            other: The IP network or address, to check

        Returns:
            A boolean: True if other is in this network, or vice versa.

        Raises:
            TypeError: If self and other are of different types.
        """
        if not isinstance(other, self.__class__):
            raise TypeError('self (%r) and other (%r) must be the asame type' %
                            (self, other))
        return (self._ip <= other._ip < self._ip + self._size or
                other._ip <= self._ip < other._ip + other._size)

    def __len__(self):
        """Returns the number of IP addresses in the network."""
        return self._size

    @property
    def network_address(self):
        """The IP network base IP address."""
        if self._networkaddress is None:
            self._networkaddress = self._address_class(self._ip)
            if self._version == IPV6:
                self._networkaddress._scope = self._scope
        return self._networkaddress

    @property
    def _broadcast_int(self):
        """Returns the broadcast IP address for the network, as an integer."""
        return self._ip + self._size - 1

    @property
    def broadcast_address(self):
        """Returns the broadcast IP address for the network."""
        if self._broadcastaddress is None:
            self._broadcastaddress = self._address_class(self._broadcast_int)
        return self._broadcastaddress

    @property
    def netmask(self):
        """Returns the network mask for the network, as an IP address"""
        if self._netmaskaddress is None:
            self._netmaskaddress = self._address_class(self._netmask)
        return self._netmaskaddress

    @property
    def hostmask(self):
        """Returns the host mask for the network, as an IP address."""
        if self._hostmask is None:
            self._hostmask = self._address_class(self._size - 1)
        return self._hostmask

    @property
    def with_prefixlen(self):
        """Returns the network address and prefix length as a string."""
        return self.__str__()

    @property
    def with_netmask(self):
        """Returns the network address and network mask as a string."""
        return '%s/%s' % (self._address_class._to_string(self._ip),
                          self.netmask)

    @property
    def with_hostmask(self):
        """Returns the network address and host mask as a string."""
        return '%s/%s' % (self._address_class._to_string(self._ip),
                          self.hostmask)

    @property
    def num_addresses(self):
        """The number of addresses in this network."""
        return self._size

    @property
    def prefixlen(self):
        """The network prefix length, in bits."""
        return self._prefixlen

    def exclude(self, net):
        """Remove a network, or address, from a larger block.

        Args:
            net: The IP network, or address, to exclude

        Returns:
            - An iterator of the IPv(4|6)Network objects, which is self
              with net excluded, if net is a subset of self.
            - Nothing, if self is a subset of net, or equal to it.
            - Self, if net is not a subnet of self.

        Raises:
            TypeError: If net is not an IPv(4|6)Network, or
                IPv(4|6)Address, of the same IP version.
        """
        # convert net to a network, if necessary
        if isinstance(net, self._address_class):
            net = self.__class__(net._ip)
        elif not isinstance(net, self.__class__):
            raise TypeError('can only exclude a network, or address, '
                            'of the same IP version')
        if self != net:
            if self._contains_net(net):
                subs = list(self.subnetworks(1))
                # hold on to higher subnets to yield at the end, in order
                tail = deque()
                while len(subs) == 2:
                    if subs[0]._contains_net(net):
                        tail.appendleft(subs[1])
                        if net == subs[0]:
                            break
                        subs = list(subs[0].subnetworks(1))
                    else:  # net in subs[1]:
                        yield subs[0]
                        if net == subs[1]:
                            break
                        subs = list(subs[1].subnetworks(1))
                yield from tail
            else:
                yield self

    def address_exclude(self, other):
        """Remove a network from a larger block.

        For example:

            net1 = ip_network('192.0.2.0/28')
            net2 = ip_network('192.0.2.1/32')
            list(net1.address_exclude(net2)) =
                [IPv4Network('192.0.2.0/32'),
                 IPv4Network('192.0.2.2/31'),
                 IPv4Network('192.0.2.4/30'),
                 IPv4Network('192.0.2.8/29')]

        or IPv6:

            net1 = ip_network('2001:db8::1/32')
            net2 = ip_network('2001:db8::1/128')
            list(net1.address_exclude(net2)) =
                [ip_network('2001:db8::1/128'),
                 ip_network('2001:db8::2/127'),
                 ip_network('2001:db8::4/126'),
                 ip_network('2001:db8::8/125'),
                 ...
                 ip_network('2001:db8:8000::/33')]

        Args:
            other: An IP network object, of the same type, to exclude.

        Returns:
            An iterator of the IPv(4|6)Network objects which is self
            minus other.

        Raises:
            TypeError: If self and other are of different types.
            ValueError: If other is not completely contained by self.
        """
        if not isinstance(other, self.__class__):
            raise TypeError('other (%r) is not the same type as %r' %
                            (other, self))
        if not self._contains_net(other):
            raise ValueError('other (%r) is not contained in %r' %
                             (other, self))
        return self.exclude(other)

    def compare_networks(self, other):
        """Compare with another IP network.

        Args:
            other: An IP object.

        Returns:
            -1 if self < other; 0 if self == other; 1 if self > other

        Raises:
            TypeError if other is not the same type as self.
        """
        if not isinstance(other, self.__class__):
            raise TypeError('comparing %r to %r' % (self, other))
        if self._ip < other._ip:
            return -1
        if self._ip > other._ip:
            return 1
        if self._size < other._size:
            return -1
        if self._size > other._size:
            return 1
        return 0

    def subnetworks(self, diff=None, preflen=None):
        """The subnets which join to make the current subnet.

        In the case that self contains only one IP
        (self._prefixlen == 32 for IPv4 or self._prefixlen == 128
        for IPv6), yield an iterator with just ourself.

        Args:
            diff: An integer, the amount the prefix length should be
                increased by. This should be None if preflen is set.
            preflen: The desired new prefix length. This must be a
                larger number (smaller prefix) than the existing prefix.
                This should not be set if diff is also set.

        Returns:
            An iterator of IPv(4|6)Network objects.

        Raises:
            ValueError: The diff is too small or too large;
                or diff and preflen are both set; or
                preflen is smaller than the current prefix (a smaller
                prefix means a larger network)
        """
        if preflen is not None:
            if diff is not None:
                raise ValueError('cannot set both the prefix length '
                                 'difference and the new prefix length')
        elif diff is None:
            raise ValueError('either the prefix length difference or the '
                             'new prefix length must be specified')
        else:
            preflen = self._prefixlen + diff
        if not self._prefixlen <= preflen <= self._address_len:
            raise ValueError('prefix length difference %s is invalid for '
                             'network %r' % (preflen, self))
        if preflen == self._prefixlen:
            yield self
            return
        size = 0
        while size < self._size:
            sub = self.__class__((self._ip + size, preflen), False)
            yield sub
            size += sub._size

    def subnets(self, prefixlen_diff=1, new_prefix=None):
        """The subnets which join to make the current subnet.

        In the case that self contains only one IP
        (self._prefixlen == 32 for IPv4 or self._prefixlen == 128
        for IPv6), yield an iterator with just ourself.

        Args:
            prefixlen_diff: An integer, the amount the prefix length
                should be increased by. This should be None if
                new_prefix is set.
            new_prefix: The desired new prefix length. This must be a
                larger number (smaller prefix) than the existing prefix.
                This should not be set if prefixlen_diff is also set.

        Returns:
            An iterator of IPv(4|6)Network objects.

        Raises:
            ValueError: The prefixlen_diff is too small or too large;
                or prefixlen_diff and new_prefix are both set; or
                new_prefix is smaller than the current prefix (a smaller
                prefix means a larger network)
        """
        if prefixlen_diff == 1 and new_prefix is not None:
            prefixlen_diff = None
        return self.subnetworks(prefixlen_diff, new_prefix)

    def supernetwork(self, diff=None, preflen=None):
        """Get a supernet of this network.

        Args:
            diff: An integer, the amount the prefix length should be
                increased by. This should be None if preflen is set.
            preflen: The desired new prefix length. This must be a
                larger number (smaller prefix) than the existing prefix.
                This should not be set if diff is also set.

        Returns:
            An IP network object.

        Raises:
            ValueError: The prefixlen_diff is too small or too large;
                or prefixlen_diff and new_prefix are both set; or
                new_prefix is larger than the current prefix (a larger
                prefix means a smaller network)
        """
        if preflen is not None:
            if diff is not None:
                raise ValueError('cannot set both the prefix length '
                                 'difference and the new prefix length')
        elif diff is None:
            raise ValueError('either the prefix length difference or the '
                             'new prefix length must be specified')
        else:
            preflen = self._prefixlen - diff
        if not 0 <= preflen <= self._prefixlen:
            raise ValueError('prefix length difference %s is invalid for '
                             'network %r' % (preflen, self))
        if preflen == self._prefixlen:
            return self
        return self.__class__((self._ip, preflen), False)

    def supernet(self, prefixlen_diff=1, new_prefix=None):
        """The supernet containing the current network.

        Args:
            prefixlen_diff: An integer, the amount the prefix length of
                the network should be decreased by.  For example, given
                a /24 network and a prefixlen_diff of 3, a supernet with
                a /21 netmask is returned.

        Returns:
            An IP network object.

        Raises:
            ValueError: The prefixlen_diff is too small or too large;
                or prefixlen_diff and new_prefix are both set; or
                new_prefix is larger than the current prefix (a larger
                prefix means a smaller network)
        """
        if self._prefixlen == 0:
            return self
        if prefixlen_diff == 1 and new_prefix is not None:
            prefixlen_diff = None
        return self.supernetwork(prefixlen_diff, new_prefix)

    def subnet_of(self, other):
        """Return True if this network is a subnet of other."""
        return self in other

    def supernet_of(self, other):
        """Return True if this network is a supernet of other."""
        return other in self

    @property
    def is_multicast(self):
        """Test if the netork is reserved for multicast use.

        Returns:
            True if this is a multicast network.  See RFC 2373 2.7.
        """
        return self._constants._multicast_net._contains_net(self)

    @property
    def is_reserved(self):
        """Test if the network is otherwise IETF reserved.

        Returns:
            A boolean, True if the network is within one of the
            reserved IPv6 Network ranges.
        """
        for net in self._constants._reserved_nets:
            if net._contains_net(self):
                return True
        return False

    @property
    def is_link_local(self):
        """Test if the network is reserved for link-local.

        Returns:
            A boolean, True if the address is reserved per RFC 4291.
        """
        return self._constants._linklocal_net._contains_net(self)

    @property
    def is_private(self):
        """Test if this network is allocated for private networks.

        Returns:
            A boolean, True if the address is reserved per
            iana-ipv4-special-registry or iana-ipv6-special-registry.
        """
        if self._private is None:
            self._private = False
            for net in self._constants._private_nets:
                if net._contains_net(self):
                    self._private = True
                    break
        return self._private

    @property
    def is_unspecified(self):
        """Test if the network is unspecified.

        Returns:
            A boolean, True if this is the unspecified address as
            defined in RFC 2373 2.5.2.
        """
        return self._ip == 0 and self._size == 1

# =============================================================================

class IPv4Network(_BaseIPNetwork, _BaseIPv4):
    """An IPv4 Network."""

    __slots__ = ('_ip', '_private', '_prefixlen', '_size',
                 '_netmask', '_networkaddress', '_netmaskaddress',
                 '_hostmask', '_broadcastaddress')

    _address_class = IPv4Address

    def __init__(self, address, strict=True):
        """Instantiate a new IPv4/IPv6 Network object.

        Args:
            address: A string, integer, or tuple of strings or integers
                representing the IP network as an IP address and
                optional prefix.

                If the address is a single string, it must represent the
                network IP address and an optional '/' character
                followed by the prefix.

                If the address is a single integer, it is taken as the
                network IP address, it must be: 0 <= address < 2**32.

                if the prefix is given as an integer, it must be:
                0 <= prefix <= 32.

                The prefix may also be specified as a netmask address
                string, with the number of most significant bits set
                defining the prefix length, and the remaining host bits
                all zero; or as a hostmask address string, with the
                number of most significant zero bits defining the prefix
                length, and the remaining host bits all set.

                If the prefix is not given, it defaults to the full
                address length, 32 bits for IPv4.

            strict: A boolean. If True, ensure that the IP address is a
                true network address, i.e. the host bits (after the
                prefix) must all be zero.

        Raises:
            AddressValueError: If address is not valid.
            NetmaskValueError: If prefix/netmask/hostmask are not valid.
            ValueError: If strict is True and any host bits are set.
        """
        prefix = None
        if isinstance(address, tuple):
            if len(address) == 1:
                address = address[0]
            elif len(address) == 2:
                address, prefix = address
        if isinstance(address, bytes):
            address = int.from_bytes(address, 'big')
        if isinstance(address, int):
            if address < 0 or address > self._max_address:
                raise AddressValueError('invalid network: %r' % (address,))
            ip = address
        elif isinstance(address, str):
            if prefix is None:
                ip, prefix = self.from_string(address)
            else:
                ip = self._address_class.from_string(address)
        else:
            raise AddressValueError('invalid address: %r' % (address,))
        if isinstance(prefix, int):
            self._prefixlen = prefix
        elif isinstance(prefix, str):
            self._prefixlen = self._prefix_from_string(prefix)
        elif prefix is None:
            self._prefixlen = self._address_len
        else:
            raise NetmaskValueError('invalid prefix: %r' % address)
        if not 0 <= self._prefixlen <= self._address_len:
            raise NetmaskValueError('invalid prefix: %r' % address)
        self._size = 2**(self._address_len - self._prefixlen)
        self._netmask = self._max_address - self._size + 1
        self._ip = ip & self._netmask
        if strict and self._ip != ip:
            raise ValueError('%r (%x) has host bits set' % (address, addr))
        # The following values are assigned on first use
        self._private = None
        self._networkaddress = None
        self._broadcastaddress = None
        self._netmaskaddress = None
        self._hostmask = None

    def __str__(self):
        return self._to_string(self._ip, self._prefixlen)

    def __hash__(self):
        return hash((self._ip, self._size))

    def __reduce__(self):
        return self.__class__, ((self._ip, self._prefixlen),)

    def hosts(self):
        """Iterate over the IP addresses in this network.

        Excludes the network and broadcast addresses.
        """
        for i in range(self._ip + 1, self._ip + self._size - 1):
            yield self._address_class(i)

    @property
    def is_global(self):
        """Test if this network is allocated for public networks.

        Returns:
            A boolean, True if the address is not reserved per
            iana-ipv4-special-registry.
        """
        return (not self._constants._public_net._contains_net(self) and
                not self.is_private)

    @property
    def is_loopback(self):
        """Test if the network is a loopback network.

        Returns:
            A boolean, True if the address is a loopback address as
            defined in RFC 2373 2.5.3.
        """
        return self._constants._loopback_net._contains_net(self)

    def _get_mixed_type_key(self):
        """Return a value suitable for mixed type ordering."""
        return self._version, self._ip, '', self._size, 2

# =============================================================================

class IPv6Network(_BaseIPNetwork, _BaseIPv6):
    """An IPv6 Network."""

    _address_class = IPv6Address

    __slots__ = ('_ip', '_private', '_prefixlen', '_size', '_scope',
                 '_netmask', '_networkaddress', '_netmaskaddress',
                 '_hostmask', '_broadcastaddress')

    @classmethod
    def from_string_with_scope(cls, txt):
        """Convert a string to an integer with prefix and scope_id.

        Acceptable strings are in the format "a.b.c.d/p", where: a to d
        are decimal integers in the range 0 to 255, inclusive; and p is
        a decimal integer in the range 0 to 32, inclusive, or a network
        mask expressed as an IPv4/6 address (m1.m2.m3.m4).
        Spaces and leading zeros are not permitted.

        Args:
            txt: An IPv4/6 address/prefix string, e.g. '1.2.3.0/24'

        Returns:
            Tuple of (address, prefix length, scope_id) where
            address and prefix length are inegers, scope_id is a string.

        Raises:
            AddressValueError if the address is not valid.
            NetmaskValueError if the prefix is not valid.
        """
        words = txt.split('/')
        numwords = len(words)
        if numwords > 2:
            raise AddressValueError('invalid network: %r' % (txt,))
        ip, scope = cls._address_class.from_string_with_scope(words[0])
        if numwords == 2:
            preflen = cls._prefix_from_string(words[1])
        else:
            preflen = cls._address_len
        return ip, preflen, scope

    @classmethod
    def _to_string_exploded(cls, ip, preflen, scope=None):
        """IP address integer & prefix length to an exploded string.

        Args:
            ip: The network integer
            preflen: The prefix length
            scope: The scope_id string, or None

        Returns:
            The IPv6 network as a string, e.g.:
            '0001:0002:0003:0000:0000:0000:0000:0000/24'
        """
        if not scope:
            return f'{cls._address_class._to_string_exploded(ip)}/{preflen}'
        return f'{cls._address_class._to_string_exploded(ip)}%{scope}/{preflen}'

    @classmethod
    def to_string_exploded(cls, ip, preflen, scope=None):
        """IP address integer & prefix length to an exploded string.

        Args:
            ip: The network integer
            preflen: The prefix length
            scope: The scope_id string, or None

        Returns:
            The IPv6 network as a string, e.g.:
            '0001:0002:0003:0000:0000:0000:0000:0000/24'

        Raises:
            AddressValueError if the ip address is not valid
            NetmaskValueError if the prefix length is not valid
        """
        if not 0 <= ip <= MAX_IPV6:
            raise AddressValueError('IPv6 integer out of range: %r' % (ip,))
        if not 0 <= preflen <= cls._address_len:
            raise NetmaskValueError('invalid prefix length: %r' % (preflen,))
        return cls._to_string_exploded(ip, preflen, scope)

    def __init__(self, address, strict=True):
        """Instantiate a new IPv6Network object.

        Args:
            address: A string, integer, or tuple of strings or integers
                representing the IP network as an IP address and
                optional prefix.

                If the address is a single string, it must represent the
                network IP address and an optional '/' character
                followed by the prefix.

                If the address is a single integer, it is taken as the
                network IP address, it must be: 0 <= address < 2**128.

                if the prefix is given as an integer, it must be:
                0 <= prefix <= 128.

                The prefix may also be specified as a netmask address
                string, with the number of most significant bits set
                defining the prefix length, and the remaining host bits
                all zero; or as a hostmask address string, with the
                number of most significant zero bits defining the prefix
                length, and the remaining host bits all set.

                If the prefix is not given, it defaults to the full
                address length, 128 bits for IPv6.

            strict: A boolean. If True, ensure that the IP address is a
                true network address, i.e. the host bits (after the
                prefix) must all be zero.

        Raises:
            AddressValueError: If address is not valid
            NetmaskValueError: If the prefix/netmask/hostmask is invalid
            ValueError: If strict is True and any bits are set
        """
        self._scope = None
        prefix = None
        if isinstance(address, tuple):
            if len(address) == 1:
                address = address[0]
            elif len(address) == 2:
                address, prefix = address
        if isinstance(address, bytes):
            address = int.from_bytes(address, 'big')
        if isinstance(address, int):
            if address < 0 or address > self._max_address:
                raise AddressValueError('invalid network: %r' % (address,))
            ip = address
        elif isinstance(address, str):
            if prefix is None:
                ip, prefix, self._scope = self.from_string_with_scope(address)
            else:
                ip, self._scope = \
                        self._address_class.from_string_with_scope(address)
        else:
            raise AddressValueError('invalid value type: %r' % (address,))
        if isinstance(prefix, int):
            self._prefixlen = prefix
        elif isinstance(prefix, str):
            self._prefixlen = self._prefix_from_string(prefix)
        elif prefix is None:
            self._prefixlen = self._address_len
        else:
            raise NetmaskValueError('invalid prefix: %r' % address)
        if not 0 <= self._prefixlen <= self._address_len:
            raise NetmaskValueError('invalid prefix: %r' % address)
        self._size = 2**(self._address_len - self._prefixlen)
        self._netmask = self._max_address - self._size + 1
        self._ip = ip & self._netmask
        if strict and self._ip != ip:
            raise ValueError('%r (%x) has host bits set' % (address, ip))
        # The following values are assigned on first use
        self._private = None
        self._networkaddress = None
        self._broadcastaddress = None
        self._netmaskaddress = None
        self._hostmask = None

    def __str__(self):
        return self._to_string(self._ip, self._prefixlen, self._scope)

    def __hash__(self):
        return hash((self._ip, self._scope, self._size))

    def __reduce__(self):
        return self.__class__, (self.__str__(),)

    @property
    def exploded(self):
        """The full string representation of the IP network."""
        return self._to_string_exploded(self._ip, self._prefixlen, self._scope)

    def hosts(self):
        """Iterate over the IP addresses in this network.

        Excludes the network address.
        """
        for i in range(self._ip + 1, self._ip + self._size):
            yield self._address_class(i)

    @property
    def is_global(self):
        """Test if this network is allocated for public networks.

        Returns:
            A boolean, True if the address is not reserved per
            iana-ipv4-special-registry or iana-ipv6-special-registry.
        """
        return not self.is_private

    @property
    def is_site_local(self):
        """Test if the network is reserved for site-local.

        Note that the site-local address space has been deprecated by
        RFC 3879.  Use is_private to test if this network is in the
        space of unique local addresses as defined by RFC 4193.

        Returns:
            A boolean, True if the network is reserved per RFC 3513 2.5.6.
        """
        return self._constants._sitelocal_net._contains_net(self)

    @property
    def is_loopback(self):
        """Test if the network is a loopback network.

        Returns:
            A boolean, True if the address is a loopback address as
            defined in RFC 2373 2.5.3.
        """
        return self._ip == 1 and self._size == 1

    def _get_mixed_type_key(self):
        """Return a value suitable for mixed type ordering."""
        scope = '' if self._scope is None else self._scope
        return self._version, self._ip, scope, self._size, 2

# =============================================================================

class _IPv4Constants:

    _reserved_nets = (IPv4Network('240.0.0.0/4'),)
    _private_nets = (
        IPv4Network('0.0.0.0/8'),
        IPv4Network('10.0.0.0/8'),
        IPv4Network('127.0.0.0/8'),
        IPv4Network('169.254.0.0/16'),
        IPv4Network('172.16.0.0/12'),
        IPv4Network('192.0.0.0/29'),
        IPv4Network('192.0.0.170/31'),
        IPv4Network('192.0.2.0/24'),
        IPv4Network('192.168.0.0/16'),
        IPv4Network('198.18.0.0/15'),
        IPv4Network('198.51.100.0/24'),
        IPv4Network('203.0.113.0/24'),
        IPv4Network('240.0.0.0/4'),
        IPv4Network('255.255.255.255/32'),
    )
    _multicast_net = IPv4Network('224.0.0.0/4')
    _loopback_net = IPv4Network('127.0.0.0/8')
    _linklocal_net = IPv4Network('169.254.0.0/16')
    _public_net = IPv4Network('100.64.0.0/10')

_BaseIPv4._constants = _IPv4Constants
_BaseIPv4._network_class = IPv4Network

class _IPv6Constants:

    _reserved_nets = (
        IPv6Network('::/8'),
        IPv6Network('100::/8'),
        IPv6Network('200::/7'),
        IPv6Network('400::/6'),
        IPv6Network('800::/5'),
        IPv6Network('1000::/4'),
        IPv6Network('4000::/3'),
        IPv6Network('6000::/3'),
        IPv6Network('8000::/3'),
        IPv6Network('A000::/3'),
        IPv6Network('C000::/3'),
        IPv6Network('E000::/4'),
        IPv6Network('F000::/5'),
        IPv6Network('F800::/6'),
        IPv6Network('FE00::/9'),
    )
    _private_nets = (
        IPv6Network('::/128'),
        IPv6Network('::1/128'),
        IPv6Network('::ffff:0:0/96'),
        IPv6Network('100::/64'),
        IPv6Network('2001::/23'),
        IPv6Network('2001:2::/48'),
        IPv6Network('2001:10::/28'),
        IPv6Network('2001:db8::/32'),
        IPv6Network('fc00::/7'),
        IPv6Network('fe80::/10'),
    )
    _multicast_net = IPv6Network('ff00::/8')
    _loopback_net = IPv6Network('::1/128')
    _linklocal_net = IPv6Network('fe80::/10')
    _sitelocal_net = IPv6Network('fec0::/10')

_BaseIPv6._constants = _IPv6Constants
_BaseIPv6._network_class = IPv6Network

# =============================================================================
# IP Interface classes
# =============================================================================

class _BaseIPInterface:

    __slots__ = ()

    def __init__(self, address):
        """Instantiate a new IPv4/IPv6 Interface object.

        Args:
            address: A string, integer, or tuple of strings or integers
                representing the IP interface as an IP address and an
                optional prefix.

                If the address is a single string, it must represent the
                interface IP address and an optional '/' character
                followed by the prefix.

                If the address is a single integer, it is taken as the
                interface IP address.

                if the IP address is given as an integer, it must be:
                    IPv4: 0 <= address < 2**32
                    IPv6: 0 <= address < 2**128

                if the prefix is given as an integer, it is taken as
                the prefix length and it must be:
                    IPv4:  0 <= prefix length <= 32
                    IPv6:  0 <= prefix length <= 128

                The prefix may also be specified as a netmask address
                string, with the number of most significant bits set
                defining the prefix length, and the remaining host bits
                all zero; or as a hostmask address string, with the
                number of most significant zero bits defining the prefix
                length, and the remaining host bits all set.

                If the prefix is not given, it defaults to the full
                address length: 32 bits for IPv4, 128 bits for IPv6.

        Raises:
            AddressValueError: If the IP address is not valid.
            NetmaskValueError: If the prefix is not valid.
        """
        if isinstance(address, (int, bytes)):
            addr = address, self._address_len
        elif isinstance(address, str):
            addr = address.split('/')
        elif isinstance(address, tuple):
            addr = address
        else:
            raise AddressValueError("Invalid address %r" % address)
        if len(addr) > 2:
            raise AddressValueError("Invalid address %r" % address)
        addr, prefix = addr if len(addr) > 1 else (addr[0], self._address_len)
        self._address_class.__init__(self, addr)
        self.network = self._network_class((self._ip, prefix), strict=False)
        self._prefixlen = self.network._prefixlen

    @property
    def netmask(self):
        """Returns the net mask for the interface, as an IP address."""
        return self.network.netmask

    @property
    def hostmask(self):
        """Returns the host mask for the interface, as an IP address."""
        return self.network.hostmask

    @property
    def with_prefixlen(self):
        """Returns the network address and prefix length as a string."""
        return self.__str__()

    @property
    def is_unspecified(self):
        """Test if the interface is unspecified.

        Returns:
            A boolean, True if this is the unspecified address, on the
            unspecified network.
            RFC 2373 2.5.2.
        """
        return self._ip == 0 and self.network.is_unspecified

class IPv4Interface(_BaseIPInterface, IPv4Address):
    """An IPv4 Interface: an IP address with an associated network."""

    __slots__ = ('network', '_prefixlen')

    _address_class = IPv4Address

    def __str__(self):
        return f'{self._to_string(self._ip)}/{self._prefixlen}'

    def __reduce__(self):
        return self.__class__, ((self._ip, self._prefixlen),)

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return (self._ip == other._ip and
                    self.network._size == other.network._size)
        if isinstance(other, self._address_class):
            return False
        return NotImplemented

    def __ne__(self, other):
        if isinstance(other, self.__class__):
            return (self._ip != other._ip or
                    self.network._size != other.network._size)
        if isinstance(other, self._address_class):
            return True
        return NotImplemented

    def __lt__(self, other):
        if isinstance(other, self.__class__):
            return (self._ip < other._ip or
                    (self._ip == other._ip and
                     self.network._size < other.network._size))
        if isinstance(other, self._address_class):
            return self._ip < other._ip
        return NotImplemented

    def __le__(self, other):
        if isinstance(other, self.__class__):
            return (self._ip < other._ip or
                    (self._ip == other._ip and
                     self.network._size <= other.network._size))
        if isinstance(other, self._address_class):
            return self._ip < other._ip
        return NotImplemented

    def __gt__(self, other):
        if isinstance(other, self.__class__):
            return (self._ip > other._ip or
                    (self._ip == other._ip and
                     self.network._size > other.network._size))
        if isinstance(other, self._address_class):
            # if ip integers are equal, interface is greater than address
            return self._ip >= other._ip
        return NotImplemented

    def __ge__(self, other):
        if isinstance(other, self.__class__):
            return (self._ip > other._ip or
                    (self._ip == other._ip and
                     self.network._size >= other.network._size))
        if isinstance(other, self._address_class):
            return self._ip >= other._ip
        return NotImplemented

    def __hash__(self):
        return hash((self._ip, self.network._size))

    @property
    def ip(self):
        """Returns the interface as an IP address."""
        return self._address_class(self._ip)

    @property
    def with_netmask(self):
        """Returns the network address and network mask as a string."""
        return '%s/%s' % (self._to_string(self._ip), self.netmask)

    @property
    def with_hostmask(self):
        """Returns the network address and host mask as a string."""
        return '%s/%s' % (self._to_string(self._ip), self.hostmask)

    def _get_mixed_type_key(self):
        """Return a value suitable for mixed type ordering."""
        return self._version, self._ip, '', self.network._size

class IPv6Interface(_BaseIPInterface, IPv6Address):
    """An IPv6 Interface: an IP address with an associated network."""

    __slots__ = ('network', '_prefixlen')

    _address_class = IPv6Address

    def __str__(self):
        return f'{self._to_string(self._ip, self._scope)}/{self._prefixlen}'

    def __reduce__(self):
        return self.__class__, (self.__str__(),)

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            self_scope = '' if self._scope is None else self._scope
            other_scope = '' if other._scope is None else other._scope
            return (self._ip == other._ip and self_scope == other_scope and
                    self.network._size == other.network._size)
        if isinstance(other, self._address_class):
            return False
        return NotImplemented

    def __ne__(self, other):
        if isinstance(other, self.__class__):
            self_scope = '' if self._scope is None else self._scope
            other_scope = '' if other._scope is None else other._scope
            return (self._ip != other._ip or self_scope != other_scope or
                    self.network._size != other.network._size)
        if isinstance(other, self._address_class):
            return True
        return NotImplemented

    def __lt__(self, other):
        self_scope = '' if self._scope is None else self._scope
        if isinstance(other, self.__class__):
            other_scope = '' if other._scope is None else other._scope
            return (self._ip < other._ip or
                    (self._ip == other._ip and
                     (self_scope < other_scope or
                      (self._scope == other._scope and
                       self.network._size < other.network._size))))
        if isinstance(other, self._address_class):
            other_scope = '' if other._scope is None else other._scope
            return (self._ip < other._ip or
                    (self._ip == other._ip and self_scope < other_scope))
        return NotImplemented

    def __le__(self, other):
        self_scope = '' if self._scope is None else self._scope
        if isinstance(other, self.__class__):
            other_scope = '' if other._scope is None else other._scope
            return (self._ip < other._ip or
                    (self._ip == other._ip and
                     (self_scope < other_scope or
                      (self_scope == other_scope and
                       self.network._size <= other.network._size))))
        if isinstance(other, self._address_class):
            other_scope = '' if other._scope is None else other._scope
            # if ip and scope are equal, interface is greater than address
            return (self._ip < other._ip or
                    (self._ip == other._ip and self_scope < other_scope))
        return NotImplemented

    def __gt__(self, other):
        self_scope = '' if self._scope is None else self._scope
        if isinstance(other, self.__class__):
            other_scope = '' if other._scope is None else other._scope
            return (self._ip > other._ip or
                    (self._ip == other._ip and
                     (self_scope > other_scope or
                      (self._scope == other._scope and
                       self.network._size > other.network._size))))
        if isinstance(other, self._address_class):
            other_scope = '' if other._scope is None else other._scope
            # if ip and scope are equal, interface is greater than address
            return (self._ip > other._ip or
                    (self._ip == other._ip and self_scope >= other_scope))
        return NotImplemented

    def __ge__(self, other):
        self_scope = '' if self._scope is None else self._scope
        if isinstance(other, self.__class__):
            other_scope = '' if other._scope is None else other._scope
            return (self._ip > other._ip or
                    (self._ip == other._ip and
                     (self_scope > other_scope or
                      (self._scope == other._scope and
                       self.network._size >= other.network._size))))
        if isinstance(other, self._address_class):
            other_scope = '' if other._scope is None else other._scope
            return (self._ip > other._ip or
                    (self._ip == other._ip and self_scope >= other_scope))
        return NotImplemented

    def __hash__(self):
        return hash((self._ip, self._scope, self.network._size))

    @property
    def ip(self):
        """Returns the interface as an IP address."""
        addr = self._address_class(self._ip)
        addr._scope = self._scope
        return addr

    @property
    def with_netmask(self):
        """Returns the network address and network mask as a string."""
        return f'{self._to_string(self._ip, self._scope)}/{self.netmask}'

    @property
    def with_hostmask(self):
        """Returns the network address and host mask as a string."""
        return f'{self._to_string(self._ip, self._scope)}/{self.hostmask}'

    @property
    def exploded(self):
        """The full string representation of the IP interface."""
        # Do not include the scope-id, for consistency with ipaddress
        return '%s/%s' % (self._to_string_exploded(self._ip), self._prefixlen)

    @property
    def is_loopback(self):
        """Test if this is a loopback interface.

        Returns:
            A boolean, True if the interface address and the network it
            is in are loopback, as defined in RFC 3330 and 2373 2.5.3.
        """
        return self._ip == 1 and self.network.is_loopback

    def _get_mixed_type_key(self):
        """Return a value suitable for mixed type ordering."""
        scope = '' if self._scope is None else self._scope
        return self._version, self._ip, scope, self.network._size
