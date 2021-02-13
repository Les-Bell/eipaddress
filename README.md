# eipaddress

A faster, lightweight IPv4/IPv6 manipulation library in Python.

This module is used to create/poke/manipulate IPv4 and IPv6 addresses
and networks.

This module is a faster version of the standard ipaddress module.  It is fully
API compatible with [ipaddress version 1.0](https://github.com/python/cpython/blob/master/Lib/ipaddress.py) (commit fabd7bb on 11 Aug 2020).
However, there are a few intentional user visible differences, described in the
next section.  Also, a number of bugs found in the ipaddress module have been
fixed in eipaddress, these bugs are listed in a later section.

Other sections compare eipaddress and ipaddress in terms of performance, memory
usage, and API extensions.

The [documentation for the standard ipaddress module](https://docs.python.org/3/library/ipaddress.html) also applies to the
eipaddress module, with the minor exception on logical operations for network
objects, which are ordered first by network address, and second by network size.
This difference is described in more detail below.

For more detailed documentation, use the python help command,

# User Visible Differences

* Network comparisons:
  - eipaddress compares networks based on the network address and network size
    (i.e. the number of addresses in the network).
  - ipaddress compares networks based on the network address and netmask.
    - This results in a bigger network (with more addresses) being reported as
      _less than_ a smaller network (with fewer addresses) if their network
      addresses are the same.
  - This applies to the comparison operators (`==`, `!=`, `<`, `<=`, `>`, `>-`)
    and the `compare_networks` method.
  - This also affects interfaces, as their networks are compared if their
    interface addresses are the same.
* `get_mixed_type_key`
  - eipaddress returns the following values, most significant first:
      version: the IP version of the object
      address:
        - for an address or interface, the integer value of the object
        - for a network, the integer value of the network address
      scope-ID:
        - for an IPv6 object; an empty string if there is no scope-ID
        - omitted for an IPv4 address
        - an empty string for an IPv4 network or interface
      size:
        - for a network or interface, the number of addresses in the network
        - omitted for an address
      suffix:
        - for a network only, to differentiate it from an interface
        - omitted for an address or an interface
  - ipaddress order is based on:
      version: the IP version of the object
      address:
        - for an address or interface, the object itself
        - for a network, the `network_address` object from the network
      netmask;
        - for a network, the netmask, as an address object
        - omitted for an address or interface
* IPv4Network and IPv6Network `address_exclude`
  - eipaddress returns the generated subnets in sorted order.
  - ipaddress returns some generated subnets out of order.

# Performance

The `eipaddress_perf.py` application measures the performance of all public
API calls, with one, or more, use cases for each call, and compares the results
for eipaddress and ipaddress.  The results are reported for each use case, with
summaries for each public class, IP version, and more.

To run the performance tests, you must hava a copy of [ipaddress version 1.0](https://github.com/python/cpython/blob/master/Lib/ipaddress.py)
installed in the same directory as eipaddress, or on your PYTHONPATH.

Overall, the time measured for running all of the use cases using eipaddress was
a little less than half the time for the same use cases to run using ipaddress.

The following operations on the specified classes are slower than their
ipaddress version 1.0 equivalents, with a summary of why this is the case:

* `__eq__`, `__ne__`
  - IPv4Address
    - This is due to an ipaddress bug: it does not check the  other type.
* `__lt__`
  - IPv6Address
    - This is due to an ipaddress bug: it does not compare the scope-ID.
* `__reduce__`
  - IPv6Address
    - This is due to an ipaddress bug: it does not include the scope-ID.
* `broadcast_address`, `hostmask`
  - IPv4Network, IPv6Network
    - eipaddress is faster for the first call, subsequent calls are slower.
    - ipaddress uses `functools.@cached_property` to save these on first use.
    - eipaddress sets these values directly on first use, instead of using an
      extermal cache.
    - eipaddress object creation followed by access to these properties (up to
      a reasonable number of times) is faster.
* `netmask`, `network_address`
  - IPv4Network, IPv6Network
    - ipaddress sets these values when the object is created.
    - eipaddress sets them on first use.
    - eipaddress object creation followed by access to these attributes (up to
      a reasonable number of times) is faster.
* `ip`
  - IPv6Interface
    - This is due to an ipaddress bug: it does not include the scope-ID.

# Memory Usage

## The Size Of An Object

To measure the amount of memory used by an object is not trivial.  The size
returned by `sys.getsizeof` only reports the size of the data structure
directly allocated for an object.  The true size of an object must include the
size of any other objects allocated to store the values of any attributes it
references, and the size of the keys used to map the attribute names to the
referenced objects.  Another consideration is that class attributes do not add
to the size of an object instance, nor do references to built-in objects.
The `sizes` module provides a `sizeof` function that takes all of these
considerations, and more, into account, to return a more accurate measure for
the size of an object.  This function has been used to compare the sizes of the
objects used by the eipaddress and ipaddress modules.

## Cached Attributes

The ipaddress and eipaddress modules do not compute the values of all of their
attributes when the object is created.  Some attributes (that are non-trivial
to compute and less likely to be used) are computed when they are first
accessed, and their values cached so they do not have to be re-computed if
they are accessed again.

The use of cached attributes means that the size of the object is at its
smallest when it is created and can grow as each of the cached attributes are
accessed.  Some caching schemes do not store a direct reference to the cached
value within the object, but in a separate cache accessed through a hidden
function or method.

The eipaddress module classes cache all sttributes with direct references to the
cached values in the instance objects, and the memory for the cached attributes
is included in the used sizes, in the table, above.

The ipaddress module classes cache some sttributes externally, with no direct
reference to the cached value in the instance objects.  The cache types used for
each attribute are listed in the table, below, and whether they are included in
the sizes measured in the table, above.

| Cache Type | Attribute | External | Size |
| --- | --- | --- | ---:|
| `functools.lru_cache()` | `IPv4Address.is_private` | YES | 24 |
| `functools.lru_cache()` | `IPv4Address.is_global` | YES | 28 |
| `functools.lru_cache()` | `IPv6Address.is_private` | YES | 28 |
| `functools.cached_property` | `IPv4Interface.hostmask` | NO | |
| `functools.cached_property` | `IPv6Interface.hostmask` | NO | |
| `functools.lru_cache()` | `IPv4Network.is_global` | YES | 28 |
| `functools.cached_property` | `IPv4Network.broadcast_address` | NO | |
| `functools.cached_property` | `IPv4Network.hostmask` | NO | |
| class attribute dictionary | `IPv4Network.netmask` | YES | 80 |
| `functools.cached_property` | `IPv6Network.broadcast_address` | NO | |
| `functools.cached_property` | `IPv6Network.hostmask` | NO | |
| class attribute dictionary | `IPv6Network.netmask` | YES | 100 |

> __Note__: The external sizes in the table, above, and the summary table,
> below, are just for the cached value, they do not include the overhead of the
> key used to index the cache.

## Summary

The following table summarises the memory size for objects of each type in the
ipaddress and eipaddress modules.  The unused size is the minimal object size,
with none of the cached attributes populated.  The used size is with all of the
cached attributes populated.  The external size is the size of the externally cached attributes (excluding the overhead for the cache index values).  The total
size is the sum of the used and external sizes.

| Object Type | Value | Unused Size | Used Size | External Size | Total Size |
| --- | --- | ---:| ---:| ---:| ---:|
| ipaddress. IPv4Address | '1.2.3.4' | 76 | 76 | 52 | 128 |
| eipaddress. IPv4Address | '1.2.3.4' | 76 | 100 | 0 | 100 |
| ipaddress. IPv4Interface | '8.7.6.5/24' | 759 | 1148 | 0 | 1148 |
| eipaddress. IPv4Interface | '8.7.6.5/24' | 312 | 460 | 0 | 480 |
| ipaddress. IPv4Network | '192.3.0.0/16' | 519 | 1054 | 108 | 1162 |
| eipaddress. IPv4Network | '192.3.0.0/16' | 224 | 500 | 0 | 500 |
| ipaddress. IPv6Address | '2001::1%A' | 150 | 150 | 28 | 178 |
| eipaddress. IPv6Address | '2001::1%A' | 150 | 178 | 0 | 178 |
| ipaddress. IPv6Interface | '1000::2%I/24' | 877 | 1286 | 0 | 1286 |
| eipaddress. IPv6Interface | '1000::2%I/24' | 434 | 610 | 0 | 610 |
| ipaddress. IPv6Network | '3000::%N/16' | 611 | 1186 | 100 | 1286 |
| eipaddress. IPv6Network | '3000::%N/16' | 320 | 652 | 0 | 612 |

# Public API Extensions

* `ishexdigit`
  - A function to check if a string contains only hexadecimal digit characters.
    This is a faster alternative to the `_BaseV6._HEX_DIGITS.issuperset` check
    used in ipaddress.
* `from_string`
  - IPv4Address, IPv6Address
    - This static method converts an IP address string to an integer.
  - IPv4Network, IPv6Network
    - This class method converts an IP address string to an integer address and
      prefix length.
* `from_string_with_scope`
  - IPv6Address
    - This class method converts an IP address string with an optional scope-ID
      to a tuple: with the address (as an integer) and the scope-ID (as a
      string, or None, if there is no scope-ID).
  - IPv6Network
    - This class method converts an IP address string with an optional scope-ID
      and an optional prefix to a tuple: with the address and prefix length (as
      integers) and the scope-ID (as a string, or None, if there is no
      scope-ID).
* `to_string`
  - IPv4Address
    - This class method converts an integer to an IP address string.
  - IPv6Address
    - This class method converts an integer and an optional scope-ID to an IP
      address string.
  - IPv4Network
    - This class method converts an integer address and prefix length to an IP
      network string.
  - IPv6Network
    - This class method converts an integer address, prefix length and an
      optional scope-ID to an IP network string.
* `to_string_exploded`
  - IPv4Address, IPv4Network
    - This is a pseudonym for the `to_string` method.
  - IPv6Address
    - This class method converts an integer and an optional scope-ID to an
      exploded IP address string.
  - IPv6Network
    - This class method converts an integer address, prefix length and an
      optional scope-ID to an exploded IP network string.
* `exclude`
  - IPv4Network, IPv6Network
    This method is similar to the ipaddress network `address_exclude` method,
    but it accepts a network, or an address, to be excluded: `address_exclude`
    only accepts a network to be excluded.  It returns an iterator of subnets of
    this network, with the given network, or address, excluded.
* `subnetworks`
  - IPv4Network, IPv6Network
    This method is similar to the ipaddress network `subnets` method, but the
    prefixlen_diff` argument has been renamed to `diff` and its default value is
    None, instead of 1.  It returns an iterator of the subnet network objects.
* `supernetwork`
  - IPv4Network, IPv6Network
    This method is similar to the ipaddress network `supernet` method, but the
    `prefixlen_diff` argument has been renamed to `diff` and its default value
    is None, instead of 1.  It returns the supernet network object.

# ipaddress Bugs

The following issues are believed to be bugs in the ipaddress module.
They are _fixed_ in the eipaddress module.

* `IPv6Address.exploded` raises an exception if the address has a scope-ID.`
    ```python
    >>> import ipaddress as ip
    >>> a1 = ip.IPv6Address('1:2:3::%A')
    >>> a1.exploded
    Traceback (most recent call last):
      File "<stdin>", line 1, in <module>
    ...
    ipaddress.AddressValueError: Only hex digits permitted in '%A' in '1:2:3::%A'
    ```
* `IPv4Interface('0.0.0.0/32').is_unspecified` returns False (should be True).
* `IPv6Address.__lt__` does not compare the scope-ID, but `__eq__` does.
  This leads to logical inconsistencies:
    ```python
    >>> import ipaddress as ip
    >>> a6 = ip.IPv6Address('1::2:3')
    >>> a6s = ip.IPv6Address('1::2:3%T')
    >>> a6 < a6s
    False
    >>> a6s < a6
    False
    >>> a6 == a6s
    False
    >>> a6 > a6s
    True
    >>> a6s > a6
    True
    ```
* `IPv6Address.__reduce__` does not include the scope-ID.
* The `__eq__` operators for all ipaddress classes rely on the catching of an
  `AttributeError` for detection of incompatible types for the other object,
  returning `NotImplemented` when this occurs.  This allows comparisons with
  other classes that coincidentally implement attributes named `_version`,
  `_ip`, `_scope_id`, `network_address` and `netmask` (where appropriate).
* `IPv6Interface.ip`  does not set the scope-ID in the address returned.

