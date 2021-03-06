# eipaddress

A faster, lightweight IPv4/IPv6 manipulation library in Python.

This module is used to create/poke/manipulate IPv4 and IPv6 addresses
and networks.

This module is a faster version of the standard ipaddress module.  It is fully
API compatible with [ipaddress version 1.0](https://github.com/python/cpython/blob/master/Lib/ipaddress.py) (commit fabd7bb on 11 Aug 2020).
However, there are some intentional user visible differences, described in the
next section.  Also, a number of bugs found in the ipaddress module have been
fixed in eipaddress, these bugs are listed in a later section.

Comparisons of eipaddress and ipaddress in terms of performance, memory usage,
and API extensions are also covered, in later sections.

The [ipaddress documentation](https://docs.python.org/3/library/ipaddress.html)
also applies to the eipaddress module, with the minor exception on logical
operations for network objects, which are ordered first by network address, and
second by network size.  This difference is described in more detail below.

For more detailed documentation, use the python help command,

# User Visible Differences

* Network comparisons:
  * eipaddress compares networks based on their network address and network size
    (i.e. the number of addresses in the network).  For networks with the same
    network address, the bigger network (with more addresses) is reported as
    _greater than_ a smaller network (with fewer addresses).
  * ipaddress compares networks based on their network address and netmask.
    This results in a bigger network (with more addresses) being reported as
    _less than_ a smaller network (with fewer addresses) if their network
    addresses are the same.
  * This applies to the comparison operators (`<`, `<=`, `>`, `>=`) and the
    `compare_networks` method.
  * This also affects interfaces, as their networks are compared if their
    interface addresses are the same.
* `get_mixed_type_key`
  * eipaddress returns the following values, most significant first:
    * version: the IP version of the object
    * address:
      * for an address or interface, the integer value of the object
      * for a network, the integer value of the network address
    * scope-ID:
      * for an IPv6 object; an empty string if there is no scope-ID
      * omitted for an IPv4 address
      * an empty string for an IPv4 network or interface
    * size:
      * for a network or interface, the number of addresses in the network
      * omitted for an address
    * suffix:
      * for a network only, to differentiate it from an interface
      * omitted for an address or an interface
  * ipaddress returns the following values, most significant first:
    * version: the IP version of the object
    * address:
      * for an address or interface, the object itself
      * for a network, the `network_address` object from the network
    * netmask;
      * for a network, the netmask, as an address object
      * omitted for an address or interface
  * Sorting a mixed type list, with hundreds of objects of each type, is an
    order of magnitude faster with eipaddress.  For details, see the
    `test_sort_get_mixed_type_key` function in the eipaddress_perf.py module.
* IPv4Network and IPv6Network `address_exclude`
  * eipaddress returns the generated subnets in sorted order.
  * ipaddress returns some generated subnets out of order.

# Performance

The `eipaddress_perf.py` application measures the performance of all public
API calls, with one, or more, use cases for each call, and compares the results
for eipaddress and ipaddress.  The results are reported for each use case, with
summaries for each public class, IP version, and more.

To run the performance tests, you must have a copy of [ipaddress version 1.0](https://github.com/python/cpython/blob/master/Lib/ipaddress.py)
installed in the current directory, or on your PYTHONPATH.

Overall, the time measured for running all of the use cases using eipaddress was
a little less than half the time for the same use cases to run using ipaddress.

The following operations on the specified classes are slower than their
ipaddress version 1.0 equivalents, with a summary of why this is the case:

* `_IPv4Address._eq__`, `_IPv4Address.__ne__`
  This is due to an ipaddress bug: it does not check the  other type.
* `IPv6Address.__lt__`
  This is due to an ipaddress bug: it does not check the  other type or compare
  the scope-ID.
* `IPv6Address.__reduce__`
  This is due to an ipaddress bug: it does not include the scope-ID.
* `IPv4Network.broadcast_address`, `IPv4Network.hostmask`
  `IPv6Network.broadcast_address`, `IPv6Network.hostmask`
  * ipaddress uses `functools.@cached_property` to save these on first use.
  * eipaddress sets these values directly on first use.  This makes it much
    faster for the first call, but subsequent calls are slower as the value must
    be checked it is not None before it is returned.  Object creation followed
    by access to these properties (up to a reasonable number of times) is
    faster.
* `IPv4Network.netmask`, `IPv4Network.network_address`
  `IPv6Network.netmask`, `IPv6Network.network_address`
  * ipaddress sets these values when the object is created.
  * eipaddress sets them on first use.  Object creation followed by access to
    these attributes (up to a reasonable number of times) is faster.
* `IPv6Interface.ip`
  This is due to an ipaddress bug: it does not include the scope-ID.

# Memory Usage

## The Size Of An Object

To measure the amount of memory used by an object is not trivial.  The size
returned by `sys.getsizeof` only reports the size of the data structure
directly allocated for an object.  The true size of an object must include the
size of any other objects allocated to store the values of any attributes it
references, and the size of the keys used to map the attribute names to the
referenced objects.  Another consideration is that class attributes do not add
to the size of an object instance, nor do references to built-in objects.
The `sizes.py` module in this repository provides a `sizeof` function that takes
all of these considerations, and more, into account, to return a more accurate
measure for the size of an object.  This function has been used to compare the
sizes of the objects used by the eipaddress and ipaddress modules.

## Cached Attributes

The ipaddress and eipaddress modules do not compute the values of all of their
attributes when the object is created.  Some attributes (that are non-trivial
to compute and less likely to be used) are computed when they are first
accessed, and their values cached so they do not have to be re-computed if
they are accessed again.

The use of cached attributes means that the size of the object is at its
smallest when it is created and can grow as each of the cached attributes are
added.  Some caching schemes do not store a direct reference to the cached
value within the object, but in a separate cache accessed through a function or
method.

The eipaddress module classes cache all attributes with direct references to the
cached values in the instance objects, and the memory for the cached attributes
is included in the used sizes reported in the Summary section, below.

The ipaddress module classes cache some attributes externally, with no direct
reference to the cached value in the instance objects.  The cache types used for
each attribute are listed in the table, below, and the size of the externally
cached value, if any.

| `ipaddress` Cache Type | Attribute | External Size |
| --- | --- | ---:|
| `functools.lru_cache()` | `IPv4Address.is_private` | 24 or 28 |
| `functools.lru_cache()` | `IPv4Address.is_global` | 24 or 28 |
| `functools.lru_cache()` | `IPv6Address.is_private` | 24 or 28 |
| `functools.cached_property` | `IPv4Interface.hostmask` | 0 |
| `functools.cached_property` | `IPv6Interface.hostmask` | 0 |
| `functools.lru_cache()` | `IPv4Network.is_global` | 24 or 28 |
| `functools.cached_property` | `IPv4Network.broadcast_address` | 0 |
| `functools.cached_property` | `IPv4Network.hostmask` | 0 |
| class attribute dictionary | `IPv4Network.netmask` | 80 |
| `functools.cached_property` | `IPv6Network.broadcast_address` | 0 |
| `functools.cached_property` | `IPv6Network.hostmask` | 0 |
| class attribute dictionary | `IPv6Network.netmask` | 100 |

__Note 1:__ The external sizes in the cached attributes table, above, and the
Summary section, below, are just for the cached value, they do not include the
overhead for the key used to index the cache.

__Note 2:__ The `is_private` and `is_global` attributes are boolean values, with
an external size of 24 for `False`, or 28 for `True`.

## Summary

The following table shows the memory size for objects of each type in the
ipaddress and eipaddress modules.  The unused size is the minimal object size,
with none of the cached attributes populated.  The used size is with all of the
cached attributes populated.  The external size is the size of the externally
cached attributes (excluding the overhead for the cache index values).  The
total size is the sum of the used and external sizes.

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

__Note 3:__ The sizes may differ a little if different object values are used.

# Public API Extensions

* `ishexdigit`
  A function to check if a string contains only hexadecimal digit characters.
  This is slightly faster than the `_BaseV6._HEX_DIGITS.issuperset` check used
  in ipaddress.
* `IPv4Address.from_string`
  This static method converts an IPv4 address string to an integer.
* `IPv6Address.from_string`
  This static method converts an IPv6 address string to an integer.
* `IPv4Network.from_string`
  This class method converts an IPv4 address string to an integer address and
  prefix length.
* `IPv6Network.from_string`
  This class method converts an IPv6 address string to an integer address and
  prefix length.
* `IPv6Address.from_string_with_scope`
  This class method converts an IPv6 address string with an optional scope-ID to
  a tuple: with the address (as an integer) and the scope-ID (as a string, or
  None, if there is no scope-ID).
* `IPv6Network.from_string_with_scope`
  This class method converts an IPv6 address string with an optional scope-ID
  and an optional prefix to a tuple: with the address and prefix length (as
  integers) and the scope-ID (as a string, or None, if there is no scope-ID).
* `IPv4Address.to_string`
  This class method converts an integer to an IPv4 address string.
* `IPv6Address.to_string`
  This class method converts an integer and an optional scope-ID to an IPv6
  address string.
* `IPv4Network.to_string`
  This class method converts an integer address and prefix length to an IPv4
  network string.
* `IPv6Network.to_string`
  This class method converts an integer address, prefix length and an optional
  scope-ID to an IPv6 network string.
* `IPv4Address.to_string_exploded`
  This is a pseudonym for the `IPv4Address.to_string` method.
* `IPv4Network.to_string_exploded`
  This is a pseudonym for the `IPv4Network.to_string` method.
* `IPv6Address.to_string_exploded`
  This class method converts an integer and an optional scope-ID to an exploded
  IPv6 address string.
* `IPv6Network.to_string_exploded`
  This class method converts an integer address, prefix length and an optional
  scope-ID to an exploded IPv6 network string.
* `IPv4Network.exclude`
  This method is similar to the ipaddress `IPv4Network.address_exclude` method,
  but it accepts a network, or an address, to be excluded: `address_exclude`
  only accepts a network to be excluded.  It returns an iterator of subnets of
  this network, with the given network, or address, excluded.
* `IPv6Network.exclude`
  This method is similar to the ipaddress `IPv6Network.address_exclude` method,
  but it accepts a network, or an address, to be excluded: `address_exclude`
  only accepts a network to be excluded.  It returns an iterator of subnets of
  this network, with the given network, or address, excluded.
* `IPv4Network.subnetworks`
  This method is similar to the ipaddress `IPv4Network.subnets` method, but the
  `prefixlen_diff` argument has been renamed to `diff` and its default value is
  None, instead of 1.  It returns an iterator of subnet network objects.
* `IPv6Network.subnetworks`
  This method is similar to the ipaddress `IPv6Network.subnets` method, but the
  `prefixlen_diff` argument has been renamed to `diff` and its default value is
  None, instead of 1.  It returns an iterator of subnet network objects.
* `IPv4Network.supernetwork`
  This method is similar to the ipaddress `IPv4Network.supernet` method, but the
  `prefixlen_diff` argument has been renamed to `diff` and its default value is
  None, instead of 1.  It returns the supernet network object.
* `IPv6Network.supernetwork`
  This method is similar to the ipaddress `IPv6Network.supernet` method, but the
  `prefixlen_diff` argument has been renamed to `diff` and its default value is
  None, instead of 1.  It returns the supernet network object.

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

