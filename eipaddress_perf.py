#!/usr/bin/env python
"""Performance tests for the eipaddress module."""

import sys
import time

import ipaddress as ip
import eipaddress as eip

from sizes import sizeof

# =============================================================================

class TextFx:
    '''Terminal strings for text effects.'''

    PLAIN               = '\033[m'
    RESET               = '\033[0m'
    BOLD                = '\033[1m'
    UNDERLINE           = '\033[4m'
    BLACK               = '\033[30m'
    RED                 = '\033[31m'
    GREEN               = '\033[32m'
    YELLOW              = '\033[33m'
    BLUE                = '\033[34m'
    MAGENTA             = '\033[35m'
    CYAN                = '\033[36m'
    WHITE               = '\033[37m'
    BG_BLACK            = '\033[40m'
    BG_RED              = '\033[41m'
    BG_GREEN            = '\033[42m'
    BG_YELLOW           = '\033[43m'
    BG_BLUE             = '\033[44m'
    BG_MAGENTA          = '\033[45m'
    BG_CYAN             = '\033[46m'
    BG_WHITE            = '\033[47m'
    BOLD_BLACK          = '\033[90m'
    BOLD_RED            = '\033[91m'
    BOLD_GREEN          = '\033[92m'
    BOLD_YELLOW         = '\033[93m'
    BOLD_BLUE           = '\033[94m'
    BOLD_MAGENTA        = '\033[95m'
    BOLD_CYAN           = '\033[96m'
    BOLD_WHITE          = '\033[97m'
    UNDERLINE_BLACK     = '\033[4;30m'
    UNDERLINE_RED       = '\033[4;31m'
    UNDERLINE_GREEN     = '\033[4;32m'
    UNDERLINE_YELLOW    = '\033[4;33m'
    UNDERLINE_BLUE      = '\033[4;34m'
    UNDERLINE_MAGENTA   = '\033[4;35m'
    UNDERLINE_CYAN      = '\033[4;36m'
    UNDERLINE_WHITE     = '\033[4;37m'

# =============================================================================

def fn_name(depth = 0):
    """Get the function name from the call stack.

    Args:
        depth: call stack depth to return, 0=parent, 1=grandparent, etc.

    Returns:
        The function name from the call stack, at the depth given.
    """
    return sys._getframe(depth + 1).f_code.co_name  # pylint: disable=W0212

def has_colours(stream):
    """Determine if an output stream supports colours.

    Args:
        stream: the output stream to check

    Returns:
        True if more than 2 colours are supported; else False
    """
    if hasattr(stream, 'isatty') and stream.isatty():
        try:
            import curses
            curses.setupterm()
            return curses.tigetnum('colors') > 2
        except Exception:
            pass
    return False

def timefn(n, fn, *args, **kwargs):
    """Time the execution of a function call.

    Args:
        n: number of times to call the function
        fn: the function to call
        args: positional arguments to pass to fn
        kwargs: keyword arguments to pass to fn

    Returns:
        A tuple: (elapsed time, return value from the last call to fn).
    """
    start = time.perf_counter_ns()
    for i in range(n):
        result = fn(*args, **kwargs)
    return time.perf_counter_ns() - start, result

def timelist(n, fn, *args, **kwargs):
    """Time the execution of generating a list from an iterator function.

    Args:
        n: number of times to call the function
        fn: the function to call
        args: positional arguments to pass to fn
        kwargs: keyword arguments to pass to fn

    Returns:
        A tuple: (elapsed time, the last repeated list).
    """
    start = time.perf_counter_ns()
    for i in range(n):
        result = list(fn(*args, **kwargs))
    return time.perf_counter_ns() - start, result

def time_multi(n, fns, *args, **kwargs):
    """Time the execution of multiple functions.

    Args:
        n: number of times to call each function
        fns: a list of functions to time
        args: positional arguments to pass to each function
        kwargs: keyword arguments to pass to each function

    Returns:
        A list of tuples: (time, result)
            with the elapsed time and last return value from each function
    """
    results = []
    for fn in fns:
        start = time.perf_counter_ns()
        for i in range(n):
            result = fn(*args, **kwargs)
        elapsed = time.perf_counter_ns() - start
        results.append((elapsed, result))
    return results

def time_multi_list(n, fns, *args, **kwargs):
    """Time the execution of generating a list from iterator functions.

    Args:
        n: number of times to generate each list
        fns: a list of iterator functions to time
        args: positional arguments to pass to each iterator function
        kwargs: keyword arguments to pass to each iterator function

    Returns:
        A list of tuples: (time, result)
            with the elapsed time and result list from the last iteration
    """
    results = []
    for fn in fns:
        start = time.perf_counter_ns()
        for i in range(n):
            result = list(fn(*args, **kwargs))
        elapsed = time.perf_counter_ns() - start
        results.append((elapsed, result))
    return results

def generic_test(reporter, test_id, n, fns, *args, **kwargs):
    """Run a timed test for each function in fns and report the results.

    Args:
        reporer: the Reporter object to use
        n: number of times to call each function
        fns: a list of functions to time
        args: positional arguments to pass to each function
        kwargs: keyword arguments to pass to each function
    """
    results = time_multi(n, fns, *args, **kwargs)
    reporter.report(test_id, n, results, str(args))

def generic_list_test(reporter, test_id, n, fns, *args, **kwargs):
    """Generic timed test for generating a list from iterator functions.

    Args:
        reporer: the Reporter object to use
        n: number of times to call each function
        fns: a list of functions to time
        args: positional arguments to pass to each function
        kwargs: keyword arguments to pass to each function
    """
    results = time_multi_list(n, fns, *args, **kwargs)
    reporter.report(test_id, n, results, str(args))

# =============================================================================

class Reporter(object):
    """Reporter for performance test results."""

    def __init__(self, gt_txt='SLOWER', lt_txt='faster'):
        """Initialise the report.

        Args:
            gt_txt: the reported message if time1 > time2
            lt_txt: the reported message if time1 < time2
        """
        self.gt_txt = gt_txt
        self.lt_txt = lt_txt
        self.time1 = 0.0
        self.time2 = 0.0

    def report(self, test_id, n, results, msg):
        """Report the results.

        Args:
            n: the number of iterations
            results: a tuple ((time1, result1), (time2, result2)) where
                    time1: the ipaddress library elapsed time
                    result1: the ipaddress library result
                    time2: the eipaddress library elapsed time
                    result2: the eipaddress library result
                For memory tests, the time values are actually memory usage
            msg: test information
            gt_txt: the reported message if time1 > time2
            lt_txt: the reported message if time1 < time2
        """
        (time1, result1), (time2, result2) = results
        self.time1 += time1
        self.time2 += time2
        fx0 = TextFx.RESET
        fx1 = fx2 = ''
        if time1 == 0.0 or time2 == 0.0:
            ratio = 0.0
            summary = 'NO DATA'
        elif time1 == time2:
            ratio = 1.0
            summary = 'EQUAL'
        elif time2 < time1:
            ratio = time1 / time2
            summary = f'{ratio:.2f} times {self.lt_txt}'
        else:
            ratio = time2 / time1
            summary = f'{ratio:.2f} times {self.gt_txt} >>>'
            fx1 = TextFx.BOLD_RED
        if ratio < 1.02:
            fx1 = TextFx.YELLOW
        if str(result1) != str(result2):
            suffix = f'\n    {result1}\n    {result2}'
            fx2 = TextFx.BOLD_MAGENTA
        else:
            suffix = ''
        if not has_colours(sys.stdout):
            fx0 = fx1 = fx2 = ''
        print(f'{fx1}{test_id}: {msg}')
        pc = (time2 * 100) / time1 if time1 else 0.0
        print(f'({n:7d}) {time1:>11,.0f} -> {time2:>11,.0f} {pc:6.1f}%  '
              f'{summary}{fx2}{suffix}{fx0}')

    @staticmethod
    def group_report(name, group, gt_txt='SLOWER', lt_txt='faster', quiet=True):
        """Report a summary of a group of results.

        Args:
            name: a name for the group
            group: the Reporter objects in this group
            gt_txt: the reported message if time1 > time2
            lt_txt: the reported message if time1 < time2
            quiet: if True, suppress reports with no data
        """
        time1 = sum(x.time1 for x in group)
        time2 = sum(x.time2 for x in group)
        if quiet and time1 == 0.0 and time2 == 0.0:
            return
        fx0 = TextFx.RESET
        fx1 = ''
        if time1 == 0.0 or time2 == 0.0:
            ratio = 0.0
            summary = 'NO DATA'
        elif time1 == time2:
            ratio = 1.0
            summary = f'EQUAL'
        elif time2 < time1:
            ratio = time1 / time2
            summary = f'{ratio:.2f} times {lt_txt}'
        else:
            ratio = time2 / time1
            summary = f'{ratio:.2f} times {gt_txt} >>>'
            fx1 = TextFx.BOLD_RED
        if ratio < 1.02:
            fx1 = TextFx.YELLOW
        if not has_colours(sys.stdout):
            fx0 = fx1 = ''
        pc = (time2 * 100) / time1 if time1 else 0.0
        print(f'{fx1}{name:14} {time1:>14,.0f} -> {time2:>14,.0f} {pc:6.1f}%  '
              f'{summary}{fx0}')

# =============================================================================

class PerfTest(object):
    """Performance tests for the eipaddress module."""

    def __init__(self):
        """Instantiate: build a list of test methods."""
        self._tests = [(name, fn)
                       for name, fn in sorted(self.__class__.__dict__.items())
                       if name.startswith('test_')]
        self.report_u = Reporter()      # for utility functions
        self.report_4a = Reporter()     # for IPv4 Address
        self.report_4n = Reporter()     # for IPv4 Network
        self.report_4i = Reporter()     # for IPv4 Interface
        self.report_6a = Reporter()     # for IPv6 Address
        self.report_6n = Reporter()     # for IPv6 Network
        self.report_6i = Reporter()     # for IPv6 Interface
        self.report_m = Reporter(gt_txt='BIGGER', lt_txt='smaller') # for memory

    def run(self, matches=None):
        """Run the tests.

        Args:
            matches: sequence of strings to match test names to be run
        """
        for name, fn in self._tests:
            if matches:
                for match in matches:
                    if match in name:
                        fn(self)
                        break
            else:
                fn(self)
        # summarise by type
        utils = self.report_u,
        addresses = self.report_4a, self.report_6a
        networks = self.report_4n, self.report_6n
        interfaces = self.report_4i, self.report_6i
        v4 = self.report_4a, self.report_4n, self.report_4i
        v6 = self.report_6a, self.report_6n, self.report_6i
        total = utils + v4 + v6
        Reporter.group_report('IPv4Address', [self.report_4a])
        Reporter.group_report('IPv4Network', [self.report_4n])
        Reporter.group_report('IPv4INterface', [self.report_4i])
        Reporter.group_report('IPv6Address', [self.report_6a])
        Reporter.group_report('IPv6Network', [self.report_6n])
        Reporter.group_report('IPv6INterface', [self.report_6i])
        Reporter.group_report('Memory', [self.report_m], 'BIGGER', 'smaller')
        Reporter.group_report('Utils', utils)
        Reporter.group_report('Addresses', addresses)
        Reporter.group_report('Networks', networks)
        Reporter.group_report('Interfaces', interfaces)
        Reporter.group_report('IPv4', v4)
        Reporter.group_report('IPv6', v6)
        Reporter.group_report('TOTAL', total)

    # =========================================================================
    # Factory functions
    # =========================================================================

    def test_ip_address(self):
        """Test the ip_address function."""
        n = 10**4
        data = [
            '1.2.3.4',
            '::',
            '::%8',
            '1:2:3:4:5:6::',
            '::1.2.3.4',
            '1:2:3:4:5:6:7:8',
            '1:2:3:4:5:6:7:8%s',
            '1:2::7:8%1',
            0,
            2**32,
        ]
        fns = ip.ip_address, eip.ip_address
        for args in data:
            generic_test(self.report_u, fn_name(), n, fns, args)

    def test_ip_network(self):
        """Test the ip_network function."""
        n = 10**4
        data = [
            ('1.2.3.4/30'),
            ('1:2:3:4:5:6::/112'),
        ]
        fns = ip.ip_network, eip.ip_network
        for args in data:
            generic_test(self.report_u, fn_name(), n, fns, args)

    def test_ip_interface(self):
        """Test the ip_interface function."""
        n = 10**4
        data = [
            ('1.2.3.4/30'),
            ('1:2:3:4:5:6::/112'),
        ]
        fns = ip.ip_interface, eip.ip_interface
        for args in data:
            generic_test(self.report_u, fn_name(), n, fns, args)

    # =========================================================================
    # Utility functions
    # =========================================================================

    def test_ishexdigit(self):
        """Test the ishexdigit function."""
        n = 10**6
        data = [
            '0123456789ABCDEFabcdef',
            '1234',
            'abcd',
            'X',
        ]
        fns = ip._BaseV6._HEX_DIGITS.issuperset, eip.ishexdigit
        for args in data:
            generic_test(self.report_u, fn_name(), n, fns, args)

    def test_v4_int_to_packed(self):
        """Test the ip_v4_int_to_packed function."""
        n = 10**6
        data = [1]
        fns = ip.v4_int_to_packed, eip.v4_int_to_packed
        for args in data:
            generic_test(self.report_u, fn_name(), n, fns, args)

    def test_v6_int_to_packed(self):
        """Test the ip_v6_int_to_packed function."""
        n = 10**6
        data = [1]
        fns = ip.v6_int_to_packed, eip.v6_int_to_packed
        for args in data:
            generic_test(self.report_u, fn_name(), n, fns, args)

    def test_summarize_address_range(self):
        """Test the summarize_address_range function."""
        n = 10**3
        ranges = [
            ('0.0.0.0', '255.255.255.255'),
            ('0.0.0.1', '255.255.255.254'),
            ('1.2.3.4', '5.6.7.8'),
            ('1.2.3.4', '250.99.66.33'),
            ('1:2:3:4::', '5:6:7:8::'),
            ('1:2:3:4::', 'fff9:e789:5678:1234::'),
            ('::1', 2**128 - 1),
        ]
        for first, last in ranges:
            a1 = ip.ip_address(first)
            a2 = ip.ip_address(last)
            time1, result1 = timelist(n, ip.summarize_address_range, a1, a2)
            a1 = eip.ip_address(first)
            a2 = eip.ip_address(last)
            time2, result2 = timelist(n, eip.summarize_address_range, a1, a2)
            results = (time1, result1), (time2, result2)
            self.report_u.report(fn_name(), n, results, '%s - %s' %
                                 (first, last))

    def test_collapse_addresses(self):
        """Test the collapse_addresses function."""
        n = 10**4
        data = [
            ('1.2.0.0/16', '1.3.0.0/16', '1.4.0.0/16', '1.9.0.0/16',
             '1.2.3.4/30', '0.1.2.0/24', '1.2.3.4'),
            ('0.0.0.0/16', '0.1.0.0/16', '0.2.0.0/16', '0.8.0.0/16',
             '1.0.0.0', '1.0.0.1', '1.0.0.2', '1.0.0.3'),
            ('2::/16', '3::/16', '::', '::1'),
        ]
        for addrs in data:
            nets = [ip.ip_network(addr) for addr in addrs]
            time1, result1 = timelist(n, ip.collapse_addresses, nets)
            nets = [eip.ip_network(addr) for addr in addrs]
            time2, result2 = timelist(n, eip.collapse_addresses, nets)
            results = (time1, result1), (time2, result2)
            self.report_u.report(fn_name(), n, results, addrs)

    def test_get_mixed_type_key(self):
        """Test the get_mixed_type_key function."""
        n = 10**6
        data = [
            '1.2.3.4',
            '2001::',
        ]
        for factories in [
            (ip.ip_address, eip.ip_address),
            (ip.ip_interface, eip.ip_interface),
            (ip.ip_network, eip.ip_network),
        ]:
            for val in data:
                addr = factories[0](val)
                time1, result1 = timelist(n, ip.get_mixed_type_key, addr)
                addr = factories[1](val)
                time2, result2 = timelist(n, eip.get_mixed_type_key, addr)
                # results will be ordered differently, so don't compare them
                results = (time1, None), (time2, None)
                self.report_u.report(fn_name(), n, results, repr(addr))

    def test_sort_get_mixed_type_key(self):
        """Test sorting with the get_mixed_type_key function."""
        n = 10**2
        data4 = list(range(0, 2000, 7)) + list(range(2000, 0, -13))
        data6 = list(range(0, 3000, 11)) + list(range(3000, 0, -17))
        # create ip addresses, interfaces and network
        v4_addrs = [ip.IPv4Address(x) for x in data4]
        v4_ifcs = [ip.IPv4Interface(x) for x in data4]
        v4_nets = [ip.IPv4Network(x) for x in data4]
        v6_addrs = [ip.IPv6Address(x) for x in data6]
        v6_ifcs = [ip.IPv6Interface(x) for x in data6]
        v6_nets = [ip.IPv6Network(x) for x in data6]
        # mix them up a bit
        v4_addrs = v4_addrs[20::] + v4_addrs[::20]
        v4_ifcs = v4_ifcs[10::] + v4_ifcs[::10]
        v4_nets = v4_nets[30::] + v4_nets[::30]
        v6_addrs = v6_addrs[25::] + v6_addrs[::25]
        v6_ifcs = v6_ifcs[15::] + v6_ifcs[::15]
        v6_nets = v6_nets[35::] + v6_nets[::35]
        # combine them
        ips = v4_addrs + v6_ifcs + v4_nets + v6_addrs + v4_ifcs + v6_nets
        # create eip addresses, interfaces and network
        ev4_addrs = [eip.IPv4Address(x) for x in data4]
        ev4_ifcs = [eip.IPv4Interface(x) for x in data4]
        ev4_nets = [eip.IPv4Network(x) for x in data4]
        ev6_addrs = [eip.IPv6Address(x) for x in data6]
        ev6_ifcs = [eip.IPv6Interface(x) for x in data6]
        ev6_nets = [eip.IPv6Network(x) for x in data6]
        # mix them up a bit
        ev4_addrs = ev4_addrs[20::] + ev4_addrs[::20]
        ev4_ifcs = ev4_ifcs[10::] + ev4_ifcs[::10]
        ev4_nets = ev4_nets[30::] + ev4_nets[::30]
        ev6_addrs = ev6_addrs[25::] + ev6_addrs[::25]
        ev6_ifcs = ev6_ifcs[15::] + ev6_ifcs[::15]
        ev6_nets = ev6_nets[35::] + ev6_nets[::35]
        # combine them
        eips = ev4_addrs + ev6_ifcs + ev4_nets + ev6_addrs + ev4_ifcs + ev6_nets
        # sort the lists
        time1, result1 = timefn(n, sorted, ips, key=ip.get_mixed_type_key)
        time2, result2 = timefn(n, sorted, eips, key=eip.get_mixed_type_key)
        # results will be ordered differently, so don't compare them
        results = (time1, None), (time2, None)
        num_v4 = len(v4_addrs), len(v4_ifcs), len(v4_nets)
        num_v6 = len(v6_addrs), len(v6_ifcs), len(v6_nets)
        self.report_u.report(fn_name(), n, results, (len(ips), num_v4, num_v6))

    # =========================================================================
    # IPv4Address
    # =========================================================================

    def test_ipv4address_init(self):
        """Test the IPv4Address.__init__ method."""
        n = 10**5
        data = [
            '1.2.3.4',
            16384,
            int(42).to_bytes(4, 'big'),
        ]
        fns = ip.IPv4Address, eip.IPv4Address
        for args in data:
            generic_test(self.report_4a, fn_name(), n, fns, args)

    def test_ipv4address_int(self):
        """Test the IPv4Address.__int__ method."""
        n = 10**6
        addr = ip.IPv4Address('1.2.3.4')
        eaddr = eip.IPv4Address('1.2.3.4')
        fns = addr.__int__, eaddr.__int__
        generic_test(self.report_4a, fn_name(), n, fns)

    def test_ipv4address_eq_(self):
        """Test the IPv4Address.__eq__ method."""
        n = 10**6
        data = [
            ('1.2.3.4', '1.2.3.4'),
            ('1.2.3.4', '1.2.3.3'),
            ('1.2.3.4', '2.3.4.5'),
        ]
        for a1, a2 in data:
            addr1 = ip.IPv4Address(a1)
            addr2 = ip.IPv4Address(a2)
            time1, result1 = timefn(n, addr1.__eq__, addr2)
            eaddr1 = eip.IPv4Address(a1)
            eaddr2 = eip.IPv4Address(a2)
            time2, result2 = timefn(n, eaddr1.__eq__, eaddr2)
            results = (time1, result1), (time2, result2)
            self.report_4a.report(fn_name(), n, results, (addr1, addr2))

    def test_ipv4address_ne_(self):
        """Test the IPv4Address.__ne__ method."""
        n = 10**6
        data = [
            ('1.2.3.4', '1.2.3.4'),
            ('1.2.3.4', '1.2.3.3'),
            ('1.2.3.4', '2.3.4.5'),
        ]
        for a1, a2 in data:
            addr1 = ip.IPv4Address(a1)
            addr2 = ip.IPv4Address(a2)
            time1, result1 = timefn(n, addr1.__ne__, addr2)
            eaddr1 = eip.IPv4Address(a1)
            eaddr2 = eip.IPv4Address(a2)
            time2, result2 = timefn(n, eaddr1.__ne__, eaddr2)
            results = (time1, result1), (time2, result2)
            self.report_4a.report(fn_name(), n, results, (addr1, addr2))

    def test_ipv4address_lt_(self):
        """Test the IPv4Address.__lt__ method."""
        n = 10**6
        data = [
            ('1.2.3.4', '1.2.3.4'),
            ('1.2.3.4', '1.2.3.3'),
            ('1.2.3.4', '2.3.4.5'),
        ]
        for a1, a2 in data:
            addr1 = ip.IPv4Address(a1)
            addr2 = ip.IPv4Address(a2)
            time1, result1 = timefn(n, addr1.__lt__, addr2)
            eaddr1 = eip.IPv4Address(a1)
            eaddr2 = eip.IPv4Address(a2)
            time2, result2 = timefn(n, eaddr1.__lt__, eaddr2)
            results = (time1, result1), (time2, result2)
            self.report_4a.report(fn_name(), n, results, (addr1, addr2))

    def test_ipv4address_le_(self):
        """Test the IPv4Address.__le__ method."""
        n = 10**6
        data = [
            ('1.2.3.4', '1.2.3.4'),
            ('1.2.3.4', '1.2.3.3'),
            ('1.2.3.4', '2.3.4.5'),
        ]
        for a1, a2 in data:
            addr1 = ip.IPv4Address(a1)
            addr2 = ip.IPv4Address(a2)
            time1, result1 = timefn(n, addr1.__le__, addr2)
            eaddr1 = eip.IPv4Address(a1)
            eaddr2 = eip.IPv4Address(a2)
            time2, result2 = timefn(n, eaddr1.__le__, eaddr2)
            results = (time1, result1), (time2, result2)
            self.report_4a.report(fn_name(), n, results, (addr1, addr2))

    def test_ipv4address_gt_(self):
        """Test the IPv4Address.__gt__ method."""
        n = 10**6
        data = [
            ('1.2.3.4', '1.2.3.4'),
            ('1.2.3.4', '1.2.3.3'),
            ('1.2.3.4', '2.3.4.5'),
        ]
        for a1, a2 in data:
            addr1 = ip.IPv4Address(a1)
            addr2 = ip.IPv4Address(a2)
            time1, result1 = timefn(n, addr1.__gt__, addr2)
            eaddr1 = eip.IPv4Address(a1)
            eaddr2 = eip.IPv4Address(a2)
            time2, result2 = timefn(n, eaddr1.__gt__, eaddr2)
            results = (time1, result1), (time2, result2)
            self.report_4a.report(fn_name(), n, results, (addr1, addr2))

    def test_ipv4address_ge_(self):
        """Test the IPv4Address.__ge__ method."""
        n = 10**6
        data = [
            ('1.2.3.4', '1.2.3.4'),
            ('1.2.3.4', '1.2.3.3'),
            ('1.2.3.4', '2.3.4.5'),
        ]
        for a1, a2 in data:
            addr1 = ip.IPv4Address(a1)
            addr2 = ip.IPv4Address(a2)
            time1, result1 = timefn(n, addr1.__ge__, addr2)
            eaddr1 = eip.IPv4Address(a1)
            eaddr2 = eip.IPv4Address(a2)
            time2, result2 = timefn(n, eaddr1.__ge__, eaddr2)
            results = (time1, result1), (time2, result2)
            self.report_4a.report(fn_name(), n, results, (addr1, addr2))

    def test_ipv4address_add(self):
        """Test the IPv4Address.__add__ method."""
        n = 10**5
        addr1 = ip.IPv4Address('1.2.3.4')
        time1, result1 = timefn(n, addr1.__add__, 2)
        eaddr1 = eip.IPv4Address('1.2.3.4')
        time2, result2 = timefn(n, eaddr1.__add__, 2)
        results = (time1, result1), (time2, result2)
        self.report_4a.report(fn_name(), n, results, (addr1, 2))

    def test_ipv4address_sub(self):
        """Test the IPv4Address.__sub__ method."""
        n = 10**5
        addr1 = ip.IPv4Address('1.2.3.4')
        time1, result1 = timefn(n, addr1.__sub__, 2)
        eaddr1 = eip.IPv4Address('1.2.3.4')
        time2, result2 = timefn(n, eaddr1.__sub__, 2)
        results = (time1, result1), (time2, result2)
        self.report_4a.report(fn_name(), n, results, (addr1, 2))

    def test_ipv4address_hash(self):
        """Test the IPv4Address.__hash__ method."""
        n = 10**6
        addr1 = ip.IPv4Address('1.2.3.4')
        time1, result1 = timefn(n, addr1.__hash__)
        eaddr1 = eip.IPv4Address('1.2.3.4')
        time2, result2 = timefn(n, eaddr1.__hash__)
        # results will differ, so don't compare them
        results = (time1, None), (time2, None)
        self.report_4a.report(fn_name(), n, results, addr1)

    def test_ipv4address_str(self):
        """Test the IPv4Address.__str__ method."""
        n = 10**5
        addr = ip.IPv4Address('1.2.3.4')
        time1, result1 = timefn(n, addr.__str__)
        eaddr = eip.IPv4Address('1.2.3.4')
        time2, result2 = timefn(n, eaddr.__str__)
        results = (time1, result1), (time2, result2)
        self.report_4a.report(fn_name(), n, results, addr)

    def test_ipv4address_repr(self):
        """Test the IPv4Address.__repr__ method."""
        n = 10**5
        addr = ip.IPv4Address('1.2.3.4')
        time1, result1 = timefn(n, addr.__repr__)
        eaddr = eip.IPv4Address('1.2.3.4')
        time2, result2 = timefn(n, eaddr.__repr__)
        results = (time1, result1), (time2, result2)
        self.report_4a.report(fn_name(), n, results, addr)

    def test_ipv4address_reduce(self):
        """Test the IPv4Address.__reduce__ method."""
        n = 10**6
        addr = ip.IPv4Address('1.2.3.4')
        time1, result1 = timefn(n, addr.__reduce__)
        eaddr = eip.IPv4Address('1.2.3.4')
        time2, result2 = timefn(n, eaddr.__reduce__)
        # results will differ, so don't compare them
        results = (time1, None), (time2, None)
        self.report_4a.report(fn_name(), n, results, addr)

    def test_ipv4address_compressed(self):
        """Test the IPv4Address.compressed method."""
        n = 10**5
        addr = ip.IPv4Address('1.2.3.4')
        time1, result1 = timefn(n, lambda: addr.compressed)
        eaddr = eip.IPv4Address('1.2.3.4')
        time2, result2 = timefn(n, lambda: eaddr.compressed)
        results = (time1, result1), (time2, result2)
        self.report_4a.report(fn_name(), n, results, addr)

    def test_ipv4address_exploded(self):
        """Test the IPv4Address.exploded method."""
        n = 10**5
        addr = eip.IPv4Address('1.2.3.4')
        time1, result1 = timefn(n, lambda: addr.exploded)
        eaddr = eip.IPv4Address('1.2.3.4')
        time2, result2 = timefn(n, lambda: eaddr.exploded)
        results = (time1, result1), (time2, result2)
        self.report_4a.report(fn_name(), n, results, addr)

    def test_ipv4address_format(self):
        """Test the IPv4Address.__format__ method."""
        n = 10**5
        data = ['s', 'b', 'x', 'n', '#b', '_b', '#_x']
        a1 = '1.2.3.4'
        addr = ip.IPv4Address(a1)
        eaddr = eip.IPv4Address(a1)
        fns = addr.__format__, eaddr.__format__
        for args in data:
            generic_test(self.report_4a, fn_name(), n, fns, args)

    def test_ipv4address_reverse_pointer(self):
        """Test the IPv4Address.reverse_pointer method."""
        n = 10**5
        addr = ip.IPv4Address('1.2.3.4')
        time1, result1 = timefn(n, lambda: addr.reverse_pointer)
        eaddr = eip.IPv4Address('1.2.3.4')
        time2, result2 = timefn(n, lambda: eaddr.reverse_pointer)
        results = (time1, result1), (time2, result2)
        self.report_4a.report(fn_name(), n, results, addr)

    def test_ipv4address_max_prefixlen(self):
        """Test the IPv4Address.max_prefixlen method."""
        n = 10**6
        addr = ip.IPv4Address('1.2.3.0')
        time1, result1 = timefn(n, lambda: addr.max_prefixlen)
        eaddr = eip.IPv4Address('1.2.3.0')
        time2, result2 = timefn(n, lambda: eaddr.max_prefixlen)
        results = (time1, result1), (time2, result2)
        self.report_4a.report(fn_name(), n, results, addr)

    def test_ipv4address_is_reserved(self):
        """Test the IPv4Address.is_reserved method."""
        n = 10**6
        addrs = ['1.2.3.4', '240.0.0.1']
        for a in addrs:
            addr = ip.IPv4Address(a)
            time1, result1 = timefn(n, lambda: addr.is_multicast)
            eaddr = eip.IPv4Address(a)
            time2, result2 = timefn(n, lambda: eaddr.is_multicast)
            results = (time1, result1), (time2, result2)
            self.report_4a.report(fn_name(), n, results, a)

    def test_ipv4address_is_private(self):
        """Test the IPv4Address.is_private method."""
        addrs = ['1.2.3.4', '10.0.0.1', '172.16.0.1', '192.168.0.1']
        for n in 1, 10**6:
            for a in addrs:
                addr = ip.IPv4Address(a)
                time1, result1 = timefn(n, lambda: addr.is_private)
                eaddr = eip.IPv4Address(a)
                time2, result2 = timefn(n, lambda: eaddr.is_private)
                results = (time1, result1), (time2, result2)
                self.report_4a.report(fn_name(), n, results, a)

    def test_ipv4address_is_global(self):
        """Test the IPv4Address.is_global method."""
        addrs = ['1.2.3.4', '10.0.0.1', '172.16.0.1', '192.168.0.1']
        for n in 1, 10**6:
            for a in addrs:
                addr = ip.IPv4Address(a)
                time1, result1 = timefn(n, lambda: addr.is_global)
                eaddr = eip.IPv4Address(a)
                time2, result2 = timefn(n, lambda: eaddr.is_global)
                results = (time1, result1), (time2, result2)
                self.report_4a.report(fn_name(), n, results, a)

    def test_ipv4address_is_multicast(self):
        """Test the IPv4Address.is_multicast method."""
        n = 10**6
        addrs = ['1.2.3.4', '224.0.0.1']
        for a in addrs:
            addr = ip.IPv4Address(a)
            time1, result1 = timefn(n, lambda: addr.is_multicast)
            eaddr = eip.IPv4Address(a)
            time2, result2 = timefn(n, lambda: eaddr.is_multicast)
            results = (time1, result1), (time2, result2)
            self.report_4a.report(fn_name(), n, results, a)

    def test_ipv4address_is_unspecified(self):
        """Test the IPv4Address.is_unspecified method."""
        n = 10**6
        addrs = ['1.2.3.4', '0.0.0.0']
        for a in addrs:
            addr = ip.IPv4Address(a)
            time1, result1 = timefn(n, lambda: addr.is_unspecified)
            eaddr = eip.IPv4Address(a)
            time2, result2 = timefn(n, lambda: eaddr.is_unspecified)
            results = (time1, result1), (time2, result2)
            self.report_4a.report(fn_name(), n, results, a)

    def test_ipv4address_is_loopback(self):
        """Test the IPv4Address.is_loopback method."""
        n = 10**6
        addrs = ['1.2.3.4', '127.0.0.1']
        for a in addrs:
            addr = ip.IPv4Address(a)
            time1, result1 = timefn(n, lambda: addr.is_loopback)
            eaddr = eip.IPv4Address(a)
            time2, result2 = timefn(n, lambda: eaddr.is_loopback)
            results = (time1, result1), (time2, result2)
            self.report_4a.report(fn_name(), n, results, a)

    def test_ipv4address_is_link_local(self):
        """Test the IPv4Address.is_link_local method."""
        n = 10**6
        addrs = ['1.2.3.4', '169.254.0.1']
        for a in addrs:
            addr = ip.IPv4Address(a)
            time1, result1 = timefn(n, lambda: addr.is_link_local)
            eaddr = eip.IPv4Address(a)
            time2, result2 = timefn(n, lambda: eaddr.is_link_local)
            results = (time1, result1), (time2, result2)
            self.report_4a.report(fn_name(), n, results, a)

    def test_ipv4address_packed(self):
        """Test the IPv4Address.packed function."""
        n = 10**6
        a = 1
        addr = eip.IPv4Address(a)
        time1, result1 = timefn(n, lambda: addr.packed)
        eaddr = eip.IPv4Address(a)
        time2, result2 = timefn(n, lambda: eaddr.packed)
        results = (time1, result1), (time2, result2)
        self.report_4a.report(fn_name(), n, results, a)

    # =========================================================================
    # IPv6Address
    # =========================================================================

    def test_ipv6address_init(self):
        """Test the IPv6Address.__init__ method."""
        n = 10**5
        data = [
            '1:2:3:4:5:6::',
            16384,
            int(42).to_bytes(16, 'big'),
        ]
        fns = ip.IPv6Address, eip.IPv6Address
        for args in data:
            generic_test(self.report_6a, fn_name(), n, fns, args)

    def test_ipv6address_int(self):
        """Test the IPv6Address.__int__ method."""
        n = 10**6
        addr = ip.IPv6Address('1:2:3:4:5:6::')
        time1, result1 = timefn(n, addr.__int__)
        eaddr = eip.IPv6Address('1:2:3:4:5:6::')
        time2, result2 = timefn(n, eaddr.__int__)
        results = (time1, result1), (time2, result2)
        self.report_6a.report(fn_name(), n, results, addr)

    def test_ipv6address_eq_(self):
        """Test the IPv6Address.__eq__ method."""
        n = 10**6
        data = [
            ('::4', '::4'),
            ('::4', '::3'),
            ('::4', '::5'),
        ]
        for a1, a2 in data:
            addr1 = ip.IPv6Address(a1)
            addr2 = ip.IPv6Address(a2)
            time1, result1 = timefn(n, addr1.__eq__, addr2)
            eaddr1 = eip.IPv6Address(a1)
            eaddr2 = eip.IPv6Address(a2)
            time2, result2 = timefn(n, eaddr1.__eq__, eaddr2)
            results = (time1, result1), (time2, result2)
            self.report_6a.report(fn_name(), n, results, (addr1, addr2))

    def test_ipv6address_ne_(self):
        """Test the IPv6Address.__ne__ method."""
        n = 10**6
        data = [
            ('::4', '::4'),
            ('::4', '::3'),
            ('::4', '::5'),
        ]
        for a1, a2 in data:
            addr1 = ip.IPv6Address(a1)
            addr2 = ip.IPv6Address(a2)
            time1, result1 = timefn(n, addr1.__ne__, addr2)
            eaddr1 = eip.IPv6Address(a1)
            eaddr2 = eip.IPv6Address(a2)
            time2, result2 = timefn(n, eaddr1.__ne__, eaddr2)
            results = (time1, result1), (time2, result2)
            self.report_6a.report(fn_name(), n, results, (addr1, addr2))

    def test_ipv6address_lt_(self):
        """Test the IPv6Address.__lt__ method."""
        n = 10**6
        data = [
            ('::4', '::4'),
            ('::4', '::3'),
            ('::4', '::5'),
        ]
        for a1, a2 in data:
            addr1 = ip.IPv6Address(a1)
            addr2 = ip.IPv6Address(a2)
            time1, result1 = timefn(n, addr1.__lt__, addr2)
            eaddr1 = eip.IPv6Address(a1)
            eaddr2 = eip.IPv6Address(a2)
            time2, result2 = timefn(n, eaddr1.__lt__, eaddr2)
            results = (time1, result1), (time2, result2)
            self.report_6a.report(fn_name(), n, results, (addr1, addr2))

    def test_ipv6address_le_(self):
        """Test the IPv6Address.__le__ method."""
        n = 10**6
        data = [
            ('::4', '::4'),
            ('::4', '::3'),
            ('::4', '::5'),
        ]
        for a1, a2 in data:
            addr1 = ip.IPv6Address(a1)
            addr2 = ip.IPv6Address(a2)
            time1, result1 = timefn(n, addr1.__le__, addr2)
            eaddr1 = eip.IPv6Address(a1)
            eaddr2 = eip.IPv6Address(a2)
            time2, result2 = timefn(n, eaddr1.__le__, eaddr2)
            results = (time1, result1), (time2, result2)
            self.report_6a.report(fn_name(), n, results, (addr1, addr2))

    def test_ipv6address_gt_(self):
        """Test the IPv6Address.__gt__ method."""
        n = 10**6
        data = [
            ('::4', '::4'),
            ('::4', '::3'),
            ('::4', '::5'),
        ]
        for a1, a2 in data:
            addr1 = ip.IPv6Address(a1)
            addr2 = ip.IPv6Address(a2)
            time1, result1 = timefn(n, addr1.__gt__, addr2)
            eaddr1 = eip.IPv6Address(a1)
            eaddr2 = eip.IPv6Address(a2)
            time2, result2 = timefn(n, eaddr1.__gt__, eaddr2)
            results = (time1, result1), (time2, result2)
            self.report_6a.report(fn_name(), n, results, (addr1, addr2))

    def test_ipv6address_ge_(self):
        """Test the IPv6Address.__ge__ method."""
        n = 10**6
        data = [
            ('::4', '::4'),
            ('::4', '::3'),
            ('::4', '::5'),
        ]
        for a1, a2 in data:
            addr1 = ip.IPv6Address(a1)
            addr2 = ip.IPv6Address(a2)
            time1, result1 = timefn(n, addr1.__ge__, addr2)
            eaddr1 = eip.IPv6Address(a1)
            eaddr2 = eip.IPv6Address(a2)
            time2, result2 = timefn(n, eaddr1.__ge__, eaddr2)
            results = (time1, result1), (time2, result2)
            self.report_6a.report(fn_name(), n, results, (addr1, addr2))

    def test_ipv6address_add(self):
        """Test the IPv6Address.__add__ method."""
        n = 10**5
        addr1 = ip.IPv6Address('1:2:3:4:5:6::')
        time1, result1 = timefn(n, addr1.__add__, 2)
        eaddr1 = eip.IPv6Address('1:2:3:4:5:6::')
        time2, result2 = timefn(n, eaddr1.__add__, 2)
        results = (time1, result1), (time2, result2)
        self.report_6a.report(fn_name(), n, results, (addr1, 2))

    def test_ipv6address_sub(self):
        """Test the IPv6Address.__sub__ method."""
        n = 10**5
        addr1 = ip.IPv6Address('1:2:3:4:5:6::')
        time1, result1 = timefn(n, addr1.__sub__, 2)
        eaddr1 = eip.IPv6Address('1:2:3:4:5:6::')
        time2, result2 = timefn(n, eaddr1.__sub__, 2)
        results = (time1, result1), (time2, result2)
        self.report_6a.report(fn_name(), n, results, (addr1, 2))

    def test_ipv6address_hash(self):
        """Test the IPv6Address.__hash__ method."""
        n = 10**6
        addr1 = ip.IPv6Address('1:2:3:4:5:6::')
        time1, result1 = timefn(n, addr1.__hash__)
        eaddr1 = eip.IPv6Address('1:2:3:4:5:6::')
        time2, result2 = timefn(n, eaddr1.__hash__)
        results = (time1, None), (time2, None)
        self.report_6a.report(fn_name(), n, results, addr1)

    def test_ipv6address_str(self):
        """Test the IPv6Address.__str__ method."""
        n = 10**4
        addrs = ['1:2:3:4:5:6::', '::', '::5:6:7:8', '1:2:3:4::', '1:2::7:8']
        for a in addrs:
            addr = ip.IPv6Address(a)
            time1, result1 = timefn(n, addr.__str__)
            eaddr = eip.IPv6Address(a)
            time2, result2 = timefn(n, eaddr.__str__)
            results = (time1, result1), (time2, result2)
            self.report_6a.report(fn_name(), n, results, addr)

    def test_ipv6address_repr(self):
        """Test the IPv6Address.__repr__ method."""
        n = 10**4
        addrs = ['1:2:3:4:5:6::', '::', '::5:6:7:8', '1:2:3:4::', '1:2::7:8']
        for a in addrs:
            addr = ip.IPv6Address(a)
            time1, result1 = timefn(n, addr.__repr__)
            eaddr = eip.IPv6Address(a)
            time2, result2 = timefn(n, eaddr.__repr__)
            results = (time1, result1), (time2, result2)
            self.report_6a.report(fn_name(), n, results, addr)

    def test_ipv6address_reduce(self):
        """Test the IPv6Address.__reduce__ method."""
        n = 10**6
        addr = ip.IPv6Address('2001::')
        time1, result1 = timefn(n, addr.__reduce__)
        eaddr = eip.IPv6Address('2001::')
        time2, result2 = timefn(n, eaddr.__reduce__)
        # results will differ, so don't compare them
        results = (time1, None), (time2, None)
        self.report_6a.report(fn_name(), n, results, addr)

    def test_ipv6address_format(self):
        """Test the IPv6Address.__format__ method."""
        n = 10**5
        data = ['s', 'b', 'x', 'n', '#b', '_b', '#_x']
        a1 = '1:2:3::6'
        addr = ip.IPv6Address(a1)
        eaddr = eip.IPv6Address(a1)
        fns = addr.__format__, eaddr.__format__
        for args in data:
            generic_test(self.report_6a, fn_name(), n, fns, args)

    def test_ipv6address_compressed(self):
        """Test the IPv6Address.compressed method."""
        n = 10**5
        addr = ip.IPv6Address('1:2:3::6')
        time1, result1 = timefn(n, lambda: addr.compressed)
        eaddr = eip.IPv6Address('1:2:3::6')
        time2, result2 = timefn(n, lambda: eaddr.compressed)
        results = (time1, result1), (time2, result2)
        self.report_6a.report(fn_name(), n, results, addr)

    def test_ipv6address_exploded(self):
        """Test the IPv6Address.exploded method."""
        n = 10**4
        addrs = ['1:2:3:4:5:6::', '::', '::5:6:7:8', '1:2:3:4::', '1:2::7:8']
        for a in addrs:
            addr = ip.IPv6Address(a)
            time1, result1 = timefn(n, lambda: addr.exploded)
            eaddr = eip.IPv6Address(a)
            time2, result2 = timefn(n, lambda: eaddr.exploded)
            results = (time1, result1), (time2, result2)
            self.report_6a.report(fn_name(), n, results, addr)

    def test_ipv6address_reverse_pointer(self):
        """Test the IPv6Address.reverse_pointer method."""
        n = 10**4
        addr = ip.IPv6Address('1:2:3:4:5:6::')
        time1, result1 = timefn(n, lambda: addr.reverse_pointer)
        eaddr = eip.IPv6Address('1:2:3:4:5:6::')
        time2, result2 = timefn(n, lambda: eaddr.reverse_pointer)
        results = (time1, result1), (time2, result2)
        self.report_6a.report(fn_name(), n, results, addr)

    def test_ipv6Address_max_prefixlen(self):
        """Test the IPv6Address.max_prefixlen method."""
        n = 10**6
        addr = ip.IPv6Address('1:2:3:4:5:6::')
        time1, result1 = timefn(n, lambda: addr.max_prefixlen)
        eaddr = eip.IPv6Address('1:2:3:4:5:6::')
        time2, result2 = timefn(n, lambda: eaddr.max_prefixlen)
        results = (time1, result1), (time2, result2)
        self.report_6a.report(fn_name(), n, results, addr)

    def _test_ipv6address_is_reserved(self):
        """Test the IPv6Address.is_reserved method."""
        n = 10**4
        addrs = [
            '2001:2:3:4:5:6::',
            '::1',
            '100::1',
            '200::1',
            '400::1',
            '800::1',
            '1000::1',
            '4000::1',
            '6000::1',
            '8000::1',
            'A000::1',
            'C000::1',
            'E000::1',
            'F000::1',
            'F800::1',
            'FE00::1',
        ]
        for a in addrs:
            addr = ip.IPv6Address(a)
            time1, result1 = timefn(n, lambda: addr.is_multicast)
            eaddr = eip.IPv6Address(a)
            time2, result2 = timefn(n, lambda: eaddr.is_multicast)
            results = (time1, result1), (time2, result2)
            self.report_6a.report(fn_name(), n, results, a)

    def test_ipv6address_is_private(self):
        """Test the IPv6Address.is_private method."""
        addrs = [
            '::',
            '::1',
            '::ffff:0:0',
            '100::',
            '2001::',
            '2001:2::',
            '2001:10::',
            '2001:db8::',
            'fc00::',
            'fe80::',
            '::2',
        ]
        for n in 1, 10**5:
            for a in addrs:
                addr = ip.IPv6Address(a)
                time1, result1 = timefn(n, lambda: addr.is_private)
                eaddr = eip.IPv6Address(a)
                time2, result2 = timefn(n, lambda: eaddr.is_private)
                results = (time1, result1), (time2, result2)
                self.report_6a.report(fn_name(), n, results, a)

    def test_ipv6address_is_global(self):
        """Test the IPv6Address.is_global method."""
        addrs = [
            '::',
            '::1',
            '::ffff:0:0',
            '100::',
            '2001::',
            '2001:2::',
            '2001:10::',
            '2001:db8::',
            'fc00::',
            'fe80::',
            '::2',
        ]
        for n in 1, 10**6:
            for a in addrs:
                addr = ip.IPv6Address(a)
                time1, result1 = timefn(n, lambda: addr.is_global)
                eaddr = eip.IPv6Address(a)
                time2, result2 = timefn(n, lambda: eaddr.is_global)
                results = (time1, result1), (time2, result2)
                self.report_6a.report(fn_name(), n, results, a)

    def test_ipv6address_is_multicast(self):
        """Test the IPv6Address.is_multicast method."""
        n = 10**6
        addrs = ['1:2:3:4:5:6::', 'ff00::1']
        for a in addrs:
            addr = ip.IPv6Address(a)
            time1, result1 = timefn(n, lambda: addr.is_multicast)
            eaddr = eip.IPv6Address(a)
            time2, result2 = timefn(n, lambda: eaddr.is_multicast)
            results = (time1, result1), (time2, result2)
            self.report_6a.report(fn_name(), n, results, a)

    def test_ipv6address_is_unspecified(self):
        """Test the IPv6Address.is_unspecified method."""
        n = 10**6
        addrs = ['1:2:3:4:5:6::', '::']
        for a in addrs:
            addr = ip.IPv6Address(a)
            time1, result1 = timefn(n, lambda: addr.is_unspecified)
            eaddr = eip.IPv6Address(a)
            time2, result2 = timefn(n, lambda: eaddr.is_unspecified)
            results = (time1, result1), (time2, result2)
            self.report_6a.report(fn_name(), n, results, a)

    def test_ipv6address_is_loopback(self):
        """Test the IPv6Address.is_loopback method."""
        n = 10**6
        addrs = ['1:2:3:4:5:6::', '::1']
        for a in addrs:
            addr = ip.IPv6Address(a)
            time1, result1 = timefn(n, lambda: addr.is_loopback)
            eaddr = eip.IPv6Address(a)
            time2, result2 = timefn(n, lambda: eaddr.is_loopback)
            results = (time1, result1), (time2, result2)
            self.report_6a.report(fn_name(), n, results, a)

    def test_ipv6address_is_link_local(self):
        """Test the IPv6Address.is_link_local method."""
        n = 10**6
        addrs = ['1:2:3:4:5:6::', 'fe80::1']
        for a in addrs:
            addr = ip.IPv6Address(a)
            time1, result1 = timefn(n, lambda: addr.is_link_local)
            eaddr = eip.IPv6Address(a)
            time2, result2 = timefn(n, lambda: eaddr.is_link_local)
            results = (time1, result1), (time2, result2)
            self.report_6a.report(fn_name(), n, results, a)

    def test_ipv6address_is_site_local(self):
        """Test the IPv6Address.is_site_local method."""
        n = 10**6
        addrs = ['1:2:3:4:5:6::', 'fec0::1']
        for a in addrs:
            addr = ip.IPv6Address(a)
            time1, result1 = timefn(n, lambda: addr.is_site_local)
            eaddr = eip.IPv6Address(a)
            time2, result2 = timefn(n, lambda: eaddr.is_site_local)
            results = (time1, result1), (time2, result2)
            self.report_6a.report(fn_name(), n, results, a)

    def test_ipv6address_ipv4_mapped(self):
        """Test the IPv6Address.ipv4_mapped method."""
        n = 10**6
        addrs = ['1:2:3:4:5:6::', '::ffff:1.2.3.4']
        for a in addrs:
            addr = ip.IPv6Address(a)
            time1, result1 = timefn(n, lambda: addr.ipv4_mapped)
            eaddr = eip.IPv6Address(a)
            time2, result2 = timefn(n, lambda: addr.ipv4_mapped)
            results = (time1, result1), (time2, result2)
            self.report_6a.report(fn_name(), n, results, a)

    def test_ipv6address_teredo(self):
        """Test the IPv6Address.teredo method."""
        n = 10**5
        addrs = ['1:2:3:4:5:6::', '2001::ffff:1']
        for a in addrs:
            addr = ip.IPv6Address(a)
            time1, result1 = timefn(n, lambda: addr.teredo)
            eaddr = eip.IPv6Address(a)
            time2, result2 = timefn(n, lambda: addr.teredo)
            results = (time1, result1), (time2, result2)
            self.report_6a.report(fn_name(), n, results, a)

    def test_ipv6address_sixtofour(self):
        """Test the IPv6Address.sixtofour method."""
        n = 10**5
        addrs = ['1:2:3:4:5:6::', '2002:0102:0304::']
        for a in addrs:
            addr = ip.IPv6Address(a)
            time1, result1 = timefn(n, lambda: addr.sixtofour)
            eaddr = eip.IPv6Address(a)
            time2, result2 = timefn(n, lambda: addr.sixtofour)
            results = (time1, result1), (time2, result2)
            self.report_6a.report(fn_name(), n, results, a)

    def test_ipv6address_packed(self):
        """Test the IPv6Address.packed function."""
        n = 10**6
        a = 1
        addr = ip.IPv6Address(a)
        time1, result1 = timefn(n, lambda: addr.packed)
        eaddr = eip.IPv6Address(a)
        time2, result2 = timefn(n, lambda: eaddr.packed)
        results = (time1, result1), (time2, result2)
        self.report_6a.report(fn_name(), n, results, a)

    def test_ipv6address_scope_id(self):
        """Test the IPv6Address.scope_id function."""
        n = 10**6
        a = '2020::%a1'
        addr = ip.IPv6Address(a)
        time1, result1 = timefn(n, lambda: addr.scope_id)
        eaddr = eip.IPv6Address(a)
        time2, result2 = timefn(n, lambda: eaddr.scope_id)
        results = (time1, result1), (time2, result2)
        self.report_6a.report(fn_name(), n, results, a)

    # =========================================================================
    # IPv4Network
    # =========================================================================

    def test_ipv4network_init(self):
        """Test the IPv4Network.__init__ method."""
        n = 10**5
        data = [
            '1.2.3.0/24',
            '1.2.3.4',
            16384,
            ('10.1.0.0', 16),
            (65536, 16),
            (int(64).to_bytes(4, 'big'), 28),
        ]
        fns = ip.IPv4Network, eip.IPv4Network
        for args in data:
            generic_test(self.report_4n, fn_name(), n, fns, args)

    def test_ipv4network_eq_(self):
        """Test the IPv4Network.__eq__ method."""
        n = 10**5
        data = [
            ('1.2.4.0/24', '1.2.4.0/24'),
            ('1.2.4.0/24', '1.2.3.0/24'),
            ('1.2.4.0/24', '1.2.5.0/24'),
            ('1.2.4.0/24', '1.2.4.0/23'),
            ('1.2.4.0/24', '1.2.4.0/25'),
        ]
        for n1, n2 in data:
            net1 = ip.IPv4Network(n1)
            net2 = ip.IPv4Network(n2)
            time1, result1 = timefn(n, net1.__eq__, net2)
            enet1 = eip.IPv4Network(n1)
            enet2 = eip.IPv4Network(n2)
            time2, result2 = timefn(n, enet1.__eq__, enet2)
            results = (time1, result1), (time2, result2)
            self.report_4n.report(fn_name(), n, results, (net1, net2))

    def test_ipv4network_ne_(self):
        """Test the IPv4Network.__ne__ method."""
        n = 10**5
        data = [
            ('1.2.4.0/24', '1.2.4.0/24'),
            ('1.2.4.0/24', '1.2.3.0/24'),
            ('1.2.4.0/24', '1.2.5.0/24'),
            ('1.2.4.0/24', '1.2.4.0/23'),
            ('1.2.4.0/24', '1.2.4.0/25'),
        ]
        for n1, n2 in data:
            net1 = ip.IPv4Network(n1)
            net2 = ip.IPv4Network(n2)
            time1, result1 = timefn(n, net1.__ne__, net2)
            enet1 = eip.IPv4Network(n1)
            enet2 = eip.IPv4Network(n2)
            time2, result2 = timefn(n, enet1.__ne__, enet2)
            results = (time1, result1), (time2, result2)
            self.report_4n.report(fn_name(), n, results, (net1, net2))

    def test_ipv4network_lt_(self):
        """Test the IPv4Network.__lt__ method."""
        n = 10**5
        data = [
            ('1.2.4.0/24', '1.2.4.0/24'),
            ('1.2.4.0/24', '1.2.3.0/24'),
            ('1.2.4.0/24', '1.2.5.0/24'),
            ('1.2.4.0/24', '1.2.4.0/23'),
            ('1.2.4.0/24', '1.2.4.0/25'),
        ]
        for n1, n2 in data:
            net1 = ip.IPv4Network(n1)
            net2 = ip.IPv4Network(n2)
            time1, result1 = timefn(n, net1.__lt__, net2)
            enet1 = eip.IPv4Network(n1)
            enet2 = eip.IPv4Network(n2)
            time2, result2 = timefn(n, enet1.__lt__, enet2)
            results = (time1, result1), (time2, result2)
            self.report_4n.report(fn_name(), n, results, (net1, net2))

    def test_ipv4network_le_(self):
        """Test the IPv4Network.__le__ method."""
        n = 10**5
        data = [
            ('1.2.4.0/24', '1.2.4.0/24'),
            ('1.2.4.0/24', '1.2.3.0/24'),
            ('1.2.4.0/24', '1.2.5.0/24'),
            ('1.2.4.0/24', '1.2.4.0/23'),
            ('1.2.4.0/24', '1.2.4.0/25'),
        ]
        for n1, n2 in data:
            net1 = ip.IPv4Network(n1)
            net2 = ip.IPv4Network(n2)
            time1, result1 = timefn(n, net1.__le__, net2)
            enet1 = eip.IPv4Network(n1)
            enet2 = eip.IPv4Network(n2)
            time2, result2 = timefn(n, enet1.__le__, enet2)
            results = (time1, result1), (time2, result2)
            self.report_4n.report(fn_name(), n, results, (net1, net2))

    def test_ipv4network_gt_(self):
        """Test the IPv4Network.__gt__ method."""
        n = 10**5
        data = [
            ('1.2.4.0/24', '1.2.4.0/24'),
            ('1.2.4.0/24', '1.2.3.0/24'),
            ('1.2.4.0/24', '1.2.5.0/24'),
            ('1.2.4.0/24', '1.2.4.0/23'),
            ('1.2.4.0/24', '1.2.4.0/25'),
        ]
        for n1, n2 in data:
            net1 = ip.IPv4Network(n1)
            net2 = ip.IPv4Network(n2)
            time1, result1 = timefn(n, net1.__gt__, net2)
            enet1 = eip.IPv4Network(n1)
            enet2 = eip.IPv4Network(n2)
            time2, result2 = timefn(n, enet1.__gt__, enet2)
            results = (time1, result1), (time2, result2)
            self.report_4n.report(fn_name(), n, results, (net1, net2))

    def test_ipv4network_ge_(self):
        """Test the IPv4Network.__ge__ method."""
        n = 10**5
        data = [
            ('1.2.4.0/24', '1.2.4.0/24'),
            ('1.2.4.0/24', '1.2.3.0/24'),
            ('1.2.4.0/24', '1.2.5.0/24'),
            ('1.2.4.0/24', '1.2.4.0/23'),
            ('1.2.4.0/24', '1.2.4.0/25'),
        ]
        for n1, n2 in data:
            net1 = ip.IPv4Network(n1)
            net2 = ip.IPv4Network(n2)
            time1, result1 = timefn(n, net1.__ge__, net2)
            enet1 = eip.IPv4Network(n1)
            enet2 = eip.IPv4Network(n2)
            time2, result2 = timefn(n, enet1.__ge__, enet2)
            results = (time1, result1), (time2, result2)
            self.report_4n.report(fn_name(), n, results, (net1, net2))

    def test_ipv4network_compare_networks(self):
        """Test the IPv4Network.compare_networks method."""
        n = 10**5
        data = [
            ('1.2.4.0/24', '1.2.4.0/24'),
            ('1.2.4.0/24', '1.2.3.0/24'),
            ('1.2.4.0/24', '1.2.5.0/24'),
            ('1.2.4.0/24', '1.2.4.0/23'),
            ('1.2.4.0/24', '1.2.4.0/25'),
        ]
        for n1, n2 in data:
            net1 = ip.IPv4Network(n1)
            net2 = ip.IPv4Network(n2)
            time1, result1 = timefn(n, net1.compare_networks, net2)
            enet1 = eip.IPv4Network(n1)
            enet2 = eip.IPv4Network(n2)
            time2, result2 = timefn(n, enet1.compare_networks, enet2)
            results = (time1, result1), (time2, result2)
            self.report_4n.report(fn_name(), n, results, (net1, net2))

    def test_ipv4network_hash(self):
        """Test the IPv4Network.__hash__ method."""
        n = 10**6
        net = ip.IPv4Network('1.2.3.0/24')
        time1, result1 = timefn(n, net.__hash__)
        enet = eip.IPv4Network('1.2.3.0/24')
        time2, result2 = timefn(n, enet.__hash__)
        # results will differ, so don't compare them
        results = (time1, None), (time2, None)
        self.report_4n.report(fn_name(), n, results, net)

    def test_ipv4network_str(self):
        """Test the IPv4Network.__str__ method."""
        n = 10**5
        net = ip.IPv4Network('1.2.3.0/24')
        time1, result1 = timefn(n, net.__str__)
        enet = eip.IPv4Network('1.2.3.0/24')
        time2, result2 = timefn(n, enet.__str__)
        results = (time1, result1), (time2, result2)
        self.report_4n.report(fn_name(), n, results, net)

    def test_ipv4network_repr(self):
        """Test the IPv4Network.__repr__ method."""
        n = 10**5
        net = ip.IPv4Network('1.2.3.0/24')
        time1, result1 = timefn(n, net.__repr__)
        enet = eip.IPv4Network('1.2.3.0/24')
        time2, result2 = timefn(n, enet.__repr__)
        results = (time1, result1), (time2, result2)
        self.report_4n.report(fn_name(), n, results, net)

    def test_ipv4network_compressed(self):
        """Test the IPv4Network.compressed method."""
        n = 10**5
        def fn(a):
            return a.compressed
        net = ip.IPv4Network('1.2.3.0/24')
        time1, result1 = timefn(n, fn, net)
        enet = eip.IPv4Network('1.2.3.0/24')
        time2, result2 = timefn(n, fn, enet)
        results = (time1, result1), (time2, result2)
        self.report_4n.report(fn_name(), n, results, net)

    def test_ipv4network_exploded(self):
        """Test the IPv4Network.exploded method."""
        n = 10**5
        net = ip.IPv4Network('1.2.3.0/24')
        time1, result1 = timefn(n, lambda: net.exploded)
        enet = eip.IPv4Network('1.2.3.0/24')
        time2, result2 = timefn(n, lambda: enet.exploded)
        results = (time1, result1), (time2, result2)
        self.report_4n.report(fn_name(), n, results, net)

    def test_ipv4network_reduce(self):
        """Test the IPv4Network.__reduce__ method."""
        n = 10**5
        addr = ip.IPv4Network('1.2.3.4')
        time1, result1 = timefn(n, addr.__reduce__)
        eaddr = eip.IPv4Network('1.2.3.4')
        time2, result2 = timefn(n, eaddr.__reduce__)
        # results will differ, so don't compare them
        results = (time1, None), (time2, None)
        self.report_4n.report(fn_name(), n, results, addr)

    def test_ipv4network_reverse_pointer(self):
        """Test the IPv4Network.reverse_pointer method."""
        n = 10**5
        addr = ip.IPv4Network('1.2.3.4')
        time1, result1 = timefn(n, lambda: addr.reverse_pointer)
        eaddr = eip.IPv4Network('1.2.3.4')
        time2, result2 = timefn(n, lambda: eaddr.reverse_pointer)
        results = (time1, result1), (time2, result2)
        self.report_4n.report(fn_name(), n, results, addr)

    def test_ipv4network_max_prefixlen(self):
        """Test the IPv4Network.max_prefixlen method."""
        n = 10**6
        net = ip.IPv4Network('1.2.3.0/24')
        time1, result1 = timefn(n, lambda: net.max_prefixlen)
        enet = eip.IPv4Network('1.2.3.0/24')
        time2, result2 = timefn(n, lambda: enet.max_prefixlen)
        results = (time1, result1), (time2, result2)
        self.report_4n.report(fn_name(), n, results, net)

    def test_ipv4network_num_addresses(self):
        """Test the IPv4Network.num_addresses method."""
        n = 10**6
        net = ip.IPv4Network('1.2.3.0/24')
        time1, result1 = timefn(n, lambda: net.num_addresses)
        enet = eip.IPv4Network('1.2.3.0/24')
        time2, result2 = timefn(n, lambda: enet.num_addresses)
        results = (time1, result1), (time2, result2)
        self.report_4n.report(fn_name(), n, results, net)

    def test_ipv4network_network_address(self):
        """Test the IPv4Network.network_address method."""
        for n in (10**0, 10**6):
            net = ip.IPv4Network('1.2.3.0/24')
            time1, result1 = timefn(n, lambda: net.network_address)
            enet = eip.IPv4Network('1.2.3.0/24')
            time2, result2 = timefn(n, lambda: enet.network_address)
            results = (time1, result1), (time2, result2)
            self.report_4n.report(fn_name(), n, results, net)

    def test_ipv4network_broadcast_address(self):
        """Test the IPv4Network.broadcast_address method."""
        for n in (10**0, 10**6):
            net = ip.IPv4Network('1.2.3.0/24')
            time1, result1 = timefn(n, lambda: net.broadcast_address)
            enet = eip.IPv4Network('1.2.3.0/24')
            time2, result2 = timefn(n, lambda: enet.broadcast_address)
            results = (time1, result1), (time2, result2)
            self.report_4n.report(fn_name(), n, results, net)

    def test_ipv4network_hostmask(self):
        """Test the IPv4Network.hostmask method."""
        for n in (10**0, 10**6):
            net = ip.IPv4Network('1.2.3.0/24')
            time1, result1 = timefn(n, lambda: net.hostmask)
            enet = eip.IPv4Network('1.2.3.0/24')
            time2, result2 = timefn(n, lambda: enet.hostmask)
            results = (time1, result1), (time2, result2)
            self.report_4n.report(fn_name(), n, results, net)

    def test_ipv4network_netmask(self):
        """Test the IPv4Network.netmask method."""
        for n in (10**0, 10**6):
            net = ip.IPv4Network('1.2.3.0/24')
            time1, result1 = timefn(n, lambda: net.netmask)
            enet = eip.IPv4Network('1.2.3.0/24')
            time2, result2 = timefn(n, lambda: enet.netmask)
            results = (time1, result1), (time2, result2)
            self.report_4n.report(fn_name(), n, results, net)

    def test_ipv4network_init_network_address(self):
        """Test the IPv4Network.network_address method."""
        def f(n, net_class, *args):
            net = net_class(*args)
            for _ in range(n):
                a = net.network_address
            return a
        for n in (1, 10, 51):
            time1, result1 = timefn(1, f, n, ip.IPv4Network, 33)
            time2, result2 = timefn(1, f, n, eip.IPv4Network, 33)
            results = (time1, result1), (time2, result2)
            self.report_4n.report(fn_name(), n, results, n)

    def test_ipv4network_init_broadcast_address(self):
        """Test the IPv4Network.broadcast_address method."""
        def f(n, net_class, *args):
            net = net_class(*args)
            for _ in range(n):
                a = net.broadcast_address
            return a
        for n in (1, 100, 184):
            time1, result1 = timefn(1, f, n, ip.IPv4Network, 33)
            time2, result2 = timefn(1, f, n, eip.IPv4Network, 33)
            results = (time1, result1), (time2, result2)
            self.report_4n.report(fn_name(), n, results, n)

    def test_ipv4network_init_hostmask(self):
        """Test the IPv4Network.hostmask method."""
        def f(n, net_class, *args):
            net = net_class(*args)
            for _ in range(n):
                a = net.hostmask
            return a
        for n in (1, 40, 80):
            time1, result1 = timefn(1, f, n, ip.IPv4Network, 33)
            time2, result2 = timefn(1, f, n, eip.IPv4Network, 33)
            results = (time1, result1), (time2, result2)
            self.report_4n.report(fn_name(), n, results, n)

    def test_ipv4network_init_netmask(self):
        """Test the IPv4Network.netmask method."""
        def f(n, net_class, *args):
            net = net_class(*args)
            for _ in range(n):
                a = net.netmask
            return a
        for n in (1, 30, 54):
            time1, result1 = timefn(1, f, n, ip.IPv4Network, 33)
            time2, result2 = timefn(1, f, n, eip.IPv4Network, 33)
            results = (time1, result1), (time2, result2)
            self.report_4n.report(fn_name(), n, results, n)

    def test_ipv4network_with_prefixlen(self):
        """Test the IPv4Network.with_prefixlen method."""
        n = 10**5
        net = ip.IPv4Network('1.2.3.0/24')
        time1, result1 = timefn(n, lambda: net.with_prefixlen)
        enet = eip.IPv4Network('1.2.3.0/24')
        time2, result2 = timefn(n, lambda: enet.with_prefixlen)
        results = (time1, result1), (time2, result2)
        self.report_4n.report(fn_name(), n, results, net)

    def test_ipv4network_with_netmask(self):
        """Test the IPv4Network.with_netmask method."""
        n = 10**5
        net = ip.IPv4Network('1.2.3.0/24')
        time1, result1 = timefn(n, lambda: net.with_netmask)
        enet = eip.IPv4Network('1.2.3.0/24')
        time2, result2 = timefn(n, lambda: enet.with_netmask)
        results = (time1, result1), (time2, result2)
        self.report_4n.report(fn_name(), n, results, net)

    def test_ipv4network_with_hostmask(self):
        """Test the IPv4Network.with_hostmask method."""
        n = 10**5
        net = ip.IPv4Network('1.2.3.0/24')
        time1, result1 = timefn(n, lambda: net.with_hostmask)
        enet = eip.IPv4Network('1.2.3.0/24')
        time2, result2 = timefn(n, lambda: enet.with_hostmask)
        results = (time1, result1), (time2, result2)
        self.report_4n.report(fn_name(), n, results, net)

    def test_ipv4network_getitem(self):
        """Test the IPv4Network.__getitem__ method."""
        n = 10**5
        net = ip.IPv4Network('1.2.3.0/24')
        time1, result1 = timefn(n, net.__getitem__, 11)
        enet = eip.IPv4Network('1.2.3.0/24')
        time2, result2 = timefn(n, enet.__getitem__, 11)
        results = (time1, result1), (time2, result2)
        self.report_4n.report(fn_name(), n, results, net)

    def test_ipv4network_iter(self):
        """Test the IPv4Network.__iter__ method."""
        n = 10**3
        net = ip.IPv4Network('1.2.0.0/24')
        time1, result1 = timelist(n, net.__iter__)
        enet = eip.IPv4Network('1.2.0.0/24')
        time2, result2 = timelist(n, enet.__iter__)
        results = (time1, result1), (time2, result2)
        self.report_4n.report(fn_name(), n, results, net)

    def test_ipv4network_hosts(self):
        """Test the IPv4Network.hosts method."""
        n = 10**3
        net = ip.IPv4Network('1.2.3.0/24')
        time1, result1 = timelist(n, net.hosts)
        enet = eip.IPv4Network('1.2.3.0/24')
        time2, result2 = timelist(n, enet.hosts)
        results = (time1, result1), (time2, result2)
        self.report_4n.report(fn_name(), n, results, net)

    def test_ipv4network_subnets(self):
        """Test the IPv4Network.subnets method."""
        n = 10**5
        net = ip.IPv4Network('1.2.3.0/24')
        time1, result1 = timelist(n, net.subnets)
        enet = eip.IPv4Network('1.2.3.0/24')
        time2, result2 = timelist(n, enet.subnets)
        results = (time1, result1), (time2, result2)
        self.report_4n.report(fn_name(), n, results, net)

    def test_ipv4network_supernet(self):
        """Test the IPv4Network.supernet method."""
        n = 10**5
        net = ip.IPv4Network('1.2.3.0/24')
        time1, result1 = timefn(n, net.supernet)
        enet = eip.IPv4Network('1.2.3.0/24')
        time2, result2 = timefn(n, enet.supernet)
        results = (time1, result1), (time2, result2)
        self.report_4n.report(fn_name(), n, results, net)

    def test_ipv4network_contains(self):
        """Test the IPv4Network.__contains__ method."""
        n = 10**6
        data = [
            ('1.2.3.0/24', '1.2.3.4'),
            ('1.2.3.4/30', '1.2.3.0'),
            ('3.2.3.0/24', '1.2.3.4'),
        ]
        for n1, a1 in data:
            net = ip.IPv4Network(n1)
            addr = ip.IPv4Address(a1)
            time1, result1 = timefn(n, net.__contains__, addr)
            enet1 = eip.IPv4Network(n1)
            eaddr = eip.IPv4Address(a1)
            time2, result2 = timefn(n, enet1.__contains__, eaddr)
            results = (time1, result1), (time2, result2)
            self.report_4n.report(fn_name(), n, results, '%s %s' % (net, addr))

    def test_ipv4network_overlaps(self):
        """Test the IPv4Network.overlaps method."""
        n = 10**5
        data = [
            ('1.2.3.0/24', '1.2.3.4/30'),
            ('1.2.3.4/30', '1.2.3.0/24'),
            ('3.2.3.0/24', '1.2.3.4/30'),
        ]
        for n1, n2 in data:
            net1 = ip.IPv4Network(n1)
            net2 = ip.IPv4Network(n2)
            time1, result1 = timefn(n, net1.overlaps, net2)
            enet1 = eip.IPv4Network(n1)
            enet2 = eip.IPv4Network(n2)
            time2, result2 = timefn(n, enet1.overlaps, enet2)
            results = (time1, result1), (time2, result2)
            self.report_4n.report(fn_name(), n, results, '%s %s' % (net1, net2))

    def test_ipv4network_address_exclude(self):
        """Test the IPv4Network.address_exclude method."""
        n = 10**3
        net1 = ip.IPv4Network('1.2.3.0/24')
        net2 = ip.IPv4Network('1.2.3.4/30')
        time1, result1 = timelist(n, net1.address_exclude, net2)
        enet1 = eip.IPv4Network('1.2.3.0/24')
        enet2 = eip.IPv4Network('1.2.3.4/30')
        time2, result2 = timelist(n, enet1.address_exclude, enet2)
        # results will differ, so don't compare them
        results = (time1, None), (time2, None)
        self.report_4n.report(fn_name(), n, results, '%s %s' % (net1, net2))

    def test_ipv4network_subnet_of(self):
        """Test the IPv4Network.subnet_of method."""
        n = 10**5
        data = [
            ('10.0.0.0/8', '10.0.0.0/8'),
            ('10.0.0.0/8', '10.1.0.0/16'),
            ('10.1.0.0/16', '10.0.0.0/8'),
        ]
        for args in data:
            net1 = ip.IPv4Network(args[0])
            net2 = ip.IPv4Network(args[1])
            time1, result1 = timefn(n, net1.subnet_of, net2)
            enet1 = eip.IPv4Network(args[0])
            enet2 = eip.IPv4Network(args[1])
            time2, result2 = timefn(n, enet1.subnet_of, enet2)
            results = (time1, result1), (time2, result2)
            self.report_4n.report(fn_name(), n, results, args)

    def test_ipv4network_supernet_of(self):
        """Test the IPv4Network.supernet_of method."""
        n = 10**5
        data = [
            ('10.0.0.0/8', '10.0.0.0/8'),
            ('10.0.0.0/8', '10.1.0.0/16'),
            ('10.1.0.0/16', '10.0.0.0/8'),
        ]
        for args in data:
            net1 = ip.IPv4Network(args[0])
            net2 = ip.IPv4Network(args[1])
            time1, result1 = timefn(n, net1.supernet_of, net2)
            enet1 = eip.IPv4Network(args[0])
            enet2 = eip.IPv4Network(args[1])
            time2, result2 = timefn(n, enet1.supernet_of, enet2)
            results = (time1, result1), (time2, result2)
            self.report_4n.report(fn_name(), n, results, args)

    def test_ipv4network_is_reserved(self):
        """Test the IPv4Network.is_reserved method."""
        n = 10**5
        args = ['1.2.3.4/30', '240.0.0.0/8']
        for arg in args:
            net = ip.IPv4Network(arg)
            time1, result1 = timefn(n, lambda: net.is_multicast)
            enet = eip.IPv4Network(arg)
            time2, result2 = timefn(n, lambda: enet.is_multicast)
            results = (time1, result1), (time2, result2)
            self.report_4n.report(fn_name(), n, results, arg)

    def test_ipv4network_is_private(self):
        """Test the IPv4Network.is_private method."""
        args = ['1.2.3.0/24', '10.0.0.0/24', '172.16.0.0/24', '192.168.0.0/24']
        for n in 1, 10**5:
            for arg in args:
                net = ip.IPv4Network(arg)
                time1, result1 = timefn(n, lambda: net.is_private)
                enet = eip.IPv4Network(arg)
                time2, result2 = timefn(n, lambda: enet.is_private)
                results = (time1, result1), (time2, result2)
                self.report_4n.report(fn_name(), n, results, arg)

    def test_ipv4network_is_global(self):
        """Test the IPv4Network.is_global method."""
        args = ['1.2.3.0/24', '10.0.0.0/24', '172.16.0.0/24', '192.168.0.0/24']
        for n in 1, 10**5:
            for arg in args:
                net = ip.IPv4Network(arg)
                time1, result1 = timefn(n, lambda: net.is_global)
                enet = eip.IPv4Network(arg)
                time2, result2 = timefn(n, lambda: enet.is_global)
                results = (time1, result1), (time2, result2)
                self.report_4n.report(fn_name(), n, results, arg)

    def test_ipv4network_is_multicast(self):
        """Test the IPv4Network.is_multicast method."""
        n = 10**5
        args = ['1.2.3.0/24', '224.0.0.0/24']
        for arg in args:
            net = ip.IPv4Network(arg)
            time1, result1 = timefn(n, lambda: net.is_multicast)
            enet = eip.IPv4Network(arg)
            time2, result2 = timefn(n, lambda: enet.is_multicast)
            results = (time1, result1), (time2, result2)
            self.report_4n.report(fn_name(), n, results, arg)

    def test_ipv4network_is_unspecified(self):
        """Test the IPv4Network.is_unspecified method."""
        n = 10**5
        args = ['1.2.3.0/24', '0.0.0.0/24']
        for arg in args:
            net = ip.IPv4Network(arg)
            time1, result1 = timefn(n, lambda: net.is_unspecified)
            enet = eip.IPv4Network(arg)
            time2, result2 = timefn(n, lambda: enet.is_unspecified)
            results = (time1, result1), (time2, result2)
            self.report_4n.report(fn_name(), n, results, arg)

    def test_ipv4network_is_loopback(self):
        """Test the IPv4Network.is_loopback method."""
        n = 10**5
        args = ['1.2.3.0/24', '127.0.0.1']
        for arg in args:
            net = ip.IPv4Network(arg)
            time1, result1 = timefn(n, lambda: net.is_loopback)
            enet = eip.IPv4Network(arg)
            time2, result2 = timefn(n, lambda: enet.is_loopback)
            results = (time1, result1), (time2, result2)
            self.report_4n.report(fn_name(), n, results, arg)

    def test_ipv4network_is_link_local(self):
        """Test the IPv4Network.is_link_local method."""
        n = 10**5
        args = ['1.2.3.0/24', '169.254.0.0/24']
        for arg in args:
            net = ip.IPv4Network(arg)
            time1, result1 = timefn(n, lambda: net.is_link_local)
            enet = eip.IPv4Network(arg)
            time2, result2 = timefn(n, lambda: enet.is_link_local)
            results = (time1, result1), (time2, result2)
            self.report_4n.report(fn_name(), n, results, arg)

    # =========================================================================
    # IPv6Network
    # =========================================================================

    def test_ipv6network_init(self):
        """Test the IPv6Network.__init__ method."""
        n = 10**5
        data = [
            '1:2:3:4::/120',
            '1:2:3:4::',
            16384,
            (int(64).to_bytes(16, 'big'), 124),
        ]
        fns = ip.IPv6Network, eip.IPv6Network
        for args in data:
            generic_test(self.report_6n, fn_name(), n, fns, args)

    def test_ipv6network_eq_(self):
        """Test the IPv6Network.__eq__ method."""
        n = 10**5
        data = [
            ('1:2:3:4::/80', '1:2:3:4::/80'),
            ('1:2:3:4::/80', '1:2:3:3::/80'),
            ('1:2:3:4::/80', '1:2:3:5::/80'),
            ('1:2:3:4::/80', '1:2:3:4::/64'),
            ('1:2:3:4::/80', '1:2:3:4::/96'),
        ]
        for a1, a2 in data:
            addr1 = ip.IPv6Network(a1)
            addr2 = ip.IPv6Network(a2)
            time1, result1 = timefn(n, addr1.__eq__, addr2)
            eaddr1 = eip.IPv6Network(a1)
            eaddr2 = eip.IPv6Network(a2)
            time2, result2 = timefn(n, eaddr1.__eq__, eaddr2)
            results = (time1, result1), (time2, result2)
            self.report_6n.report(fn_name(), n, results, (addr1, addr2))

    def test_ipv6network_ne_(self):
        """Test the IPv6Network.__ne__ method."""
        n = 10**5
        data = [
            ('1:2:3:4::/80', '1:2:3:4::/80'),
            ('1:2:3:4::/80', '1:2:3:3::/80'),
            ('1:2:3:4::/80', '1:2:3:5::/80'),
            ('1:2:3:4::/80', '1:2:3:4::/64'),
            ('1:2:3:4::/80', '1:2:3:4::/96'),
        ]
        for a1, a2 in data:
            addr1 = ip.IPv6Network(a1)
            addr2 = ip.IPv6Network(a2)
            time1, result1 = timefn(n, addr1.__ne__, addr2)
            eaddr1 = eip.IPv6Network(a1)
            eaddr2 = eip.IPv6Network(a2)
            time2, result2 = timefn(n, eaddr1.__ne__, eaddr2)
            results = (time1, result1), (time2, result2)
            self.report_6n.report(fn_name(), n, results, (addr1, addr2))

    def test_ipv6network_lt_(self):
        """Test the IPv6Network.__lt__ method."""
        n = 10**5
        data = [
            ('1:2:3:4::/80', '1:2:3:4::/80'),
            ('1:2:3:4::/80', '1:2:3:3::/80'),
            ('1:2:3:4::/80', '1:2:3:5::/80'),
            ('1:2:3:4::/80', '1:2:3:4::/64'),
            ('1:2:3:4::/80', '1:2:3:4::/96'),
        ]
        for a1, a2 in data:
            addr1 = ip.IPv6Network(a1)
            addr2 = ip.IPv6Network(a2)
            time1, result1 = timefn(n, addr1.__lt__, addr2)
            eaddr1 = eip.IPv6Network(a1)
            eaddr2 = eip.IPv6Network(a2)
            time2, result2 = timefn(n, eaddr1.__lt__, eaddr2)
            results = (time1, result1), (time2, result2)
            self.report_6n.report(fn_name(), n, results, (addr1, addr2))

    def test_ipv6network_le_(self):
        """Test the IPv6Network.__le__ method."""
        n = 10**5
        data = [
            ('1:2:3:4::/80', '1:2:3:4::/80'),
            ('1:2:3:4::/80', '1:2:3:3::/80'),
            ('1:2:3:4::/80', '1:2:3:5::/80'),
            ('1:2:3:4::/80', '1:2:3:4::/64'),
            ('1:2:3:4::/80', '1:2:3:4::/96'),
        ]
        for a1, a2 in data:
            addr1 = ip.IPv6Network(a1)
            addr2 = ip.IPv6Network(a2)
            time1, result1 = timefn(n, addr1.__le__, addr2)
            eaddr1 = eip.IPv6Network(a1)
            eaddr2 = eip.IPv6Network(a2)
            time2, result2 = timefn(n, eaddr1.__le__, eaddr2)
            results = (time1, result1), (time2, result2)
            self.report_6n.report(fn_name(), n, results, (addr1, addr2))

    def test_ipv6network_gt_(self):
        """Test the IPv6Network.__gt__ method."""
        n = 10**5
        data = [
            ('1:2:3:4::/80', '1:2:3:4::/80'),
            ('1:2:3:4::/80', '1:2:3:3::/80'),
            ('1:2:3:4::/80', '1:2:3:5::/80'),
            ('1:2:3:4::/80', '1:2:3:4::/64'),
            ('1:2:3:4::/80', '1:2:3:4::/96'),
        ]
        for a1, a2 in data:
            addr1 = ip.IPv6Network(a1)
            addr2 = ip.IPv6Network(a2)
            time1, result1 = timefn(n, addr1.__gt__, addr2)
            eaddr1 = eip.IPv6Network(a1)
            eaddr2 = eip.IPv6Network(a2)
            time2, result2 = timefn(n, eaddr1.__gt__, eaddr2)
            results = (time1, result1), (time2, result2)
            self.report_6n.report(fn_name(), n, results, (addr1, addr2))

    def test_ipv6network_ge_(self):
        """Test the IPv6Network.__ge__ method."""
        n = 10**5
        data = [
            ('1:2:3:4::/80', '1:2:3:4::/80'),
            ('1:2:3:4::/80', '1:2:3:3::/80'),
            ('1:2:3:4::/80', '1:2:3:5::/80'),
            ('1:2:3:4::/80', '1:2:3:4::/64'),
            ('1:2:3:4::/80', '1:2:3:4::/96'),
        ]
        for a1, a2 in data:
            addr1 = ip.IPv6Network(a1)
            addr2 = ip.IPv6Network(a2)
            time1, result1 = timefn(n, addr1.__ge__, addr2)
            eaddr1 = eip.IPv6Network(a1)
            eaddr2 = eip.IPv6Network(a2)
            time2, result2 = timefn(n, eaddr1.__ge__, eaddr2)
            results = (time1, result1), (time2, result2)
            self.report_6n.report(fn_name(), n, results, (addr1, addr2))

    def test_ipv6network_compare_networks(self):
        """Test the IPv6Network.compare_networks method."""
        n = 10**5
        data = [
            ('1:2:3:4::/80', '1:2:3:4::/80'),
            ('1:2:3:4::/80', '1:2:3:3::/80'),
            ('1:2:3:4::/80', '1:2:3:5::/80'),
            ('1:2:3:4::/80', '1:2:3:4::/64'),
            ('1:2:3:4::/80', '1:2:3:4::/96'),
        ]
        for a1, a2 in data:
            addr1 = ip.IPv6Network(a1)
            addr2 = ip.IPv6Network(a2)
            time1, result1 = timefn(n, addr1.compare_networks, addr2)
            eaddr1 = eip.IPv6Network(a1)
            eaddr2 = eip.IPv6Network(a2)
            time2, result2 = timefn(n, eaddr1.compare_networks, eaddr2)
            results = (time1, result1), (time2, result2)
            self.report_6n.report(fn_name(), n, results, (addr1, addr2))

    def test_ipv6network_hash(self):
        """Test the IPv6Network.__hash__ method."""
        n = 10**6
        net = ip.IPv6Network('1:2:3:4::/120')
        time1, result1 = timefn(n, net.__hash__)
        enet = eip.IPv6Network('1:2:3:4::/120')
        time2, result2 = timefn(n, enet.__hash__)
        # results will differ, so don't compare them
        results = (time1, None), (time2, None)
        self.report_6n.report(fn_name(), n, results, net)

    def test_ipv6network_str(self):
        """Test the IPv6Network.__str__ method."""
        n = 10**5
        net = ip.IPv6Network('1:2:3:4::/120')
        time1, result1 = timefn(n, net.__str__)
        enet = eip.IPv6Network('1:2:3:4::/120')
        time2, result2 = timefn(n, enet.__str__)
        results = (time1, result1), (time2, result2)
        self.report_6n.report(fn_name(), n, results, net)

    def test_ipv6network_repr(self):
        """Test the IPv6Network.__repr__ method."""
        n = 10**5
        net = ip.IPv6Network('1:2:3:4::/120')
        time1, result1 = timefn(n, net.__repr__)
        enet = eip.IPv6Network('1:2:3:4::/120')
        time2, result2 = timefn(n, enet.__repr__)
        results = (time1, result1), (time2, result2)
        self.report_6n.report(fn_name(), n, results, net)

    def test_ipv6network_compressed(self):
        """Test the IPv6Network.compressed method."""
        n = 10**5
        def fn(a):
            return a.compressed
        net = ip.IPv6Network('1:2:3:4::/120')
        time1, result1 = timefn(n, fn, net)
        enet = eip.IPv6Network('1:2:3:4::/120')
        time2, result2 = timefn(n, fn, enet)
        results = (time1, result1), (time2, result2)
        self.report_6n.report(fn_name(), n, results, net)

    def test_ipv6network_exploded(self):
        """Test the IPv6Network.exploded method."""
        n = 10**4
        nets = ['1:2:3:4:5:6::/120',
                '::/96',
                '::5:6:7:8/125',
                '1:2:3:4::/96',
                '1:2::7:8/125']
        for netstr in nets:
            net = ip.IPv6Network(netstr)
            time1, result1 = timefn(n, lambda: net.exploded)
            enet = eip.IPv6Network(netstr)
            time2, result2 = timefn(n, lambda: enet.exploded)
            results = (time1, result1), (time2, result2)
            self.report_6n.report(fn_name(), n, results, netstr)

    def test_ipv6network_reduce(self):
        """Test the IPv6Network.__reduce__ method."""
        n = 10**5
        addr = ip.IPv6Network('2001::/48')
        time1, result1 = timefn(n, addr.__reduce__)
        eaddr = eip.IPv6Network('2001::/48')
        time2, result2 = timefn(n, eaddr.__reduce__)
        # results will differ, so don't compare them
        results = (time1, None), (time2, None)
        self.report_6n.report(fn_name(), n, results, addr)

    def test_ipv6network_reverse_pointer(self):
        """Test the IPv6Network.reverse_pointer method."""
        n = 10**4
        addr = ip.IPv6Network('1:2:3:4:5:6::')
        time1, result1 = timefn(n, lambda: addr.reverse_pointer)
        eaddr = eip.IPv6Network('1:2:3:4:5:6::')
        time2, result2 = timefn(n, lambda: eaddr.reverse_pointer)
        results = (time1, result1), (time2, result2)
        self.report_6n.report(fn_name(), n, results, addr)

    def test_ipv6network_max_prefixlen(self):
        """Test the IPv6Network.max_prefixlen method."""
        n = 10**6
        net = ip.IPv6Network('1:2:3:4::/120')
        time1, result1 = timefn(n, lambda: net.max_prefixlen)
        enet = eip.IPv6Network('1:2:3:4::/120')
        time2, result2 = timefn(n, lambda: enet.max_prefixlen)
        results = (time1, result1), (time2, result2)
        self.report_6n.report(fn_name(), n, results, net)

    def test_ipv6network_num_addresses(self):
        """Test the IPv6Network.num_addresses method."""
        n = 10**6
        net = ip.IPv6Network('1:2:3:4::/120')
        time1, result1 = timefn(n, lambda: net.num_addresses)
        enet = eip.IPv6Network('1:2:3:4::/120')
        time2, result2 = timefn(n, lambda: enet.num_addresses)
        results = (time1, result1), (time2, result2)
        self.report_6n.report(fn_name(), n, results, net)

    def test_ipv6network_network_address(self):
        """Test the IPv6Network.network_address method."""
        for n in (10**0, 10**6):
            net = ip.IPv6Network('1:2:3:4::/120')
            time1, result1 = timefn(n, lambda: net.network_address)
            enet = eip.IPv6Network('1:2:3:4::/120')
            time2, result2 = timefn(n, lambda: enet.network_address)
            results = (time1, result1), (time2, result2)
            self.report_6n.report(fn_name(), n, results, net)

    def test_ipv6network_broadcast_address(self):
        """Test the IPv6Network.broadcast_address method."""
        for n in (10**0, 10**6):
            net = ip.IPv6Network('1:2:3:4::/120')
            time1, result1 = timefn(n, lambda: net.broadcast_address)
            enet = eip.IPv6Network('1:2:3:4::/120')
            time2, result2 = timefn(n, lambda: enet.broadcast_address)
            results = (time1, result1), (time2, result2)
            self.report_6n.report(fn_name(), n, results, net)

    def test_ipv6network_hostmask(self):
        """Test the IPv6Network.hostmask method."""
        for n in (10**0, 10**6):
            net = ip.IPv6Network('1:2:3:4::/120')
            time1, result1 = timefn(n, lambda: net.hostmask)
            enet = eip.IPv6Network('1:2:3:4::/120')
            time2, result2 = timefn(n, lambda: enet.hostmask)
            results = (time1, result1), (time2, result2)
            self.report_6n.report(fn_name(), n, results, net)

    def test_ipv6network_netmask(self):
        """Test the IPv6Network.netmask method."""
        for n in (10**0, 10**6):
            net = ip.IPv6Network('1:2:3:4::/120')
            time1, result1 = timefn(n, lambda: net.netmask)
            enet = eip.IPv6Network('1:2:3:4::/120')
            time2, result2 = timefn(n, lambda: enet.netmask)
            results = (time1, result1), (time2, result2)
            self.report_6n.report(fn_name(), n, results, net)

    def test_ipv6network_init_network_address(self):
        """Test the IPv6Network.network_address method."""
        def f(n, net_class, *args):
            net = net_class(*args)
            for _ in range(n):
                a = net.network_address
            return a
        for n in (1, 10, 50):
            time1, result1 = timefn(1, f, n, ip.IPv6Network, 33)
            time2, result2 = timefn(1, f, n, eip.IPv6Network, 33)
            results = (time1, result1), (time2, result2)
            self.report_6n.report(fn_name(), n, results, n)

    def test_ipv6network_init_broadcast_address(self):
        """Test the IPv6Network.broadcast_address method."""
        def f(n, net_class, *args):
            net = net_class(*args)
            for _ in range(n):
                a = net.broadcast_address
            return a
        for n in (1, 100, 182):
            time1, result1 = timefn(1, f, n, ip.IPv6Network, 33)
            time2, result2 = timefn(1, f, n, eip.IPv6Network, 33)
            results = (time1, result1), (time2, result2)
            self.report_6n.report(fn_name(), n, results, n)

    def test_ipv6network_init_hostmask(self):
        """Test the IPv6Network.hostmask method."""
        def f(n, net_class, *args):
            net = net_class(*args)
            for _ in range(n):
                a = net.hostmask
            return a
        for n in (1, 40, 80):
            time1, result1 = timefn(1, f, n, ip.IPv6Network, 33)
            time2, result2 = timefn(1, f, n, eip.IPv6Network, 33)
            results = (time1, result1), (time2, result2)
            self.report_6n.report(fn_name(), n, results, n)

    def test_ipv6network_init_netmask(self):
        """Test the IPv6Network.netmask method."""
        def f(n, net_class, *args):
            net = net_class(*args)
            for _ in range(n):
                a = net.netmask
            return a
        for n in (1, 30, 53):
            time1, result1 = timefn(1, f, n, ip.IPv6Network, 33)
            time2, result2 = timefn(1, f, n, eip.IPv6Network, 33)
            results = (time1, result1), (time2, result2)
            self.report_6n.report(fn_name(), n, results, n)

    def test_ipv6network_with_prefixlen(self):
        """Test the IPv6Network.with_prefixlen method."""
        n = 10**5
        net = ip.IPv6Network('1:2:3:4::/120')
        time1, result1 = timefn(n, lambda: net.with_prefixlen)
        enet = eip.IPv6Network('1:2:3:4::/120')
        time2, result2 = timefn(n, lambda: enet.with_prefixlen)
        results = (time1, result1), (time2, result2)
        self.report_6n.report(fn_name(), n, results, net)

    def test_ipv6network_with_netmask(self):
        """Test the IPv6Network.with_netmask method."""
        n = 10**4
        net = ip.IPv6Network('1:2:3:4::/120')
        time1, result1 = timefn(n, lambda: net.with_netmask)
        enet = eip.IPv6Network('1:2:3:4::/120')
        time2, result2 = timefn(n, lambda: enet.with_netmask)
        results = (time1, result1), (time2, result2)
        self.report_6n.report(fn_name(), n, results, net)

    def test_ipv6network_with_hostmask(self):
        """Test the IPv6Network.with_hostmask method."""
        n = 10**4
        net = ip.IPv6Network('1:2:3:4::/120')
        time1, result1 = timefn(n, lambda: net.with_hostmask)
        enet = eip.IPv6Network('1:2:3:4::/120')
        time2, result2 = timefn(n, lambda: enet.with_hostmask)
        results = (time1, result1), (time2, result2)
        self.report_6n.report(fn_name(), n, results, net)

    def test_ipv6network_getitem(self):
        """Test the IPv6Network.__getitem__ method."""
        n = 10**5
        net = ip.IPv6Network('1:2:3:4::/120')
        time1, result1 = timefn(n, net.__getitem__, 11)
        enet = eip.IPv6Network('1:2:3:4::/120')
        time2, result2 = timefn(n, enet.__getitem__, 11)
        results = (time1, result1), (time2, result2)
        self.report_6n.report(fn_name(), n, results, net)

    def test_ipv6network_iter(self):
        """Test the IPv6Network.__iter__ method."""
        n = 10**3
        net = ip.IPv6Network('1:2:3:4::/120')
        time1, result1 = timelist(n, net.__iter__)
        enet = eip.IPv6Network('1:2:3:4::/120')
        time2, result2 = timelist(n, enet.__iter__)
        results = (time1, result1), (time2, result2)
        self.report_6n.report(fn_name(), n, results, net)

    def test_ipv6network_hosts(self):
        """Test the IPv6Network.hosts method."""
        n = 10**3
        net = ip.IPv6Network('1:2:3:4::/120')
        time1, result1 = timelist(n, net.hosts)
        enet = eip.IPv6Network('1:2:3:4::/120')
        time2, result2 = timelist(n, enet.hosts)
        results = (time1, result1), (time2, result2)
        self.report_6n.report(fn_name(), n, results, net)

    def test_ipv6network_subnets(self):
        """Test the IPv6Network.subnets method."""
        n = 10**4
        net = ip.IPv6Network('1:2:3:4::/120')
        time1, result1 = timelist(n, net.subnets, 3)
        enet = eip.IPv6Network('1:2:3:4::/120')
        time2, result2 = timelist(n, enet.subnets, 3)
        results = (time1, result1), (time2, result2)
        self.report_6n.report(fn_name(), n, results, (net, 3))

    def test_ipv6network_supernet(self):
        """Test the IPv6Network.supernet method."""
        n = 10**5
        net = ip.IPv6Network('1:2:3:4::/120')
        time1, result1 = timefn(n, net.supernet, 3)
        enet = eip.IPv6Network('1:2:3:4::/120')
        time2, result2 = timefn(n, enet.supernet, 3)
        results = (time1, result1), (time2, result2)
        self.report_6n.report(fn_name(), n, results, (net, 3))

    def test_ipv6network_contains(self):
        """Test the IPv6Network.__contains__ method."""
        n = 10**6
        data = [
            ('1:2:3:4::/120', '1:2:3:4::8'),
            ('1:2:3:4::/120', '1:2:3:0::8'),
            ('3:2:3:4::/120', '1:2:3:4::8'),
        ]
        for n1, a1 in data:
            net = ip.IPv6Network(n1)
            addr = ip.IPv6Address(a1)
            time1, result1 = timefn(n, net.__contains__, addr)
            enet1 = eip.IPv6Network(n1)
            eaddr = eip.IPv6Address(a1)
            time2, result2 = timefn(n, enet1.__contains__, eaddr)
            results = (time1, result1), (time2, result2)
            self.report_6n.report(fn_name(), n, results, '%s %s' % (net, addr))

    def test_ipv6network_overlaps(self):
        """Test the IPv6Network.overlaps method."""
        n = 10**5
        data = [
            ('1:2:3:4::/120', '1:2:3:4::123'),
            ('1:2:3:4::/120', '1:2:3:0::96'),
            ('3:2:3:4::/120', '1:2:3:4::123'),
        ]
        for n1, n2 in data:
            net1 = ip.IPv6Network(n1)
            net2 = ip.IPv6Network(n2)
            time1, result1 = timefn(n, net1.overlaps, net2)
            enet1 = eip.IPv6Network(n1)
            enet2 = eip.IPv6Network(n2)
            time2, result2 = timefn(n, enet1.overlaps, enet2)
            results = (time1, result1), (time2, result2)
            self.report_6n.report(fn_name(), n, results, '%s %s' % (net1, net2))

    def test_ipv6network_address_exclude(self):
        """Test the IPv6Network.address_exclude method."""
        n = 10**3
        net1 = ip.IPv6Network('1:2:3:4::/120')
        net2 = ip.IPv6Network('1:2:3:4::/123')
        time1, result1 = timelist(n, net1.address_exclude, net2)
        enet1 = eip.IPv6Network('1:2:3:4::/120')
        enet2 = eip.IPv6Network('1:2:3:4::/123')
        time2, result2 = timelist(n, enet1.address_exclude, enet2)
        # results will differ, so don't compare them
        results = (time1, None), (time2, None)
        self.report_6n.report(fn_name(), n, results, '%s %s' % (net1, net2))

    def test_ipv6network_subnet_of(self):
        """Test the IPv6Network.subnet_of method."""
        n = 10**5
        data = [
            ('10:0:0:0::/18', '10:0:0:0::/18'),
            ('10:0:0:0::/18', '10:1:0:0::/116'),
            ('10:1:0:0::/116', '10:0:0:0::/18'),
        ]
        for args in data:
            net1 = ip.IPv6Network(args[0])
            net2 = ip.IPv6Network(args[1])
            time1, result1 = timefn(n, net1.subnet_of, net2)
            enet1 = eip.IPv6Network(args[0])
            enet2 = eip.IPv6Network(args[1])
            time2, result2 = timefn(n, enet1.subnet_of, enet2)
            results = (time1, result1), (time2, result2)
            self.report_6n.report(fn_name(), n, results, args)

    def test_ipv6network_supernet_of(self):
        """Test the IPv6Network.supernet_of method."""
        n = 10**5
        data = [
            ('10:0:0:0::/18', '10:0:0:0::/18'),
            ('10:0:0:0::/18', '10:1:0:0::/116'),
            ('10:1:0:0::/116', '10:0:0:0::/18'),
        ]
        for args in data:
            net1 = ip.IPv6Network(args[0])
            net2 = ip.IPv6Network(args[1])
            time1, result1 = timefn(n, net1.supernet_of, net2)
            enet1 = eip.IPv6Network(args[0])
            enet2 = eip.IPv6Network(args[1])
            time2, result2 = timefn(n, enet1.supernet_of, enet2)
            results = (time1, result1), (time2, result2)
            self.report_6n.report(fn_name(), n, results, args)

    def _test_ipv6network_is_reserved(self):
        """Test the IPv6Network.is_reserved method."""
        n = 10**4
        args = [
            '::/8',
            '100::/8',
            '200::/7',
            '400::/6',
            '800::/5',
            '1000::/4',
            '4000::/3',
            '6000::/3',
            '8000::/3',
            'A000::/3',
            'C000::/3',
            'E000::/4',
            'F000::/5',
            'F800::/6',
            'FE00::/9',
            '2001:1234::/32',
        ]
        for arg in args:
            net = ip.IPv6Network(arg)
            time1, result1 = timefn(n, lambda: net.is_multicast)
            enet = eip.IPv6Network(arg)
            time2, result2 = timefn(n, lambda: enet.is_multicast)
            results = (time1, result1), (time2, result2)
            self.report_6n.report(fn_name(), n, results, arg)

    def test_ipv6network_is_private(self):
        """Test the IPv6Network.is_private method."""
        args = (
            '::/128',
            '::1/128',
            '::ffff:0:0/96',
            '100::/64',
            '2001::/23',
            '2001:2::/48',
            '2001:10::/28',
            '2001:db8::/32',
            'fc00::/7',
            'fe80::/10',
            '1001:1234::/32',
        )
        for n in 1, 10**5:
            for arg in args:
                net = ip.IPv6Network(arg)
                time1, result1 = timefn(n, lambda: net.is_private)
                enet = eip.IPv6Network(arg)
                time2, result2 = timefn(n, lambda: enet.is_private)
                results = (time1, result1), (time2, result2)
                self.report_6n.report(fn_name(), n, results, arg)

    def test_ipv6network_is_global(self):
        """Test the IPv6Network.is_global method."""
        args = (
            '::/128',
            '::1/128',
            '::ffff:0:0/96',
            '100::/64',
            '2001::/23',
            '2001:2::/48',
            '2001:10::/28',
            '2001:db8::/32',
            'fc00::/7',
            'fe80::/10',
            '1001:1234::/32',
        )
        for n in 1, 10**5:
            for arg in args:
                net = ip.IPv6Network(arg)
                time1, result1 = timefn(n, lambda: net.is_global)
                enet = eip.IPv6Network(arg)
                time2, result2 = timefn(n, lambda: enet.is_global)
                results = (time1, result1), (time2, result2)
                self.report_6n.report(fn_name(), n, results, arg)

    def test_ipv6network_is_multicast(self):
        """Test the IPv6Network.is_multicast method."""
        n = 10**4
        args = ['1:2:3:4:5:6::/96', 'ff00::/8']
        for arg in args:
            net = ip.IPv6Network(arg)
            time1, result1 = timefn(n, lambda: net.is_multicast)
            enet = eip.IPv6Network(arg)
            time2, result2 = timefn(n, lambda: enet.is_multicast)
            results = (time1, result1), (time2, result2)
            self.report_6n.report(fn_name(), n, results, arg)

    def test_ipv6network_is_unspecified(self):
        """Test the IPv6Network.is_unspecified method."""
        n = 10**6
        args = ['1:2:3:4:5:6::/96', '::/128']
        for arg in args:
            net = ip.IPv6Network(arg)
            time1, result1 = timefn(n, lambda: net.is_unspecified)
            enet = eip.IPv6Network(arg)
            time2, result2 = timefn(n, lambda: enet.is_unspecified)
            results = (time1, result1), (time2, result2)
            self.report_6n.report(fn_name(), n, results, arg)

    def test_ipv6network_is_loopback(self):
        """Test the IPv6Network.is_loopback method."""
        n = 10**6
        args = ['1:2:3:4:5:6::/96', '::1/128']
        for arg in args:
            net = ip.IPv6Network(arg)
            time1, result1 = timefn(n, lambda: net.is_loopback)
            enet = eip.IPv6Network(arg)
            time2, result2 = timefn(n, lambda: enet.is_loopback)
            results = (time1, result1), (time2, result2)
            self.report_6n.report(fn_name(), n, results, arg)

    def test_ipv6network_is_link_local(self):
        """Test the IPv6Network.is_link_local method."""
        n = 10**5
        args = ['1:2:3:4:5:6::/96', 'fe80::/10']
        for arg in args:
            net = ip.IPv6Network(arg)
            time1, result1 = timefn(n, lambda: net.is_link_local)
            enet = eip.IPv6Network(arg)
            time2, result2 = timefn(n, lambda: enet.is_link_local)
            results = (time1, result1), (time2, result2)
            self.report_6n.report(fn_name(), n, results, arg)

    def test_ipv6network_is_site_local(self):
        """Test the IPv6Network.is_site_local method."""
        n = 10**5
        args = ['1:2:3:4:5:6::/96', 'fec0::/10']
        for arg in args:
            net = ip.IPv6Network(arg)
            time1, result1 = timefn(n, lambda: net.is_site_local)
            enet = eip.IPv6Network(arg)
            time2, result2 = timefn(n, lambda: enet.is_site_local)
            results = (time1, result1), (time2, result2)
            self.report_6n.report(fn_name(), n, results, arg)

    # =========================================================================
    # IPv4Interface
    # =========================================================================

    def test_ipv4interface_init(self):
        """Test the IPv4Interface.__init__ method."""
        n = 10**5
        data = [
            '1.2.3.4',
            16384,
            (int(64).to_bytes(4, 'big'), 28),
        ]
        fns = ip.IPv4Interface, eip.IPv4Interface
        for args in data:
            generic_test(self.report_4i, fn_name(), n, fns, args)

    def test_ipv4interface_int(self):
        """Test the IPv4Interface.__int__ method."""
        n = 10**6
        addr = ip.IPv4Interface('1.2.3.4')
        time1, result1 = timefn(n, addr.__int__)
        eaddr = eip.IPv4Interface('1.2.3.4')
        time2, result2 = timefn(n, eaddr.__int__)
        results = (time1, result1), (time2, result2)
        self.report_4i.report(fn_name(), n, results, addr)

    def test_ipv4interface_ip(self):
        """Test the IPv4Interface.ip method."""
        n = 10**5
        a = '1.2.3.4'
        addr = ip.IPv4Interface(a)
        time1, result1 = timefn(n, lambda: addr.ip)
        eaddr = eip.IPv4Interface(a)
        time2, result2 = timefn(n, lambda: eaddr.ip)
        results = (time1, result1), (time2, result2)
        self.report_4i.report(fn_name(), n, results, a)

    def test_ipv4interface_packed(self):
        """Test the IPv4Interface.packed method."""
        n = 10**6
        a = '1.2.3.4'
        addr = ip.IPv4Interface(a)
        time1, result1 = timefn(n, lambda: addr.packed)
        eaddr = eip.IPv4Interface(a)
        time2, result2 = timefn(n, lambda: eaddr.packed)
        results = (time1, result1), (time2, result2)
        self.report_4i.report(fn_name(), n, results, a)

    def test_ipv4interface_eq_(self):
        """Test the IPv4Interface.__eq__ method."""
        n = 10**5
        data = [
            ('1.2.3.4/24', '1.2.3.4/24'),
            ('1.2.3.4/24', '1.2.3.3/24'),
            ('1.2.3.4/24', '1.2.3.5/24'),
            ('1.2.3.4/24', '1.2.3.4/23'),
            ('1.2.3.4/24', '1.2.3.4/25'),
        ]
        for a1, a2 in data:
            addr1 = ip.IPv4Interface(a1)
            addr2 = ip.IPv4Interface(a2)
            time1, result1 = timefn(n, addr1.__eq__, addr2)
            eaddr1 = eip.IPv4Interface(a1)
            eaddr2 = eip.IPv4Interface(a2)
            time2, result2 = timefn(n, eaddr1.__eq__, eaddr2)
            results = (time1, result1), (time2, result2)
            self.report_4i.report(fn_name(), n, results, (addr1, addr2))

    def test_ipv4interface_ne_(self):
        """Test the IPv4Interface.__ne__ method."""
        n = 10**5
        data = [
            ('1.2.3.4/24', '1.2.3.4/24'),
            ('1.2.3.4/24', '1.2.3.3/24'),
            ('1.2.3.4/24', '1.2.3.5/24'),
            ('1.2.3.4/24', '1.2.3.4/23'),
            ('1.2.3.4/24', '1.2.3.4/25'),
        ]
        for a1, a2 in data:
            addr1 = ip.IPv4Interface(a1)
            addr2 = ip.IPv4Interface(a2)
            time1, result1 = timefn(n, addr1.__ne__, addr2)
            eaddr1 = eip.IPv4Interface(a1)
            eaddr2 = eip.IPv4Interface(a2)
            time2, result2 = timefn(n, eaddr1.__ne__, eaddr2)
            results = (time1, result1), (time2, result2)
            self.report_4i.report(fn_name(), n, results, (addr1, addr2))

    def test_ipv4interface_lt_(self):
        """Test the IPv4Interface.__lt__ method."""
        n = 10**5
        data = [
            ('1.2.3.4/24', '1.2.3.4/24'),
            ('1.2.3.4/24', '1.2.3.3/24'),
            ('1.2.3.4/24', '1.2.3.5/24'),
            ('1.2.3.4/24', '1.2.3.4/23'),
            ('1.2.3.4/24', '1.2.3.4/25'),
        ]
        for a1, a2 in data:
            addr1 = ip.IPv4Interface(a1)
            addr2 = ip.IPv4Interface(a2)
            time1, result1 = timefn(n, addr1.__lt__, addr2)
            eaddr1 = eip.IPv4Interface(a1)
            eaddr2 = eip.IPv4Interface(a2)
            time2, result2 = timefn(n, eaddr1.__lt__, eaddr2)
            results = (time1, result1), (time2, result2)
            self.report_4i.report(fn_name(), n, results, (addr1, addr2))

    def test_ipv4interface_le_(self):
        """Test the IPv4Interface.__le__ method."""
        n = 10**5
        data = [
            ('1.2.3.4/24', '1.2.3.4/24'),
            ('1.2.3.4/24', '1.2.3.3/24'),
            ('1.2.3.4/24', '1.2.3.5/24'),
            ('1.2.3.4/24', '1.2.3.4/23'),
            ('1.2.3.4/24', '1.2.3.4/25'),
        ]
        for a1, a2 in data:
            addr1 = ip.IPv4Interface(a1)
            addr2 = ip.IPv4Interface(a2)
            time1, result1 = timefn(n, addr1.__le__, addr2)
            eaddr1 = eip.IPv4Interface(a1)
            eaddr2 = eip.IPv4Interface(a2)
            time2, result2 = timefn(n, eaddr1.__le__, eaddr2)
            results = (time1, result1), (time2, result2)
            self.report_4i.report(fn_name(), n, results, (addr1, addr2))

    def test_ipv4interface_gt_(self):
        """Test the IPv4Interface.__gt__ method."""
        n = 10**5
        data = [
            ('1.2.3.4/24', '1.2.3.4/24'),
            ('1.2.3.4/24', '1.2.3.3/24'),
            ('1.2.3.4/24', '1.2.3.5/24'),
            ('1.2.3.4/24', '1.2.3.4/23'),
            ('1.2.3.4/24', '1.2.3.4/25'),
        ]
        for a1, a2 in data:
            addr1 = ip.IPv4Interface(a1)
            addr2 = ip.IPv4Interface(a2)
            time1, result1 = timefn(n, addr1.__gt__, addr2)
            eaddr1 = eip.IPv4Interface(a1)
            eaddr2 = eip.IPv4Interface(a2)
            time2, result2 = timefn(n, eaddr1.__gt__, eaddr2)
            results = (time1, result1), (time2, result2)
            self.report_4i.report(fn_name(), n, results, (addr1, addr2))

    def test_ipv4interface_ge_(self):
        """Test the IPv4Interface.__ge__ method."""
        n = 10**5
        data = [
            ('1.2.3.4/24', '1.2.3.4/24'),
            ('1.2.3.4/24', '1.2.3.3/24'),
            ('1.2.3.4/24', '1.2.3.5/24'),
            ('1.2.3.4/24', '1.2.3.4/23'),
            ('1.2.3.4/24', '1.2.3.4/25'),
        ]
        for a1, a2 in data:
            addr1 = ip.IPv4Interface(a1)
            addr2 = ip.IPv4Interface(a2)
            time1, result1 = timefn(n, addr1.__ge__, addr2)
            eaddr1 = eip.IPv4Interface(a1)
            eaddr2 = eip.IPv4Interface(a2)
            time2, result2 = timefn(n, eaddr1.__ge__, eaddr2)
            results = (time1, result1), (time2, result2)
            self.report_4i.report(fn_name(), n, results, (addr1, addr2))

    def test_ipv4interface_add(self):
        """Test the IPv4Interface.__add__ method."""
        n = 10**5
        addr1 = ip.IPv4Interface('1.2.3.4')
        time1, result1 = timefn(n, addr1.__add__, 2)
        eaddr1 = eip.IPv4Interface('1.2.3.4')
        time2, result2 = timefn(n, eaddr1.__add__, 2)
        results = (time1, result1), (time2, result2)
        self.report_4i.report(fn_name(), n, results, (addr1, 2))

    def test_ipv4interface_sub(self):
        """Test the IPv4Interface.__sub__ method."""
        n = 10**5
        addr1 = ip.IPv4Interface('1.2.3.4')
        time1, result1 = timefn(n, addr1.__sub__, 2)
        eaddr1 = eip.IPv4Interface('1.2.3.4')
        time2, result2 = timefn(n, eaddr1.__sub__, 2)
        results = (time1, result1), (time2, result2)
        self.report_4i.report(fn_name(), n, results, (addr1, 2))

    def test_ipv4interface_hash(self):
        """Test the IPv4Interface.__hash__ method."""
        n = 10**6
        addr1 = ip.IPv4Interface('1.2.3.4')
        time1, result1 = timefn(n, addr1.__hash__)
        eaddr1 = eip.IPv4Interface('1.2.3.4')
        time2, result2 = timefn(n, eaddr1.__hash__)
        # results will differ, so don't compare them
        results = (time1, None), (time2, None)
        self.report_4i.report(fn_name(), n, results, addr1)

    def test_ipv4interface_str(self):
        """Test the IPv4Interface.__str__ method."""
        n = 10**5
        addr = ip.IPv4Interface('1.2.3.4')
        time1, result1 = timefn(n, addr.__str__)
        eaddr = eip.IPv4Interface('1.2.3.4')
        time2, result2 = timefn(n, eaddr.__str__)
        results = (time1, result1), (time2, result2)
        self.report_4i.report(fn_name(), n, results, addr)

    def test_ipv4interface_repr(self):
        """Test the IPv4Interface.__repr__ method."""
        n = 10**5
        addr = ip.IPv4Interface('1.2.3.4')
        time1, result1 = timefn(n, addr.__repr__)
        eaddr = eip.IPv4Interface('1.2.3.4')
        time2, result2 = timefn(n, eaddr.__repr__)
        results = (time1, result1), (time2, result2)
        self.report_4i.report(fn_name(), n, results, addr)

    def test_ipv4interface_compressed(self):
        """Test the IPv4Interface.compressed method."""
        n = 10**5
        addr = ip.IPv4Interface('1.2.3.4')
        time1, result1 = timefn(n, lambda: addr.compressed)
        eaddr = eip.IPv4Interface('1.2.3.4')
        time2, result2 = timefn(n, lambda: eaddr.compressed)
        results = (time1, result1), (time2, result2)
        self.report_4i.report(fn_name(), n, results, addr)

    def test_ipv4interface_exploded(self):
        """Test the IPv4Interface.exploded method."""
        n = 10**5
        addr = ip.IPv4Interface('1.2.3.4')
        time1, result1 = timefn(n, lambda: addr.exploded)
        eaddr = eip.IPv4Interface('1.2.3.4')
        time2, result2 = timefn(n, lambda: eaddr.exploded)
        results = (time1, result1), (time2, result2)
        self.report_4i.report(fn_name(), n, results, addr)

    def test_ipv4interface_reduce(self):
        """Test the IPv4interface.__reduce__ method."""
        n = 10**5
        addr = ip.IPv4Interface('1.2.3.4')
        time1, result1 = timefn(n, addr.__reduce__)
        eaddr = eip.IPv4Interface('1.2.3.4')
        time2, result2 = timefn(n, eaddr.__reduce__)
        # results will differ, so don't compare them
        results = (time1, None), (time2, None)
        self.report_4i.report(fn_name(), n, results, addr)

    def test_ipv4interface_format(self):
        """Test the IPv4Interface.__format__ method."""
        n = 10**5
        data = ['s', 'b', 'x', 'n', '#b', '_b', '#_x']
        a1 = '1.2.3.4'
        addr = ip.IPv4Interface(a1)
        eaddr = eip.IPv4Interface(a1)
        fns = addr.__format__, eaddr.__format__
        for args in data:
            generic_test(self.report_4i, fn_name(), n, fns, args)

    def test_ipv4interface_max_prefixlen(self):
        """Test the IPv4Interface.max_prefixlen method."""
        n = 10**6
        net = ip.IPv4Interface('1.2.3.0/24')
        time1, result1 = timefn(n, lambda: net.max_prefixlen)
        enet = eip.IPv4Interface('1.2.3.0/24')
        time2, result2 = timefn(n, lambda: enet.max_prefixlen)
        results = (time1, result1), (time2, result2)
        self.report_4i.report(fn_name(), n, results, net)

    def test_ipv4interface_with_prefixlen(self):
        """Test the IPv4Interface.with_prefixlen method."""
        n = 10**5
        net = ip.IPv4Interface('1.2.3.0/24')
        time1, result1 = timefn(n, lambda: net.with_prefixlen)
        enet = eip.IPv4Interface('1.2.3.0/24')
        time2, result2 = timefn(n, lambda: enet.with_prefixlen)
        results = (time1, result1), (time2, result2)
        self.report_4i.report(fn_name(), n, results, net)

    def test_ipv4interface_with_netmask(self):
        """Test the IPv4Interface.with_netmask method."""
        n = 10**5
        net = ip.IPv4Interface('1.2.3.0/24')
        time1, result1 = timefn(n, lambda: net.with_netmask)
        enet = eip.IPv4Interface('1.2.3.0/24')
        time2, result2 = timefn(n, lambda: enet.with_netmask)
        results = (time1, result1), (time2, result2)
        self.report_4i.report(fn_name(), n, results, net)

    def test_ipv4interface_with_hostmask(self):
        """Test the IPv4Interface.with_hostmask method."""
        n = 10**5
        net = ip.IPv4Interface('1.2.3.0/24')
        time1, result1 = timefn(n, lambda: net.with_hostmask)
        enet = eip.IPv4Interface('1.2.3.0/24')
        time2, result2 = timefn(n, lambda: enet.with_hostmask)
        results = (time1, result1), (time2, result2)
        self.report_4i.report(fn_name(), n, results, net)

    def test_ipv4interface_reverse_pointer(self):
        """Test the IPv4Interface.reverse_pointer method."""
        n = 10**5
        addr = ip.IPv4Interface('1.2.3.4')
        time1, result1 = timefn(n, lambda: addr.reverse_pointer)
        eaddr = eip.IPv4Interface('1.2.3.4')
        time2, result2 = timefn(n, lambda: eaddr.reverse_pointer)
        results = (time1, result1), (time2, result2)
        self.report_4i.report(fn_name(), n, results, addr)

    def test_ipv4interface_is_reserved(self):
        """Test the IPv4Interface.is_reserved method."""
        n = 10**5
        addrs = ['1.2.3.4', '240.0.0.1']
        for a in addrs:
            addr = ip.IPv4Interface(a)
            time1, result1 = timefn(n, lambda: addr.is_multicast)
            eaddr = eip.IPv4Interface(a)
            time2, result2 = timefn(n, lambda: eaddr.is_multicast)
            results = (time1, result1), (time2, result2)
            self.report_4i.report(fn_name(), n, results, a)

    def test_ipv4interface_is_private(self):
        """Test the IPv4Interface.is_private method."""
        addrs = ['1.2.3.4', '10.0.0.1', '172.16.0.1', '192.168.0.1']
        for n in 1, 10**5:
            for a in addrs:
                addr = ip.IPv4Interface(a)
                time1, result1 = timefn(n, lambda: addr.is_private)
                eaddr = eip.IPv4Interface(a)
                time2, result2 = timefn(n, lambda: eaddr.is_private)
                results = (time1, result1), (time2, result2)
                self.report_4i.report(fn_name(), n, results, a)

    def test_ipv4interface_is_global(self):
        """Test the IPv4Interface.is_global method."""
        addrs = ['1.2.3.4', '10.0.0.1', '172.16.0.1', '192.168.0.1']
        for n in 1, 10**5:
            for a in addrs:
                addr = ip.IPv4Interface(a)
                time1, result1 = timefn(n, lambda: addr.is_global)
                eaddr = eip.IPv4Interface(a)
                time2, result2 = timefn(n, lambda: eaddr.is_global)
                results = (time1, result1), (time2, result2)
                self.report_4i.report(fn_name(), n, results, a)

    def test_ipv4interface_is_multicast(self):
        """Test the IPv4Interface.is_multicast method."""
        n = 10**5
        addrs = ['1.2.3.4', '224.0.0.1']
        for a in addrs:
            addr = ip.IPv4Interface(a)
            time1, result1 = timefn(n, lambda: addr.is_multicast)
            eaddr = eip.IPv4Interface(a)
            time2, result2 = timefn(n, lambda: eaddr.is_multicast)
            results = (time1, result1), (time2, result2)
            self.report_4i.report(fn_name(), n, results, a)

    def test_ipv4interface_is_unspecified(self):
        """Test the IPv4Interface.is_unspecified method."""
        n = 10**5
        addrs = ['1.2.3.4', '0.0.0.0']
        for a in addrs:
            addr = ip.IPv4Interface(a)
            time1, result1 = timefn(n, lambda: addr.is_unspecified)
            eaddr = eip.IPv4Interface(a)
            time2, result2 = timefn(n, lambda: eaddr.is_unspecified)
            results = (time1, result1), (time2, result2)
            self.report_4i.report(fn_name(), n, results, a)

    def test_ipv4interface_is_loopback(self):
        """Test the IPv4Interface.is_loopback method."""
        n = 10**5
        addrs = ['1.2.3.4', '127.0.0.1']
        for a in addrs:
            addr = ip.IPv4Interface(a)
            time1, result1 = timefn(n, lambda: addr.is_loopback)
            eaddr = eip.IPv4Interface(a)
            time2, result2 = timefn(n, lambda: eaddr.is_loopback)
            results = (time1, result1), (time2, result2)
            self.report_4i.report(fn_name(), n, results, a)

    def test_ipv4interface_is_link_local(self):
        """Test the IPv4Interface.is_link_local method."""
        n = 10**5
        addrs = ['1.2.3.4', '169.254.0.1']
        for a in addrs:
            addr = ip.IPv4Interface(a)
            time1, result1 = timefn(n, lambda: addr.is_link_local)
            eaddr = eip.IPv4Interface(a)
            time2, result2 = timefn(n, lambda: eaddr.is_link_local)
            results = (time1, result1), (time2, result2)
            self.report_4i.report(fn_name(), n, results, a)

    # =========================================================================
    # IPv6Interface
    # =========================================================================

    def test_ipv6interface_init(self):
        """Test the IPv6Interface.__init__ method."""
        n = 10**4
        data = [
            '1:2:3:4:5:6::',
            16384,
            (int(64).to_bytes(16, 'big'), 124),
        ]
        fns = ip.IPv6Interface, eip.IPv6Interface
        for args in data:
            generic_test(self.report_6i, fn_name(), n, fns, args)

    def test_ipv6interface_int(self):
        """Test the IPv6Interface.__int__ method."""
        n = 10**6
        addr = ip.IPv6Interface('1:2:3:4:5:6::')
        time1, result1 = timefn(n, addr.__int__)
        eaddr = eip.IPv6Interface('1:2:3:4:5:6::')
        time2, result2 = timefn(n, eaddr.__int__)
        results = (time1, result1), (time2, result2)
        self.report_6i.report(fn_name(), n, results, addr)

    def test_ipv6interface_ip(self):
        """Test the IPv6Interface.ip method."""
        n = 10**5
        a = '2000:3456::/40'
        addr = ip.IPv6Interface(a)
        time1, result1 = timefn(n, lambda: addr.ip)
        eaddr = eip.IPv6Interface(a)
        time2, result2 = timefn(n, lambda: eaddr.ip)
        results = (time1, result1), (time2, result2)
        self.report_6i.report(fn_name(), n, results, a)

    def test_ipv6interface_packed(self):
        """Test the IPv6Interface.packed method."""
        n = 10**6
        a = '2000:3456::/40'
        addr = ip.IPv6Interface(a)
        time1, result1 = timefn(n, lambda: addr.packed)
        eaddr = eip.IPv6Interface(a)
        time2, result2 = timefn(n, lambda: eaddr.packed)
        results = (time1, result1), (time2, result2)
        self.report_6i.report(fn_name(), n, results, a)

    def test_ipv6interface_eq_(self):
        """Test the IPv6Interface.__eq__ method."""
        n = 10**5
        data = [
            ('::4/96', '::4/96'),
            ('::4/96', '::3/96'),
            ('::4/96', '::5/96'),
            ('::4/96', '::4/93'),
            ('::4/96', '::4/97'),
        ]
        for a1, a2 in data:
            addr1 = ip.IPv6Interface(a1)
            addr2 = ip.IPv6Interface(a2)
            time1, result1 = timefn(n, addr1.__eq__, addr2)
            eaddr1 = eip.IPv6Interface(a1)
            eaddr2 = eip.IPv6Interface(a2)
            time2, result2 = timefn(n, eaddr1.__eq__, eaddr2)
            results = (time1, result1), (time2, result2)
            self.report_6i.report(fn_name(), n, results, (addr1, addr2))

    def test_ipv6interface_ne_(self):
        """Test the IPv6Interface.__ne__ method."""
        n = 10**5
        data = [
            ('::4/96', '::4/96'),
            ('::4/96', '::3/96'),
            ('::4/96', '::5/96'),
            ('::4/96', '::4/93'),
            ('::4/96', '::4/97'),
        ]
        for a1, a2 in data:
            addr1 = ip.IPv6Interface(a1)
            addr2 = ip.IPv6Interface(a2)
            time1, result1 = timefn(n, addr1.__ne__, addr2)
            eaddr1 = eip.IPv6Interface(a1)
            eaddr2 = eip.IPv6Interface(a2)
            time2, result2 = timefn(n, eaddr1.__ne__, eaddr2)
            results = (time1, result1), (time2, result2)
            self.report_6i.report(fn_name(), n, results, (addr1, addr2))

    def test_ipv6interface_lt_(self):
        """Test the IPv6Interface.__lt__ method."""
        n = 10**5
        data = [
            ('::4/96', '::4/96'),
            ('::4/96', '::3/96'),
            ('::4/96', '::5/96'),
            ('::4/96', '::4/93'),
            ('::4/96', '::4/97'),
        ]
        for a1, a2 in data:
            addr1 = ip.IPv6Interface(a1)
            addr2 = ip.IPv6Interface(a2)
            time1, result1 = timefn(n, addr1.__lt__, addr2)
            eaddr1 = eip.IPv6Interface(a1)
            eaddr2 = eip.IPv6Interface(a2)
            time2, result2 = timefn(n, eaddr1.__lt__, eaddr2)
            results = (time1, result1), (time2, result2)
            self.report_6i.report(fn_name(), n, results, (addr1, addr2))

    def test_ipv6interface_le_(self):
        """Test the IPv6Interface.__le__ method."""
        n = 10**5
        data = [
            ('::4/96', '::4/96'),
            ('::4/96', '::3/96'),
            ('::4/96', '::5/96'),
            ('::4/96', '::4/93'),
            ('::4/96', '::4/97'),
        ]
        for a1, a2 in data:
            addr1 = ip.IPv6Interface(a1)
            addr2 = ip.IPv6Interface(a2)
            time1, result1 = timefn(n, addr1.__le__, addr2)
            eaddr1 = eip.IPv6Interface(a1)
            eaddr2 = eip.IPv6Interface(a2)
            time2, result2 = timefn(n, eaddr1.__le__, eaddr2)
            results = (time1, result1), (time2, result2)
            self.report_6i.report(fn_name(), n, results, (addr1, addr2))

    def test_ipv6interface_gt_(self):
        """Test the IPv6Interface.__gt__ method."""
        n = 10**5
        data = [
            ('::4/96', '::4/96'),
            ('::4/96', '::3/96'),
            ('::4/96', '::5/96'),
            ('::4/96', '::4/93'),
            ('::4/96', '::4/97'),
        ]
        for a1, a2 in data:
            addr1 = ip.IPv6Interface(a1)
            addr2 = ip.IPv6Interface(a2)
            time1, result1 = timefn(n, addr1.__gt__, addr2)
            eaddr1 = eip.IPv6Interface(a1)
            eaddr2 = eip.IPv6Interface(a2)
            time2, result2 = timefn(n, eaddr1.__gt__, eaddr2)
            results = (time1, result1), (time2, result2)
            self.report_6i.report(fn_name(), n, results, (addr1, addr2))

    def test_ipv6interface_ge_(self):
        """Test the IPv6Interface.__ge__ method."""
        n = 10**5
        data = [
            ('::4/96', '::4/96'),
            ('::4/96', '::3/96'),
            ('::4/96', '::5/96'),
            ('::4/96', '::4/93'),
            ('::4/96', '::4/97'),
        ]
        for a1, a2 in data:
            addr1 = ip.IPv6Interface(a1)
            addr2 = ip.IPv6Interface(a2)
            time1, result1 = timefn(n, addr1.__ge__, addr2)
            eaddr1 = eip.IPv6Interface(a1)
            eaddr2 = eip.IPv6Interface(a2)
            time2, result2 = timefn(n, eaddr1.__ge__, eaddr2)
            results = (time1, result1), (time2, result2)
            self.report_6i.report(fn_name(), n, results, (addr1, addr2))

    def test_ipv6interface_add(self):
        """Test the IPv6Interface.__add__ method."""
        n = 10**5
        addr1 = ip.IPv6Interface('1:2:3:4:5:6::')
        time1, result1 = timefn(n, addr1.__add__, 2)
        eaddr1 = eip.IPv6Interface('1:2:3:4:5:6::')
        time2, result2 = timefn(n, eaddr1.__add__, 2)
        results = (time1, result1), (time2, result2)
        self.report_6i.report(fn_name(), n, results, (addr1, 2))

    def test_ipv6interface_sub(self):
        """Test the IPv6Interface.__sub__ method."""
        n = 10**5
        addr1 = ip.IPv6Interface('1:2:3:4:5:6::')
        time1, result1 = timefn(n, addr1.__sub__, 2)
        eaddr1 = eip.IPv6Interface('1:2:3:4:5:6::')
        time2, result2 = timefn(n, eaddr1.__sub__, 2)
        results = (time1, result1), (time2, result2)
        self.report_6i.report(fn_name(), n, results, (addr1, 2))

    def test_ipv6interface_hash(self):
        """Test the IPv6Interface.__hash__ method."""
        n = 10**6
        addr1 = ip.IPv6Interface('1:2:3:4:5:6::')
        time1, result1 = timefn(n, addr1.__hash__)
        eaddr1 = eip.IPv6Interface('1:2:3:4:5:6::')
        time2, result2 = timefn(n, eaddr1.__hash__)
        results = (time1, None), (time2, None)
        self.report_6i.report(fn_name(), n, results, addr1)

    def test_ipv6interface_str(self):
        """Test the IPv6Interface.__str__ method."""
        n = 10**4
        addrs = ['1:2:3:4:5:6::', '::', '::5:6:7:8', '1:2:3:4::', '1:2::7:8']
        for a in addrs:
            addr = ip.IPv6Interface(a)
            time1, result1 = timefn(n, addr.__str__)
            eaddr = eip.IPv6Interface(a)
            time2, result2 = timefn(n, eaddr.__str__)
            results = (time1, result1), (time2, result2)
            self.report_6i.report(fn_name(), n, results, addr)

    def test_ipv6interface_repr(self):
        """Test the IPv6Interface.__repr__ method."""
        n = 10**5
        addr = ip.IPv6Interface('1:2:3:4:5:6::')
        time1, result1 = timefn(n, addr.__repr__)
        eaddr = eip.IPv6Interface('1:2:3:4:5:6::')
        time2, result2 = timefn(n, eaddr.__repr__)
        results = (time1, result1), (time2, result2)
        self.report_6i.report(fn_name(), n, results, addr)

    def test_ipv6interface_compressed(self):
        """Test the IPv6Interface.compressed method."""
        n = 10**4
        addrs = ['1:2:3:4:5:6::', '::', '::5:6:7:8', '1:2:3:4::', '1:2::7:8']
        for a in addrs:
            addr = ip.IPv6Interface(a)
            time1, result1 = timefn(n, lambda: addr.compressed)
            eaddr = eip.IPv6Interface(a)
            time2, result2 = timefn(n, lambda: eaddr.compressed)
            results = (time1, result1), (time2, result2)
            self.report_6i.report(fn_name(), n, results, addr)

    def test_ipv6interface_exploded(self):
        """Test the IPv6Interface.exploded method."""
        n = 10**4
        addrs = ['1:2:3:4:5:6::', '::', '::5:6:7:8', '1:2:3:4::', '1:2::7:8']
        for a in addrs:
            addr = ip.IPv6Interface(a)
            time1, result1 = timefn(n, lambda: addr.exploded)
            eaddr = eip.IPv6Interface(a)
            time2, result2 = timefn(n, lambda: eaddr.exploded)
            results = (time1, result1), (time2, result2)
            self.report_6i.report(fn_name(), n, results, addr)

    def test_ipv6interface_reduce(self):
        """Test the IPv6Interface.__reduce__ method."""
        n = 10**5
        addr = ip.IPv6Interface('2001::/48')
        time1, result1 = timefn(n, addr.__reduce__)
        eaddr = eip.IPv6Interface('2001::/48')
        time2, result2 = timefn(n, eaddr.__reduce__)
        # results will differ, so don't compare them
        results = (time1, None), (time2, None)
        self.report_6i.report(fn_name(), n, results, addr)

    def test_ipv6interface_format(self):
        """Test the IPv6Interface.__format__ method."""
        n = 10**5
        data = ['s', 'b', 'x', 'n', '#b', '_b', '#_x']
        a1 = '1:2:3::6'
        addr = ip.IPv6Interface(a1)
        eaddr = eip.IPv6Interface(a1)
        fns = addr.__format__, eaddr.__format__
        for args in data:
            generic_test(self.report_6i, fn_name(), n, fns, args)

    def test_ipv6interface_max_prefixlen(self):
        """Test the IPv6Interface.max_prefixlen method."""
        n = 10**6
        net = ip.IPv6Interface('1:2:3:4::/120')
        time1, result1 = timefn(n, lambda: net.max_prefixlen)
        enet = eip.IPv6Interface('1:2:3:4::/120')
        time2, result2 = timefn(n, lambda: enet.max_prefixlen)
        results = (time1, result1), (time2, result2)
        self.report_6i.report(fn_name(), n, results, net)

    def test_ipv6interface_with_prefixlen(self):
        """Test the IPv6Interface.with_prefixlen method."""
        n = 10**5
        net = ip.IPv6Interface('1:2:3:4::/120')
        time1, result1 = timefn(n, lambda: net.with_prefixlen)
        enet = eip.IPv6Interface('1:2:3:4::/120')
        time2, result2 = timefn(n, lambda: enet.with_prefixlen)
        results = (time1, result1), (time2, result2)
        self.report_6i.report(fn_name(), n, results, net)

    def test_ipv6interface_with_netmask(self):
        """Test the IPv6Interface.with_netmask method."""
        n = 10**4
        net = ip.IPv6Interface('1:2:3:4::/120')
        time1, result1 = timefn(n, lambda: net.with_netmask)
        enet = eip.IPv6Interface('1:2:3:4::/120')
        time2, result2 = timefn(n, lambda: enet.with_netmask)
        results = (time1, result1), (time2, result2)
        self.report_6i.report(fn_name(), n, results, net)

    def test_ipv6interface_with_hostmask(self):
        """Test the IPv6Interface.with_hostmask method."""
        n = 10**4
        net = ip.IPv6Interface('1:2:3:4::/120')
        time1, result1 = timefn(n, lambda: net.with_hostmask)
        enet = eip.IPv6Interface('1:2:3:4::/120')
        time2, result2 = timefn(n, lambda: enet.with_hostmask)
        results = (time1, result1), (time2, result2)
        self.report_6i.report(fn_name(), n, results, net)

    def test_ipv6interface_reverse_pointer(self):
        """Test the IPv6Interface.reverse_pointer method."""
        n = 10**4
        addr = ip.IPv6Interface('1:2:3:4:5:6::')
        time1, result1 = timefn(n, lambda: addr.reverse_pointer)
        eaddr = eip.IPv6Interface('1:2:3:4:5:6::')
        time2, result2 = timefn(n, lambda: eaddr.reverse_pointer)
        results = (time1, result1), (time2, result2)
        self.report_6i.report(fn_name(), n, results, addr)

    def _test_ipv6interface_is_reserved(self):
        """Test the IPv6Interface.is_reserved method."""
        n = 10**4
        addrs = [
            '2001:2:3:4:5:6::',
            '::1',
            '100::1',
            '200::1',
            '400::1',
            '800::1',
            '1000::1',
            '4000::1',
            '6000::1',
            '8000::1',
            'A000::1',
            'C000::1',
            'E000::1',
            'F000::1',
            'F800::1',
            'FE00::1',
        ]
        for a in addrs:
            addr = ip.IPv6Interface(a)
            time1, result1 = timefn(n, lambda: addr.is_multicast)
            eaddr = eip.IPv6Interface(a)
            time2, result2 = timefn(n, lambda: eaddr.is_multicast)
            results = (time1, result1), (time2, result2)
            self.report_6i.report(fn_name(), n, results, a)

    def test_ipv6interface_is_private(self):
        """Test the IPv6Interface.is_private method."""
        addrs = [
            '::',
            '::1',
            '::ffff:0:0',
            '100::',
            '2001::',
            '2001:2::',
            '2001:10::',
            '2001:db8::',
            'fc00::',
            'fe80::',
            '::2',
        ]
        for n in 1, 10**5:
            for a in addrs:
                addr = ip.IPv6Interface(a)
                time1, result1 = timefn(n, lambda: addr.is_private)
                eaddr = eip.IPv6Interface(a)
                time2, result2 = timefn(n, lambda: eaddr.is_private)
                results = (time1, result1), (time2, result2)
                self.report_6i.report(fn_name(), n, results, a)

    def test_ipv6interface_is_global(self):
        """Test the IPv6Interface.is_global method."""
        addrs = [
            '::',
            '::1',
            '::ffff:0:0',
            '100::',
            '2001::',
            '2001:2::',
            '2001:10::',
            '2001:db8::',
            'fc00::',
            'fe80::',
            '::2',
        ]
        for n in 1, 10**5:
            for a in addrs:
                addr = ip.IPv6Interface(a)
                time1, result1 = timefn(n, lambda: addr.is_global)
                eaddr = eip.IPv6Interface(a)
                time2, result2 = timefn(n, lambda: eaddr.is_global)
                results = (time1, result1), (time2, result2)
                self.report_6i.report(fn_name(), n, results, a)

    def test_ipv6interface_is_multicast(self):
        """Test the IPv6Interface.is_multicast method."""
        n = 10**5
        addrs = ['1:2:3:4:5:6::', 'ff00::1']
        for a in addrs:
            addr = ip.IPv6Interface(a)
            time1, result1 = timefn(n, lambda: addr.is_multicast)
            eaddr = eip.IPv6Interface(a)
            time2, result2 = timefn(n, lambda: eaddr.is_multicast)
            results = (time1, result1), (time2, result2)
            self.report_6i.report(fn_name(), n, results, a)

    def test_ipv6interface_is_unspecified(self):
        """Test the IPv6Interface.is_unspecified method."""
        n = 10**6
        addrs = ['1:2:3:4:5:6::', '::']
        for a in addrs:
            addr = ip.IPv6Interface(a)
            time1, result1 = timefn(n, lambda: addr.is_unspecified)
            eaddr = eip.IPv6Interface(a)
            time2, result2 = timefn(n, lambda: eaddr.is_unspecified)
            results = (time1, result1), (time2, result2)
            self.report_6i.report(fn_name(), n, results, a)

    def test_ipv6interface_is_loopback(self):
        """Test the IPv6Interface.is_loopback method."""
        n = 10**6
        addrs = ['1:2:3:4:5:6::', '::1']
        for a in addrs:
            addr = ip.IPv6Interface(a)
            time1, result1 = timefn(n, lambda: addr.is_loopback)
            eaddr = eip.IPv6Interface(a)
            time2, result2 = timefn(n, lambda: eaddr.is_loopback)
            results = (time1, result1), (time2, result2)
            self.report_6i.report(fn_name(), n, results, a)

    def test_ipv6interface_is_link_local(self):
        """Test the IPv6Interface.is_link_local method."""
        n = 10**5
        addrs = ['1:2:3:4:5:6::', 'fe80::1']
        for a in addrs:
            addr = ip.IPv6Interface(a)
            time1, result1 = timefn(n, lambda: addr.is_link_local)
            eaddr = eip.IPv6Interface(a)
            time2, result2 = timefn(n, lambda: eaddr.is_link_local)
            results = (time1, result1), (time2, result2)
            self.report_6i.report(fn_name(), n, results, a)

    def test_ipv6interface_is_site_local(self):
        """Test the IPv6Interface.is_site_local method."""
        n = 10**5
        addrs = ['1:2:3:4:5:6::', 'fec0::1']
        for a in addrs:
            addr = ip.IPv6Interface(a)
            time1, result1 = timefn(n, lambda: addr.is_site_local)
            eaddr = eip.IPv6Interface(a)
            time2, result2 = timefn(n, lambda: eaddr.is_site_local)
            results = (time1, result1), (time2, result2)
            self.report_6i.report(fn_name(), n, results, a)

    def test_ipv6interface_ipv4_mapped(self):
        """Test the IPv6Interface.ipv4_mapped method."""
        n = 10**6
        addrs = ['1:2:3:4:5:6::', '::ffff:1.2.3.4']
        for a in addrs:
            addr = ip.IPv6Interface(a)
            time1, result1 = timefn(n, lambda: addr.ipv4_mapped)
            eaddr = eip.IPv6Interface(a)
            time2, result2 = timefn(n, lambda: addr.ipv4_mapped)
            results = (time1, result1), (time2, result2)
            self.report_6i.report(fn_name(), n, results, a)

    def test_ipv6interface_teredo(self):
        """Test the IPv6Interface.teredo method."""
        n = 10**5
        addrs = ['1:2:3:4:5:6::', '2001::ffff:1']
        for a in addrs:
            addr = ip.IPv6Interface(a)
            time1, result1 = timefn(n, lambda: addr.teredo)
            eaddr = eip.IPv6Interface(a)
            time2, result2 = timefn(n, lambda: addr.teredo)
            results = (time1, result1), (time2, result2)
            self.report_6i.report(fn_name(), n, results, a)

    def test_ipv6interface_sixtofour(self):
        """Test the IPv6Interface.sixtofour method."""
        n = 10**6
        addrs = ['1:2:3:4:5:6::', '2002:0102:0304::']
        for a in addrs:
            addr = ip.IPv6Interface(a)
            time1, result1 = timefn(n, lambda: addr.sixtofour)
            eaddr = eip.IPv6Interface(a)
            time2, result2 = timefn(n, lambda: addr.sixtofour)
            results = (time1, result1), (time2, result2)
            self.report_6i.report(fn_name(), n, results, a)

    def test_ipv6interface_scope_id(self):
        """Test the IPv6Interface.scope_id function."""
        n = 10**6
        a = '2020::%a1'
        addr = ip.IPv6Interface(a)
        time1, result1 = timefn(n, lambda: addr.scope_id)
        eaddr = eip.IPv6Interface(a)
        time2, result2 = timefn(n, lambda: eaddr.scope_id)
        results = (time1, result1), (time2, result2)
        self.report_6i.report(fn_name(), n, results, a)

    def test_memory_usage(self):
        """Test the memory usage."""

        def use_cached_attributes(*args):
            for o in args:
                try:
                    n = o.is_private
                except Exception:
                    pass
                try:
                    n = o.is_global
                except Exception:
                    pass
                try:
                    n = o.network_address
                except Exception:
                    pass
                try:
                    n = o.broadcast_address
                except Exception:
                    pass
                try:
                    n = o.netmask
                except Exception:
                    pass
                try:
                    n = o.hostmask
                except Exception:
                    pass
                try:
                    n = o.network
                except Exception:
                    pass

        data = (
            (ip.IPv4Address('1.2.3.4'), eip.IPv4Address('1.2.3.4')),
            (ip.IPv4Interface('8.7.6.5/24'),
             eip.IPv4Interface('8.7.6.5/24')),
            (ip.IPv4Network('192.3.0.0/16'),
             eip.IPv4Network('192.3.0.0/16')),
            (ip.IPv6Address('2001::1%A'), eip.IPv6Address('2001::1%A')),
            (ip.IPv6Interface('1000::2%I/24'),
             eip.IPv6Interface('1000::2%I/24')),
            (ip.IPv6Network('3000::%N::/16'),
             eip.IPv6Network('3000::%N::/16')),
        )
        for a, b in data:
            # sizeof calculation
            # make an unused copy of the objects for initial report
            i = a.__class__(str(a))
            e = b.__class__(str(b))
            isize, esize = sizeof(i), sizeof(e)
            results = (isize, repr(i)), (esize, repr(e))
            self.report_m.report(fn_name(), 1, results, 'isizes - init: %r' % i)
            use_cached_attributes(i, e)
            isize, esize = sizeof(i), sizeof(e)
            results = (isize, repr(i)), (esize, repr(e))
            self.report_m.report(fn_name(), 1, results, 'isizes - used: %r' % i)

# =============================================================================

if __name__ == '__main__':
    matches = sys.argv[1:]
    PerfTest().run(matches)
