
class AddressValueError(ValueError):
    """A Value Error related to the address."""


class NetmaskValueError(ValueError):
    """A Value Error related to the netmask."""

def _count_righthand_zero_bits(number, bits):
    """Count the number of zero bits on the right hand side.
    Args:
        number: an integer.
        bits: maximum number of bits to count.
    Returns:
        The number of zero bits on the right hand side of the number.
    """
    if number == 0:
        return bits
    return min(bits, (~number & (number-1)).bit_length())


class IPv4Address():

    _max_prefixlen = 32
    _ALL_ONES = 2**32 - 1
    _version = 4

    def __init__(self, address):
        if isinstance(address, int):
            self._check_int_address(address)
            self._ip = address
            return

        addr_str = str(address)    
        if '/' in addr_str:
            raise AddressValueError("Unexpected '/' in %r" % address)
        self._ip = self._ip_int_from_string(addr_str)

    @property
    def compressed(self):
        return str(self)

    def __int__(self):
        return self._ip

    def __str__(self):
        return str(self._string_from_ip_int(self._ip))

    def __eq__(self, other):
        try:
            return (self._ip == other._ip
                    and self._version == other._version)
        except AttributeError:
            return NotImplemented

    def __lt__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        if self._version != other._version:
            raise TypeError('%s and %s are not of the same version' % (
                             self, other))
        if self._ip != other._ip:
            return self._ip < other._ip
        return False

    # Shorthand for Integer addition and subtraction. This is not
    # meant to ever support addition/subtraction of addresses.
    def __add__(self, other):
        if not isinstance(other, int):
            return NotImplemented
        return self.__class__(int(self) + other)

    def __sub__(self, other):
        if not isinstance(other, int):
            return NotImplemented
        return self.__class__(int(self) - other)

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, str(self))

    @classmethod
    def _ip_int_from_string(cls, ip_str):
        """Turn the given IP string into an integer for comparison.
        Args:
            ip_str: A string, the IP ip_str.
        Returns:
            The IP ip_str as an integer.
        Raises:
            AddressValueError: if ip_str isn't a valid IPv4 Address.
        """
        if not ip_str:
            raise AddressValueError('Address cannot be empty')

        octets = ip_str.split('.')
        if len(octets) != 4:
            raise AddressValueError("Expected 4 octets in %r" % ip_str)

        try:
            return int.from_bytes(map(cls._parse_octet, octets), 'big')
        except ValueError as exc:
            raise AddressValueError("%s in %r" % (exc, ip_str)) from None

    @classmethod
    def _parse_octet(cls, octet_str):
        """Convert a decimal octet into an integer.
        Args:
            octet_str: A string, the number to parse.
        Returns:
            The octet as an integer.
        Raises:
            ValueError: if the octet isn't strictly a decimal from [0..255].
        """
        if not octet_str:
            raise ValueError("Empty octet not permitted")
        # Whitelist the characters, since int() allows a lot of bizarre stuff.
        
        #REMOVED
        #if not (octet_str.isascii() and octet_str.isdigit()):
        #    msg = "Only decimal digits permitted in %r"
        #    raise ValueError(msg % octet_str)
        
        # We do the length check second, since the invalid character error
        # is likely to be more informative for the user
        if len(octet_str) > 3:
            msg = "At most 3 characters permitted in %r"
            raise ValueError(msg % octet_str)
        # Convert to integer (we know digits are legal)
        octet_int = int(octet_str, 10)
        if octet_int > 255:
            raise ValueError("Octet %d (> 255) not permitted" % octet_int)
        return octet_int

    @classmethod
    def _string_from_ip_int(cls, ip_int):
        """Turns a 32-bit integer into dotted decimal notation.
        Args:
            ip_int: An integer, the IP address.
        Returns:
            The IP address as a string in dotted decimal notation.
        """
        return '.'.join(map(str, ip_int.to_bytes(4, 'big')))


    @classmethod
    def _check_int_address(cls, address):
        if address < 0:
            msg = "%d (< 0) is not permitted as an IPv4 address"
            raise AddressValueError(msg % (address))
        if address > cls._ALL_ONES:
            msg = "%d (>= 2**%d) is not permitted as an IPv4 address"
            raise AddressValueError(msg % (address, cls._max_prefixlen))

class IPInterface(IPv4Address):

    def __init__(self, address):
        addr, mask = self._split_addr_prefix(address)
        IPv4Address.__init__(self, addr)
        self._netmask, self._prefixlen = self._make_netmask(mask)

    @property
    def network_address(self):
        return IPv4Address(self._ip & self._netmask)

    @property
    def broadcast_address(self):
        i = 2**(self._max_prefixlen - self._prefixlen)
        return IPv4Address((self._ip & self._netmask) + i - 1)

    @property
    def prefix_len(self):
        return self._prefixlen

    @property
    def ip(self):
        return IPv4Address(self._ip)

    @property
    def with_prefixlen(self):
        return '%s/%s' % (self._string_from_ip_int(self._ip),
                          self._prefixlen)

    @property
    def netmask(self):
        return IPv4Address(self._netmask)

    @property
    def with_netmask(self):
        return '%s/%s' % (self._string_from_ip_int(self._ip),
                          self._string_from_ip_int(self._netmask))
    @property
    def network_with_prefixlen(self):
         return '%s/%s' % (self._string_from_ip_int(self._netmask),
                          self._prefixlen)       
    @property
    def first_host_address(self):
        return self.network_address + 1

    @property
    def last_host_address(self):
        return self.broadcast_address - 1 

    def same_network_with(self, other):
        if isinstance(other, self.__class__):
            network_address = other.network_address
        elif isinstance(other, IPv4Address):
            network_address = other._ip
        else:    
            return NotImplemented
        if self._version != other._version:
            raise TypeError('%s and %s are not of the same version' % (
                             self, other))
        return self.network_address == network_address

    def network_include_address(self, other):
        if not isinstance(other, (self.__class__, IPv4Address)):   
            return NotImplemented
        if self._version != other._version:
            raise TypeError('%s and %s are not of the same version' % (
                             self, other))

        return self.network_address._ip <= other._ip and  other._ip <= self.broadcast_address._ip

    @classmethod
    def _split_addr_prefix(cls, address):
        """Helper function to parse address of Network/Interface.
        Arg:
            address: Argument of Network/Interface.
        Returns:
            (addr, prefix) tuple.
        """
        # a packed address or integer
        if isinstance(address, (bytes, int)):
            return address, cls._max_prefixlen

        if not isinstance(address, tuple):
            # Assume input argument to be string or any object representation
            # which converts into a formatted IP prefix string.
            address = cls._split_optional_netmask(address)

        # Constructing from a tuple (addr, [mask])
        if len(address) > 1:
            return address
        return address[0], cls._max_prefixlen

    @classmethod
    def _split_optional_netmask(cls, address):
        """Helper to split the netmask and raise AddressValueError if needed"""
        addr = str(address).split('/')
        if len(addr) == 1:
            # Set prefixlen = 32 if no mask found in address.
            addr.append('32')
            return addr

        if len(addr) > 2:
            raise AddressValueError("Only one '/' permitted in %r" % address)
        return addr


    @classmethod
    def _ip_int_from_prefix(cls, prefixlen):
        """Turn the prefix length into a bitwise netmask
        Args:
            prefixlen: An integer, the prefix length.
        Returns:
            An integer.
        """
        return cls._ALL_ONES ^ (cls._ALL_ONES >> prefixlen)

    @classmethod
    def _make_netmask(cls, arg):
        """Make a (netmask, prefix_len) tuple from the given argument.
        Argument can be:
        - an integer (the prefix length)
        - a string representing the prefix length (e.g. "24")
        - a string representing the prefix netmask (e.g. "255.255.255.0")
        """
        if isinstance(arg, int):
            prefixlen = arg
            if not (0 <= prefixlen <= cls._max_prefixlen):
                cls._report_invalid_netmask(prefixlen)
        else:
            try:
                # Check for a netmask in prefix length form
                prefixlen = cls._prefix_from_prefix_string(arg)
            except NetmaskValueError:
                # Check for a netmask or hostmask in dotted-quad form.
                # This may raise NetmaskValueError.
                prefixlen = cls._prefix_from_ip_string(arg)

        netmask = cls._ip_int_from_prefix(prefixlen)
        cls._check_int_address(netmask)
        
        return netmask, prefixlen

    @classmethod
    def _report_invalid_netmask(cls, netmask_str):
        msg = '%r is not a valid netmask' % netmask_str
        raise NetmaskValueError(msg) from None

    @classmethod
    def _prefix_from_prefix_string(cls, prefixlen_str):
        """Return prefix length from a numeric string
        Args:
            prefixlen_str: The string to be converted
        Returns:
            An integer, the prefix length.
        Raises:
            NetmaskValueError: If the input is not a valid netmask
        """
        # int allows a leading +/- as well as surrounding whitespace,
        # so we ensure that isn't the case
        
        #REMOVED 
        #if not (prefixlen_str.isascii() and prefixlen_str.isdigit()):
        #    cls._report_invalid_netmask(prefixlen_str)
        try:
            prefixlen = int(prefixlen_str)
        except ValueError:
            cls._report_invalid_netmask(prefixlen_str)
        if not (0 <= prefixlen <= cls._max_prefixlen):
            cls._report_invalid_netmask(prefixlen_str)
        return prefixlen

    @classmethod
    def _prefix_from_ip_string(cls, ip_str):
        """Turn a netmask/hostmask string into a prefix length
        Args:
            ip_str: The netmask/hostmask to be converted
        Returns:
            An integer, the prefix length.
        Raises:
            NetmaskValueError: If the input is not a valid netmask/hostmask
        """
        # Parse the netmask/hostmask like an IP address.
        try:
            ip_int = cls._ip_int_from_string(ip_str)
        except AddressValueError:
            cls._report_invalid_netmask(ip_str)

        # Try matching a netmask (this would be /1*0*/ as a bitwise regexp).
        # Note that the two ambiguous cases (all-ones and all-zeroes) are
        # treated as netmasks.
        try:
            return cls._prefix_from_ip_int(ip_int)
        except ValueError:
            pass

        # Invert the bits, and try matching a /0+1+/ hostmask instead.
        ip_int ^= cls._ALL_ONES
        try:
            return cls._prefix_from_ip_int(ip_int)
        except ValueError:
            cls._report_invalid_netmask(ip_str)

    @classmethod
    def _prefix_from_ip_int(cls, ip_int):
        """Return prefix length from the bitwise netmask.
        Args:
            ip_int: An integer, the netmask in expanded bitwise format
        Returns:
            An integer, the prefix length.
        Raises:
            ValueError: If the input intermingles zeroes & ones
        """
        trailing_zeroes = _count_righthand_zero_bits(ip_int,
                                                     cls._max_prefixlen)
        prefixlen = cls._max_prefixlen - trailing_zeroes
        leading_ones = ip_int >> trailing_zeroes
        all_ones = (1 << prefixlen) - 1
        if leading_ones != all_ones:
            byteslen = cls._max_prefixlen // 8
            details = ip_int.to_bytes(byteslen, 'big')
            msg = 'Netmask pattern %r mixes zeroes & ones'
            raise ValueError(msg % details)
        return prefixlen

def ipaddress(address):
    return IPInterface(address)
