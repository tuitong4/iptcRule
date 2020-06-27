import subprocess
import hashlib
import os
import re
import io
import time

def execute_command(cmd):
    """Return (exitcode, output) of executing cmd in a shell.
    Execute the string 'cmd' in a shell with 'check_output' and
    return a 2-tuple (status, output). The locale encoding is used
    to decode the output and process newlines.
    A trailing newline is stripped from the output.
    The exit status for the command can be interpreted
    according to the rules for the function 'wait'. Example:
    >>> import subprocess
    >>> subprocess.getstatusoutput('ls /bin/ls')
    (0, '/bin/ls')
    >>> subprocess.getstatusoutput('cat /bin/junk')
    (1, 'cat: /bin/junk: No such file or directory')
    >>> subprocess.getstatusoutput('/bin/junk')
    (127, 'sh: /bin/junk: not found')
    >>> subprocess.getstatusoutput('/bin/kill $$')
    (-15, '')
    """
    try:
        data = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        exitcode = 0
    except subprocess.CalledProcessError as ex:
        data = ex.output
        exitcode = ex.returncode
    if data[-1:] == '\n':
        data = data[:-1]
    return exitcode, bytes.decode(data)

def is_ip(ip_str):
    """Check if the given IP string is a ipv4 address"""
    if not ip_str:
        raise ValueError('Address cannot be empty')

    octets = ip_str.split('.')
    if len(octets) != 4:
        raise ValueError("Expected 4 octets in %r" % ip_str)

    for octet in octets:
        try :
            if int(octet) > 255 or int(octet) < 0:
                return False
        except:
            return False
    return True   

def correspond_to_map(s):
    """Convert a string to a map, string start with '#'will be striped.
    For Example :
    'vitrual_server 10.0.0.1 0' --> {'vitrual_server': ['10.0.0.1', '0']}
    'protocol ICMP'             --> {'protocal': 'ICMP'}
    'alpha'                     --> {'alpha': True}
    'quorum_down "text string"' --> {'quorum_down': '"text string"'}
    'weight 3 #Numberic content'--> {'weight': '3'}
    """
    key, val = None, None
    s = s.strip()
    if s.startswith("#"):
        return key, val

    if "#" in s:
        s = s.split("#")[0]    

    c = s.split()

    if len(c) > 2:
        if '"' in s:
            r = re.search('(".*")', s)
            if r :
                val = r.group(1)
        else:
            val = c[1:]

        key = c[0]
    
    elif len(c) == 2:
        key = c[0]
        val = c[1]

    elif len(c) == 1:
        key =c[0]
        val = True

    return key, val

def _nat_config_parser(s, idx):
    """Parser the given string 's' to a map. 'idx' is the start index of 
    string 's' to parse.
    It uses function 'correspond_to_map' to convert the matched string to
    a map, if value in pair (key, value) the function returned is a list,
    value will formated as a string with ':' as delimiter.
    """
    next_line = []
    result = {}
    while True:
        try:
            char = s[idx]
        except IndexError:
            break

        if char == "\n" or char == "\r":
            k, v = correspond_to_map("".join(next_line))
            if k :
                result[k] = v
            next_line = []

        elif char == "{":
            k, v = correspond_to_map("".join(next_line))
            if k is not None:
                r, end_idx = _nat_config_parser(s, idx+1)
                idx = end_idx 
                if isinstance(v, list):
                    if k not in result:
                        result[k] = {}
                    result[k][':'.join(v)] = r
                else:
                    result[k] = r
                #skip the item v == True
                #if v is not True:
                    #result[k]["no_name"] = v
            next_line = []
            
        elif char == "}":
            k, v = correspond_to_map("".join(next_line))
            if k :
                result[k] = v
            return result, idx

        else:
            next_line.append(char)

        idx += 1
    
    raise ValueError("string is invalid to prase.")
    
def nat_config_parser(s):
    """Scan the whole given string and try to parse a map from it"""
    
    delimiter = "virtual_server"
    re_vs_name = re.compile(r"match (\w+)\s*\{")
    l = len(delimiter)
    result = {}
    idx = 0
    while idx < len(s):
        if s[idx] == "v" and s[idx:idx+l]==delimiter:
            pos = idx + l
            re_ = re_vs_name.match(s, pos+1)
            vs_name = None
            if re_:
                vs_name = re_.group(1)
                r, end_idx = _nat_config_parser(s, re_.end()+1)
                result[vs_name] = r
                idx = end_idx
            else:
                idx = pos

        idx += 1

    return result

def _nat_config_dump(obj, indent="\t"):
    """Conver the map type obj to string"""
    result = "{\n"
    for k, v in obj.items():
        #exactlly bool true
        if v == True:
            result += indent + "%s\n" % k

        elif isinstance(v, str):
           result += indent + "%s %s\n" % (k, v)

        elif isinstance(v, dict):
            if k == "real_server":
                for sub_key, sub_val in v.items():
                    _items = sub_key.split(":")
                    result += indent + 'real_server %s %s ' % (_items[0], _items[1])
                    result += _nat_config_dump(sub_val, indent=indent+"\t")
            else:
                result += indent + "%s " % k
                result += _nat_config_dump(v, indent=indent+"\t")

    return result + indent[:-1] + "}\n"

def nat_config_dump(obj):
    """Conver the map type obj to string"""
    result = ""
    for k, v in obj.items():
        content = "virtual_server match %s " % k
        content += _nat_config_dump(v, indent="\t")
        result += content

    return result

class NatError(Exception):
    pass

class HashRing(object):

    def __init__(self, nodes=None, replicas=3):
        """Manages a hash ring.
        `nodes` is a list of objects that have a proper __str__ representation.
        `replicas` indicates how many virtual points should be used pr. node,
        replicas are required to improve the distribution.
        """
        self.replicas = replicas

        self.ring = dict()
        self._sorted_keys = []

        if nodes:
            for node in nodes:
                self.add_node(node)

    def add_node(self, node):
        """Adds a `node` to the hash ring (including a number of replicas).
        """
        for i in range(0, self.replicas):
            key = self.gen_key('%s:%s' % (node, i))
            self.ring[key] = node
            self._sorted_keys.append(key)

        self._sorted_keys.sort()


    def get_node(self, string_key):
        """Given a string key a corresponding node in the hash ring is returned.

        If the hash ring is empty, `None` is returned.
        """
        return self.get_node_pos(string_key)[0]

    def get_node_pos(self, string_key):
        """Given a string key a corresponding node in the hash ring is returned
        along with it's position in the ring.

        If the hash ring is empty, (`None`, `None`) is returned.
        """
        if not self.ring:
            return None, None

        key = self.gen_key(string_key)

        nodes = self._sorted_keys
        for i in range(0, len(nodes)):
            node = nodes[i]
            if key <= node:
                return self.ring[node], i

        return self.ring[nodes[0]], 0


    def gen_key(self, key):
        """Given a string key it returns a long value,
        this long value represents a place on the hash ring.

        md5 is currently used because it mixes well.
        """

        code = hashlib.md5(key.encode("utf-8")).hexdigest()
        return int(code[:8], 16)

class Command(object):
    """A command represents a shell tool"""
    def __init__(self, cmd_str):
        self.cmd = cmd_str

    def run(self):
        return execute_command(self.cmd)


class SysCommand(object):
    """ A set of system shell command utils."""
    
    def __init__(self, cmd_path="/usr/bin/", env="kernel"):
        self.path = os.path.abspath(cmd_path)
        self.env = env
    
    def ip_addr_add(self, device, ipaddress, *args):
        """Command to set ip address to device"""
        if self.env == "kernel":
            return Command(self.path 
                           + "/ip addr add '%s' dev '%s'" 
                           %  (ipaddress, device)
                           )

        elif self.env == "dpdk":
            return Command(self.path
                           + "/dpip addr add '%s' dev '%s'" 
                           %  (ipaddress, device)
                           )

    def ip_addr_del(self, device, ipaddress, *args):
        """Command to remove a ip address from device"""
        if self.env == "kernel":
            return Command(self.path 
                           + "/ip addr del '%s' dev '%s'"
                           %  (ipaddress, device)
                           )

        elif self.env == "dpdk":
            return Command(self.path
                           + "/dpip addr del '%s' dev '%s'" 
                           %  (ipaddress, device)
                           )

    def systemctl_reload(self, serivce, *args):
        """ Command Used systemcl to reload service"""
        return Command("systemctl reload '%s'" % serivce)


# We will store inside ip addresses to separate files with global pool name.
# The count of each global pool should be specified.
MAX_COMMON_ADDR_FILE_COUNT   = 10
MAX_SPECIAL_ADDR_FILE_COUNT  = 2

assert(MAX_COMMON_ADDR_FILE_COUNT < 100)
assert(MAX_SPECIAL_ADDR_FILE_COUNT < 10)

class NatService(object):
    
    def __init__(self, 
                 dpdk_path     = "/usr/local/dpvs",
                 config_path   = "/usr/local/dpvs/conf/server.d",
                 dpdk_bin_path = "/usr/local/dpvs/bin",
                 lan_nic       = "dpdk1",
                 wan_nic       = "dpdk0",
                 mgt_nic       = "em1",
                 keepalived_pid_file= "/etc/keepalived.pid",
                 global_pools  = ["common", "special"],
                 ):

        self.config_path = config_path

        self.keepalived_pid_file = keepalived_pid_file
                 
        # Commands for dpdk
        self.dpdk_tools = SysCommand(cmd_path=dpdk_bin_path, env="dpdk")

        # Commands for kernel
        self.kernel_tools = SysCommand(cmd_path="/usr/bin", env="kernel")

        # global ip pool for net address translation(NAT)
        self.global_pools = global_pools

        # Init a hash ring dict, whilch used to select a suitable 
        # file to store the inside ip address.
        self._hash = self._init_hashring()

        # The suffix of file which recorded the inside ip addresses, 
        # here we call it 'ipset'.
        self._ipset_suffix = ".iplist"

        # Upadted ipset filename records
        self._updated_ipset = None

        # New created ipset filename list.
        self._created_ipset = None 

        # Pool that updated when add or delete a nat rule.
        self._updated_pool = None

        # Pool that created when add or delete a nat rule.
        self._created_pool = None

        # Status wheather the nat configurationo updated. True of False.
        self._nat_updated = False 
        

    def _init_hashring(self):
        """Init a hash ring to store the filename prefix
        for each global pool. the filename prefix is used
        to create a ipset file on disk, and store the inside
        ip addresses.  
        """
        rings = {}
        for pool in self.global_pools:
            filename_prefix = []
            if pool == "common":
                count = MAX_COMMON_ADDR_FILE_COUNT
            else:
                count = MAX_SPECIAL_ADDR_FILE_COUNT

            for i in range(count):
                filename_prefix.append(pool + "_address_group_%02d" % i)

            rings[pool] = HashRing(filename_prefix, replicas=2)

        return rings

    def _set_ip_addr(self, device=None, ipaddress=None, env="kernel"):
        """Add a ip address to device, If env(environment) is kernel, it will use 
        'ip addr add' to set the ip address to the device.  If env is dpdk, it'll 
        use 'dpip addr add' instead.
        """
        if device is None or device == "":
            raise ValueError("Parameter device expect device name like 'lo' or 'dpdk0', but get '%s'." 
                            % device
                            )

        if ipaddress is None or ipaddress == "":
            raise ValueError("Parameter ipaddress expect ip address format string, but get '%s'."
                            % ipaddress
                            )

        if env == "kernel":
            cmd = self.kernel_tools.ip_addr_add(device, ipaddress)

        elif env == "dpdk":
            cmd = self.dpdk_tools.ip_addr_add(device, ipaddress)

        exit_code, output = cmd.run()

        if exit_code != 0:
            #TODO: replace the key words.
            if '????' in output or '????' in output:
                return True, output
            else:
                return False, output
        else:
            return True, output
        
    def set_ip_addr_dpdk(self, device, ipaddress):
        return self._set_ip_addr(device, ipaddress, "dpdk")

    def set_ip_addr_kernel(self, device, ipaddress):
        return self._set_ip_addr(device, ipaddress, "kernel")

    def reload_keepalived(self):
        with open(self.keepalived_pid_file, 'r') as pid:
            _pid = pid.read().strip()
            try:
                _pid = int(_pid)
            except:
                raise ValueError("Invalid keepalived pid number, expects a number but get '%s'." % _pid)
        
        if _pid > 0:
            cmd = self.kernel_tools.systemctl_reload(serivce="keepalived.service")

        exit_code, output = cmd.run()

        if exit_code != 0:
            return False, output
        
        return True, output

    def gen_ipset_prefix(self, pool, ipaddress):
        """Return the filename prefix the nat inside ip address will be 
        added to.
        """
        return self._hash[pool].get_node(ipaddress)

    def get_filename(self, ipset_prefix=None):
        """Return a filename include filename_prefix if the file exists in
        config_path floder. Make sure only one file in this folder with
        ipset_prefix, it only returns the first matched.
        Actually, we will generate a filename with a verison number like
        'comman_address_group_01_ver2020060501.conf' when file is updated 
        ervey time.
        """
        files = os.listdir(self.config_path)
        for file in files:
            # '.conf' is suffix of the file.
            p = ipset_prefix + r".+ver.+" + self._ipset_suffix
            if re.match(pattern=p, string=file):
                return file
        return None

    def add_rule(self, inside_addr, global_pool):
        """Add a nat rule for inside ip address. The global_pool is the 
        translated ips of inside address.We only return the filename 
        prefix of the file that rule will be write to.
        """

        if not is_ip(inside_addr):
            raise ValueError("The inside_addr need a exactly ipv4 address.")

        if not global_pool:
            raise ValueError("global pool should not be empty.")

        return self.gen_ipset_prefix(pool=global_pool, 
                                     ipaddress=inside_addr
                                    )

    def write_rule_batch(self, pairs):
        """Write the nat rule to a ipset file, which filename is generated by
        inside ip addrees and global pool name. Actually, it just write 
        the inside ip address to the given file, and rename filename with an
        special version tag. The new rule will take affect when reload nat 
        configuration.

        Parameter pairs is a dict mapped pool to ip addresses, 
        for example, 

        {
            "pool_name": [ipaddress1, ipaddress2, ...]
        }
        
        """
        prefix = dict()
        for pool, addresses in pairs.items():
            for addr in addresses:
                _hashed = self.gen_ipset_prefix(pool, addr)
                if _hashed in prefix:
                    prefix[_hashed] = list()
                prefix[_hashed].append(addr)

        self._upadted_ipset = dict()
        self._created_ipset = dict()

        version = "_ver%s" % time.strftime("%Y%m%d%H%M%S")
        #Start to wirte ip address to file.
        for file_prefix, addresses in prefix:
            if not addresses:
                continue

            file_write_to = self.get_filename(ipset_prefix=file_prefix)
            create_new_file = False 
            #Create a new file
            if file_write_to is None:
                file_write_to = file_prefix + version + self._ipset_suffix
                create_new_file = True

            file_with_path = os.path.join(self.config_path, file_write_to)

            with io.open(file_with_path, encoding="utf-8", mode='a+') as fw:
                fw.write("\n".join(addresses))
            
            if not create_new_file:
                new_filename = file_prefix + version + self._ipset_suffix
                new_file_with_path = os.path.join(self.config_path, new_filename)
                os.rename(file_with_path, new_file_with_path)

                #Recored the changged file, we'll use it to change the keepalived file.
                self._upadted_ipset[file_prefix] = {
                                        "old":file_with_path, 
                                        "new":new_file_with_path
                                        }
            else:
                if file_prefix not in self._created_ipset:
                    self._created_ipset[file_prefix] = list()
                self._created_ipset[file_prefix].append(file_write_to)

    def update_nat_config(self):
        """Update the NAT configuration files. These files are named with 
        global pool name. Example:
        'comman.conf', 'finacial.conf'.
        """
        if self._created_ipset or self._updated_ipset:
            self._nat_updated = True

        if not self._nat_updated:
            err_msg = "No ipset file is updated or created, skipped to update nat configuation."
            return False, NatError(err_msg)

        for file_prefix, updated_item in self._updated_ipset.items():
            nat_config_file = os.path.join(self.config_path, file_prefix) + ".conf"
            if not os.path.exists(nat_config_file):
                raise ValueError("The updateing nat configuration file '%s' dose not exsit!" % \
                                                                                nat_config_file
                                                                                )
            with io.open(nat_config_file, encoding="utf-8", mode="w") as fw:
                nat_cfg = fw.read()
                #TODO: replace the file content.
                fw.write(nat_cfg)

        for file_prefix, created_item in self._created_ipset.items():
            nat_config_file = os.path.join(self.config_path, file_prefix) + ".conf"

            with io.open(nat_config_file, encoding="utf-8", mode="w") as fw:
                nat_cfg_str = fw.read()
                #TODO: replace the file content.
                nat_cfg = self._parser_nat_config(nat_cfg_str)

                fw.write(nat_cfg_str)    

    def _parser_nat_config(self, config_string):
        if not config_string:
            raise ValueError("config_string should not be empty!")

        return nat_config_parser(config_string)


if __name__ == "__main__":
    keys = [
        "172.28.0.1",
        "172.28.0.2",
        "172.28.0.3",        
        "172.28.0.4",
        "172.28.0.5",
        "172.28.0.6",
        "172.28.0.7"
    ]
    nodes = ["Node_01", "Node_02", "Node_03"]
    ring = HashRing(nodes=nodes, replicas=3)
    for key in keys:
        print(ring.get_node_pos(key))
