DNS_DHCP_generator is the script generating configuration files for DNS and DHCP services based on provided data. The script reads information 
about VLANs and hosts from YAML configuration files and then generates configuration files for DNS and DHCP services based on this data.

## Here are some key points of the script:

* Configuration Loading: The script reads configuration files in YAML format containing information about VLANs and hosts.

* Configuration Generation for DNS and DHCP: The script iterates through the loaded information about VLANs and hosts and generates corresponding configuration files for DNS and DHCP services.

* Validation of IP and MAC Addresses: The script includes methods to validate the correctness of IP addresses and MAC addresses.

* Logging: The script logs warnings to a log file if it encounters invalid IP addresses or MAC addresses.

* File Manipulation: The script creates and writes configuration files for DNS and DHCP.

* Command-Line Arguments: The script allows specifying the -v switch for logging output to standard output.

## Here is example of input .yaml file:
```yaml
desktop.farm.particle.cz:
  192.168.1.17:
  - 08:00:27:AB:CD:EF
  fe80::a00:27ff:feab:cdef:
  - 08:00:27:AB:CD:EF
notebook.farm.particle.cz:
  10.0.0.20:
  - 00:1A:2B:3C:4D:5E
  fe80::021a:2bff:fe3c:4d5e:
  - 00:1A:2B:3C:4D:5E
```


## Here is description of dhcp_generator main config 
which contains configuration details for different VLANs, including network information, regular expressions for IP addresses, DNS settings, reverse DNS file names, DHCP configurations, and more. It serves as a template for generating DNS and DHCP configuration files based on VLAN information. Here's a breakdown:

* Puppet Directories: Specifies the directories for Puppet configuration and DNS-DHCP configuration.
* File Base: Specifies the base directory for files.
* VLANs: A dictionary containing details for each VLAN.
        Each VLAN is keyed by its identifier (e.g., '10.10.11').
        For each VLAN, the following details are provided:
* Network: CIDR notation for the VLAN's network.
* Regex: Regular expression for matching IP addresses in the VLAN.
* DNS: Boolean indicating whether DNS is enabled for the VLAN.
* Forward File: Filename for the forward DNS zone file.
* Forward Origins: List of forward DNS zone file origins.
* Reverse File: Filename for the reverse DNS zone file.
* Reverse Origins: List of reverse DNS zone file origins.
* DHCP Header: Dictionary containing DHCP configuration options.
* The script covers both IPv4 and IPv6 configurations.


```python
PUPPET_DIRECTORY = '/etc/puppetlabs/code/environments/production/'
HOSTS_DIRECTORY = '/etc/puppetlabs/code/environments/production/dns-dhcp/'

FILE_BASE = '/etc/puppetlabs/files/'

VLANS = {
    '10.10.11':{
      'network': '10.10.11.0/24',
      'regex': re.compile('0?10[\.]0?10[\.]0?11[\.]'),
      'dns': True,dns_dhcp_generator.py
      'fwd_file' : 'monitor.inside.zone',
      'fwd_origins': ['monitor.'],
      'rev_file' : '10.10.11.inside.revzone',
      'rev_origins': [ '10.10' ],
      'dhcp_header': {
          'option subnet-mask': '255.255.255.0',
          'option domain-name': 'monitor',
          'option domain-name-servers': [ '10.10.11.5', '10.10.11.4' ],
          'option log-servers': [ '10.10.11.8' ],
          'option ntp-servers': [ '10.10.11.5', '10.10.11.4' ],
          'default-lease-time': 31557600,
          'min-lease-time': 31557600,
      },
    },
    '10.30'       : {  #zde bude pouze origin 10.30
      'network': '10.30.0.0/16',
      'regex'   : re.compile('0?10[\.]0?30[\.]'),
      'dns'     : True,
      'fwd_file': 'example2.example1.cz.inside.zone',
      'fwd_origins': ['example2.example1.cz.'],
      'rev_file': '10.30.inside.revzone',
      'rev_origins': [ '30.10' ],
      'dhcp_header': {
          'option subnet-mask': '255.255.0.0',
          'option routers': [ '10.30.0.39' ],
          'option domain-name': 'example2.example1.cz',
          'option domain-name-servers': [ '10.30.0.37', '10.30.0.38' ],
          'option log-servers': [ '147.231.25.201' ],
          'option ntp-servers': [ '10.30.0.37', '10.30.0.38' ],
          'allow': 'unknown-clients',
          'range': '10.30.0.64 10.30.0.253',
          'default-lease-time': 31557600,
          'min-lease-time': 31557600,
          'include': '"/etc/dhcp/dhcpd.mff-next-server.conf"',
      },
    },
    '10.6.51': {
      'network': '10.6.51.0/24',
      'regex'   : re.compile('0?10[\.]0?0?6[\.]0?51[\.]'),
      'dns'     : False,
      'dhcp_header': {
          'option subnet-mask': '255.255.255.0',
          'option domain-name': 'monitor',
          'option domain-name-servers': [ '10.6.51.2' ],
          'option log-servers': [ '10.6.51.2' ],
          'option ntp-servers': [ '10.6.51.2' ],
          'default-lease-time': 31557600,
          'min-lease-time': 31557600,
      },
    },
    '172.16'      : { # zde pouze origin 172.16
      'network': '172.16.0.0/16',
      'regex'   : re.compile('172[\.]0?16[\.]'),
      'dns'     : True,
      'fwd_file': 'example2.example1.cz.inside.zone',
      'fwd_origins': [ 'example2.example1.cz.' ],
      'rev_file': '172.16.inside.revzone',
      'rev_origins': [ '16.172', ],
      'dhcp_header': {
          'option domain-name': 'example2.example1.cz',
          'option domain-name-servers': [ '172.16.0.16', '172.16.0.15' ],
          'option interface-mtu': 1500,
          'option log-servers': [ '172.16.0.201' ],
          'option ntp-servers': [ '172.16.0.16', '172.16.0.15' ],
          'option domain-search': [ "example2.example1.cz", "example3.cz" ],
          'default-lease-time': 31557600,
          'min-lease-time': 31557600,
          'option routers': '172.16.0.39',
          'include': '"/etc/dhcp/dhcpd.wn-next-server.conf"',
      },
    },
    '192.168'     : {  # zde pouze origin 192.168
      'network': '192.168.0.0/16',
      'regex'    : re.compile('192[\.]168[\.]'),
      'dns'      : True,
      'fwd_file': 'monitor.inside.zone',
      'fwd_origins': [ 'monitor.' ],
      'rev_file': '192.168.inside.revzone',
      'rev_origins': [ '168.192', ],
      'dhcp_header': {
          'option domain-name': 'monitor',
          'option domain-name-servers': [ '192.168.1.5', '192.168.1.38' ],
          'option interface-mtu': 1500,
          'option log-servers': [ '192.168.1.34' ],
          'option ntp-servers': [ '192.168.1.5', '192.168.1.38' ],
          'option domain-search': [ "monitor" ],
          'default-lease-time': 31557600,
          'min-lease-time': 31557600,
      },
    },
    2001:db8:3333:4444:5555:6666:7777:8888
    '3333'     : {
      'network' : '2001:db8:3333:1::/64',
      'regex'   : re.compile('2001:db8:3333:0?0?0?1:'),
      'dns'     : False,
      'dhcp_header' : {
        'option dhcp6.name-servers': [ '2001:db8:3333:6025:1::20', '2001:db8:3333:6025:1::19' ],
        'option dhcp6.domain-search': [ 'example2.example1.cz', 'example3.cz' ],
        'option dhcp6.info-refresh-time': 21600,
        'option log-servers': [ 'syslog.example2.example1.cz' ],
        'option dhcp6.sntp-servers' : [ '2001:db8:3333:6025:1::20', '2001:db8:3333:6025:1::19' ],
        'default-lease-time': 31557600,
        'min-lease-time': 31557600,
        'preferred-lifetime': 23668200,
        'include': '"/etc/dhcp/dhcpd.farm-next-server.conf"',
      },
    },


   
    }
```


## How to execute script:
python3 dns_dhcp_generator.py
