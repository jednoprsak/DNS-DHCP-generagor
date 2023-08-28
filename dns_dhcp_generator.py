#!/usr/bin/python3
import yaml
import os
import re
import ipaddress
import logging
import sys
import macaddress
import json
import time
import copy
from dns_dhcp_generator_conf import *


if '-v' in sys.argv:
  print('I am writing log to stdout.')

IN: str = 'IN'.ljust(7)
PTR: str = f'{IN} PTR'.ljust(15)
CNAME: str = f'{IN} CNAME'.ljust(15)
A: str = f'{IN} A'.ljust(15)
AAAA: str = f'{IN} AAAA'.ljust(15)
ENTRY_JUST: int = 33
ORIGIN: str = '$ORIGIN'.ljust(ENTRY_JUST)


def load_host_files(hosts_directory):
  merged_dictionary = {}
  for file in os.listdir(hosts_directory):
    if file.endswith(".yaml") or file.endswith(".yml"):
      with open(HOSTS_DIRECTORY + file, 'r') as yaml_host_file:
            volatile_dict = yaml.safe_load(yaml_host_file)
            # print(volatile_dict)
            merged_dictionary = merged_dictionary.copy()
            merged_dictionary.update(volatile_dict) #je potřeba otestovat tuto část

  return merged_dictionary


class DNS_FZU_RECORDS:
  def __init__(self, vlans, hosts, file_base, puppet_directory):
    self.vlans_dict = vlans
    self.hosts_dict = hosts
    self.file_base = file_base
    self.puppet_directory = puppet_directory
    self.origins_dict = {}
    self.files_dict = {}
    self.drawed_up_files = {}
    self.dns_files = self.collect_file_names(self.vlans_dict)
    self.create_dns_directories()
    self.fill_files_dict()
    self.iterate_and_organize_data()
    # print(json.dumps(self.files_dict, indent=4))
    self.draw_up_zonefiles()
    self.write_zonefiles()
    self.make_particle_cz_static()

  def collect_file_names(self, vlan_dict):
    files = list()
    for vlan in vlan_dict.keys():
        for filet in ['rev_file', 'fwd_file']:
            if filet in vlan_dict[vlan].keys():
                if isinstance(vlan_dict[vlan][filet], list):
                    for entry in vlan_dict[vlan][filet]:
                        if entry not in files:
                            files.append(entry)
                else:
                    if vlan_dict[vlan][filet] not in files:
                        files.append(vlan_dict[vlan][filet])
    return sorted(files)


  def Validate_IPv4(self, ipv4Address):
    try:
        ipaddress.IPv4Network(ipv4Address)
        return True
    except ValueError as errorcode:
        pass
        return False


  def Validate_IPv6(self, ipv6Address):
    try:
        ipaddress.IPv6Network(ipv6Address)
        return True
    except ValueError as errorcode:
        pass
        return False


  def create_dns_directories(self):
    for directory in [ 'dns' ]:
      os.makedirs(self.file_base + directory , mode = 0o755, exist_ok = True)


  def fill_files_dict(self):

    for file in self.dns_files:
      self.files_dict[file] = {
        'header1': open(self.puppet_directory
          + 'fzu-files/dns-dhcp-generator/templates/dns_'
          + file + '.header1.tmpl', 'r').read(),
        'header2': open(self.puppet_directory
          + 'fzu-files/dns-dhcp-generator/templates/dns_'
          + file + '.header2.tmpl', 'r').read(),
        }



      if 'inside' in file:
        self.files_dict[file]['private'] = True
      elif 'outside' in file:
        self.files_dict[file]['private'] = False
      elif 'common' in file:
        self.files_dict[file]['private'] = False
      else:
        self.files_dict[file]['private'] = False

      if 'revzone' in file:
        self.files_dict[file]['zone_type'] = 'rev'
        self.files_dict[file]['rev_origins'] = {}
      else:
        self.files_dict[file]['zone_type'] = 'fwd'

      self.files_dict[file]['networks'] = []
      self.files_dict[file]['origins'] = {}


      for vlan in self.vlans_dict:
        if self.vlans_dict[vlan]['dns'] == True:
          if file in self.vlans_dict[vlan]['fwd_file']:
            for origin in self.vlans_dict[vlan]['fwd_origins']:
              if origin not in self.files_dict[file]['origins']:
                self.files_dict[file]['origins'][origin] = { 'hosts':{} }
            if ':' in self.vlans_dict[vlan]['network']:
                if self.Validate_IPv6(self.vlans_dict[vlan]['network']):
                  self.files_dict[file]['networks'].append(self.vlans_dict[vlan]['network'])
                else:
                  continue
            else:
                if self.Validate_IPv4(self.vlans_dict[vlan]['network']):
                  self.files_dict[file]['networks'].append(self.vlans_dict[vlan]['network'])
                else:
                  continue



          if file in self.vlans_dict[vlan]['rev_file']:
            # overit pomoci ipaddress, jestli je sit validni ip, nyní se to ověřuje v třídící funkci

            if ':' in self.vlans_dict[vlan]['network']:
                # print(self.Validate_IPv6(self.vlans_dict[vlan]['network']))
                if self.Validate_IPv6(self.vlans_dict[vlan]['network']):
                  self.files_dict[file]['networks'].append(self.vlans_dict[vlan]['network'])
                else:
                  continue
            else:
                # print(self.Validate_IPv4(self.vlans_dict[vlan]['network']))
                if self.Validate_IPv4(self.vlans_dict[vlan]['network']):
                  self.files_dict[file]['networks'].append(self.vlans_dict[vlan]['network'])
                else:
                  continue
            self.files_dict[file]['networks'].append(self.vlans_dict[vlan]['network'])
            if 'special_reverse_origin' in self.vlans_dict[vlan].keys():
              self.files_dict[file]['special_reverse_origin'] = self.vlans_dict[vlan]['special_reverse_origin']


  def make_reverse_ipv4_origin(self, ip, octets=2):
      split_ip = ip.split(".")
      split_ip.reverse()
      # print(split_ip)
      if octets == 2:
        del(split_ip[0])
        del(split_ip[0])
      elif octets == 3:
        del(split_ip[0])
      elif octets == 1:
        del(split_ip[0])
        del(split_ip[0])
        del(split_ip[0])

      reverse_ip = split_ip
      reverse_origin = ''
      for o in reverse_ip:
        if reverse_origin != '':
          reverse_origin += '.'
        reverse_origin += o

      return reverse_origin

  def save_record(self, origin_field, origin, host, zonefile, record):
      if origin in self.files_dict[zonefile][origin_field]:
        if host in self.files_dict[zonefile][origin_field][origin]['hosts'].keys():
          if record not in self.files_dict[zonefile][origin_field][origin]['hosts'][host]['records']:
            self.files_dict[zonefile][origin_field][origin]['hosts'][host]['records'].append(record)
        else:
          self.files_dict[zonefile][origin_field][origin]['hosts'][host] = { 'records': [ record ] }
      else:
        self.files_dict[zonefile][origin_field][origin] = { 'hosts': { host: {'records': [ record ],} } }


  def mac2eui64(self, mac):
      '''
      Convert a MAC address to a EUI64 address
      or, with prefix provided, a full IPv6 address
      '''
      # http://tools.ietf.org/html/rfc4291#section-2.5.1
      eui64 = re.sub(r'[.:-]', '', mac).lower()
      eui64 = eui64[0:6] + 'fffe' + eui64[6:]
      eui64 = hex(int(eui64[0:2], 16) ^ 2)[2:].zfill(2) + eui64[2:]

      eui64_list = list(eui64)
      eui64_list.reverse()
      eui64_mac_reverse = '.'.join(eui64_list)
      return eui64_mac_reverse


  def organize_ipv4_record(self, zonefile, host, ip):
      host_name, origin = host.split(".", 1)
      origin += "."
      for network in self.files_dict[zonefile]['networks']:
        if ':' in network:
          continue
        if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(network):
           reverse_origin = self.make_reverse_ipv4_origin(ip, 3)
           record = f'{host_name.ljust(ENTRY_JUST)} {A} {str(ip)}'
           reverse = (
            f'{(ipaddress.IPv4Address(str(ip)).reverse_pointer).split(".")[0].ljust(ENTRY_JUST)} {PTR} {host}.')
           if self.files_dict[zonefile]['zone_type'] == 'fwd':
            self.save_record('origins', origin, host, zonefile, record)

           elif self.files_dict[zonefile]['zone_type'] == 'rev':
            if 'special_reverse_origin' in self.files_dict[zonefile].keys():
              special_reverse_origin = self.files_dict[zonefile]['special_reverse_origin']
              self.save_record('rev_origins', special_reverse_origin, host, zonefile, reverse)
            else:
              self.save_record('rev_origins', reverse_origin, host, zonefile, reverse)



  def organize_ipv6_record(self, zonefile,host, ip, rrd = False):
    host_name, origin = host.split(".", 1)
    origin += "."
    element_type = 'ipv6'
    for network in self.files_dict[zonefile]['networks']:
      if ':' not in network:
        continue
      if ipaddress.IPv6Address(ip) in ipaddress.IPv6Network(network):
          address_first_half = ipaddress.IPv6Address(ip).exploded[0:19]
          reverse_ip_host_part, reverse_origin = self.create_two_part_ipv6_reverse(
                ip, address_first_half
          )
          record = (
              f'{host_name.ljust(ENTRY_JUST)} {AAAA} {ipaddress.IPv6Address(str(ip)).exploded}'
          )
          reverse = f'{reverse_ip_host_part.ljust(ENTRY_JUST)} {PTR} {host}.'
          # zde vytvorit cyklus prochazejici mac adresy
          #(drive se s mac adresami nepracovalo,potrebujeme s nimi pracovat kvuli slaac eui-64 adrese)
          # pro kazdou mac adresu ipv6 adresy se vytvori eui64 reverz, jako cast prefixu se pouzije address_first_half
          if not rrd:
            for mac in self.hosts_dict[host][ip]:
              eui64_reverse = f'{self.mac2eui64(mac).ljust(ENTRY_JUST)} {PTR} {host}.'
              if self.files_dict[zonefile]['zone_type'] == 'rev':
                self.save_record('rev_origins', reverse_origin, host, zonefile, eui64_reverse)


          if self.files_dict[zonefile]['zone_type'] == 'fwd':
            self.save_record('origins', origin, host, zonefile, record)
          elif self.files_dict[zonefile]['zone_type'] == 'rev':
            self.save_record('rev_origins', reverse_origin, host, zonefile, reverse)



  def iterate_and_organize_data(self):
    for zonefile in self.files_dict.keys():
      for host in self.hosts_dict.keys():
        for ip in self.hosts_dict[host].keys():
          if ':' in ip:
              if not self.Validate_IPv6(ip):
                continue
              self.organize_ipv6_record(zonefile, host, ip)

          elif '.' in ip:
              if not self.Validate_IPv4(ip):
                continue
              self.organize_ipv4_record(zonefile, host, ip)

          elif 'cname' in ip:
            element_type = 'cname'
            for name in self.hosts_dict[host][ip]:
              host_name, origin = name.split(".", 1)
              origin += '.'
              for file_origin in self.files_dict[zonefile]['origins'].keys():
                if origin == file_origin:
                  record = f'{host_name.ljust(ENTRY_JUST)} {CNAME} {host}.'
                  if origin in self.files_dict[zonefile]['origins']:
                      # print(self.files_dict[zonefile]['origins'])
                      if host in self.files_dict[zonefile]['origins'][origin]['hosts'].keys():
                        if record not in self.files_dict[zonefile]['origins'][origin]['hosts'][host]['records']:
                          self.files_dict[zonefile]['origins'][origin]['hosts'][host]['records'].append(record)
                      else:
                        self.files_dict[zonefile]['origins'][origin]['hosts'][host] = {'records': [ record ] }
                  else:
                      self.files_dict[zonefile]['origins'][origin] = { 'hosts':{host:{'records': [ record ] } } }

          elif 'rrdalias' in ip:
            element_type = 'rrdalias'
            for rrdhost in self.hosts_dict[host][ip]:
              for second_ip in self.hosts_dict[host].keys():
                if ':' in second_ip:
                  self.organize_ipv6_record(zonefile, rrdhost, second_ip, True)
                elif '.' in second_ip:
                  self.organize_ipv4_record(zonefile, rrdhost, second_ip)
                else:
                  continue

          elif 'notes' in ip:
            continue
            print('There is notes record. SKIPPING.. for dns class')
          elif 'dhcp_include' in ip:
            continue
            print('There is dhcp_include. SKIPPING.. for dns class')
          else:
            print('unpredictable condition: ip is ' + str(ip))



  def draw_up_zonefiles(self):
    for zonefile in self.files_dict.keys():
      header = (
        self.files_dict[zonefile]['header1'] + '\n'
        + str(self.make_serial_line()) + '\n'
        + self.files_dict[zonefile]['header2'] + '\n\n\n'
      )

      record_part = ''

      if 'origins' in self.files_dict[zonefile].keys():
        for origin in self.files_dict[zonefile]['origins'].keys():

          if self.files_dict[zonefile]['zone_type'] == 'fwd':
            record_part += f'\n\n{ORIGIN} {origin}\n'
          elif self.files_dict[zonefile]['zone_type'] == 'rev':
            if any(map(lambda x:':' in x, self.files_dict[zonefile]['networks'])):
              record_part += f'\n\n{ORIGIN} {origin}.ip6.arpa.\n'
            else:
              record_part += f'\n\n{ORIGIN} {origin}.in-addr.arpa.\n'

          for host in self.files_dict[zonefile]['origins'][origin]['hosts'].keys():
              for record in self.files_dict[zonefile]['origins'][origin]['hosts'][host]['records']:
                  record_part += record + '\n'


      if 'rev_origins' in self.files_dict[zonefile].keys():
        for rev_origin in self.files_dict[zonefile]['rev_origins'].keys():

          if self.files_dict[zonefile]['zone_type'] == 'fwd':
            record_part += f'\n\n{ORIGIN} {rev_origin}\n'
          elif self.files_dict[zonefile]['zone_type'] == 'rev':
            if any(map(lambda x:':' in x, self.files_dict[zonefile]['networks'])):
              record_part += f'\n\n{ORIGIN} {rev_origin}.ip6.arpa.\n'
            else:
              record_part += f'\n\n{ORIGIN} {rev_origin}.in-addr.arpa.\n'

          for host in self.files_dict[zonefile]['rev_origins'][rev_origin]['hosts'].keys():
            for record in self.files_dict[zonefile]['rev_origins'][rev_origin]['hosts'][host]['records']:
                record_part += record + '\n'


      if 'for_print' in self.files_dict[zonefile].keys():
        self.files_dict[zonefile]['for_print'] += record_part
      else:
        self.files_dict[zonefile]['for_print'] = header
        self.files_dict[zonefile]['for_print'] += record_part
      # print(self.files_dict[zonefile]['for_print'])


  def write_zonefiles(self):
    for fil in self.files_dict.keys():
      fil_str = self.files_dict[fil]['for_print']
      # print(fil_str)
      duf = open(self.file_base + '/dns/' + fil, 'w')
      duf.write(fil_str)
      duf.write('\n')
      duf.close()


  def create_two_part_ipv6_reverse(self, ip_address, origin):
    origin_list = []
    for a in origin:
      if a == ':':
        continue
      origin_list.append(a)

    origin_list.reverse()
    reverse_origin_list = origin_list
    reverse_ip = ipaddress.IPv6Address(ip_address).reverse_pointer

    reverse_ip_list = []
    for a in reverse_ip:
      if a == '.':
        continue
      reverse_ip_list.append(a)

    reverse_ip_host_part = (reverse_ip_list[:(((len(reverse_ip_list)-7)) - len(reverse_origin_list))])

    reverse_ip_host_part_points = []
    for a in reverse_ip_host_part:
      reverse_ip_host_part_points.append(a)
      reverse_ip_host_part_points.append('.')

    reverse_ip_host_part_string = ''.join(reverse_ip_host_part_points[0:31])

    reverse_origin_list_points = []
    for a in reverse_origin_list:
      reverse_origin_list_points.append(a)
      reverse_origin_list_points.append('.')

    reverse_origin_string = (''.join(reverse_origin_list_points[0:31]))

    return (reverse_ip_host_part_string, reverse_origin_string)


  def make_serial_line(self):
    serial_line = f'{" ".ljust(31)} {str(int(time.time())).ljust(11)} ; serial'
    return serial_line

  def make_particle_cz_static(self):
    header1 = open(self.puppet_directory
          + 'fzu-files/dns-dhcp-generator/templates/dns_'
          + 'particle.cz.zone' + '.header1.tmpl', 'r').read()

    header2 = open(self.puppet_directory
          + 'fzu-files/dns-dhcp-generator/templates/dns_'
          + 'particle.cz.zone' + '.header2.tmpl', 'r').read()

    content = (
        header1 + '\n'
        + str(self.make_serial_line()) + '\n'
        + header2 + '\n\n\n'
    )

    zonefile = open(self.file_base + '/dns/' + 'particle.cz.zone', 'w')
    zonefile.write(content)
    zonefile.write('\n')
    zonefile.close()



class DHCP_FZU_RECORDS:
  def __init__(self, vlans, hosts, file_base, puppet_directory):
    self.vlans_dict = vlans
    self.hosts_dict = hosts
    self.file_base = file_base
    self.puppet_directory = puppet_directory
    self.create_dhcp_directories()
    self.v4_config_header = open(
      self.puppet_directory
      + 'fzu-files/dns-dhcp-generator/templates/dhcp_v4_config_header.tmpl',
       'r').read()
    self.v6_config_header = open(
      self.puppet_directory
      + 'fzu-files/dns-dhcp-generator/templates/dhcp_v6_config_header.tmpl',
       'r').read()
    self.v4_record = open(
      self.puppet_directory
      + 'fzu-files/dns-dhcp-generator/templates/dhcp_v4_record.tmpl',
      'r').read()
    self.v6_record = open(
      self.puppet_directory
      + 'fzu-files/dns-dhcp-generator/templates/dhcp_v6_record.tmpl',
      'r').read()
    self.v4_includes = '\n\n\n'
    self.v6_includes = '\n\n\n'
    self.dhcpdconf = open(self.file_base + 'dhcp/dhcpd.conf', 'w')
    self.dhcpd6conf = open(self.file_base + 'dhcp/dhcpd6.conf', 'w')
    self.create_dhcp_directories()
    self.iterate_vlans_and_create_files()
    self.iterate_make_records_fill_files()


  def Validate_IPv4(self, ipv4Address):
    try:
        ipaddress.IPv4Network(ipv4Address)
        return True
    except ValueError as errorcode:
        pass
        return False


  def Validate_IPv6(self, ipv6Address):
    try:
        ipaddress.IPv6Network(ipv6Address)
        return True
    except ValueError as errorcode:
        pass
        return False


  def Validate_mac(self, mac_address):
    try:
       macaddress.MAC(mac_address)
       return True
    except ValueError as error:
      pass
      return False


  def create_dhcp_directories(self):
    for directory in ['dhcp','dhcp/dhcpd','dhcp/dhcpd6']:
      os.makedirs(self.file_base + directory , mode = 0o755, exist_ok = True)

  def prepare_header_for_vlan_file(self, vlan_file, vlan_values, ip_version):
    if ip_version == 'ipv4':
      network_class4 = ipaddress.IPv4Network(vlan_values['network'])
      netmask4 = network_class4.netmask
      network4 = network_class4.network_address
      first_line = 'subnet ' + str(network4) + ' netmask ' + str(netmask4) + ' {\n'

    elif ip_version == 'ipv6':
      first_line = 'subnet6 ' + vlan_values['network'] + ' {\n'

    middle = ''

    for key, value in vlan_values['dhcp_header'].items():
      # print(value)
      value_line = ''
      if type(value) == list:
          # print("value is list")
          for item in value:
            # print(item)
            if value.index(item) == (len(value)-1):
              if key in ('option dhcp6.domain-search', 'option domain-search'):
                value_line += '\"' + item + '\"' + ';\n'
              else:
                value_line += item + ';\n'
            else:
              if key in ('option dhcp6.domain-search', 'option domain-search'):
                value_line += '\"' + item + '\"' + ', '
              else:
                value_line += item + ', '
      elif type(value) == str:
          if key in ('option domain-name', 'option domain-search'):
            # print(key)
            value_line += '\"' + value + '\"' + ';\n'
          else:
            value_line += value + ';\n'
      elif type(value) == int:
          value_line += str(value) + ';\n'
      line = '   ' + key.ljust(45) + value_line
      middle += line

    last_line = "}\n\n"

    dhcp_header_drawed_up = first_line + middle + last_line
    vlan_file.write(dhcp_header_drawed_up)




  def iterate_vlans_and_create_files(self):
    for vlan_name, vlan_values in self.vlans_dict.items():
      if '.' in vlan_name:
        self.vlans_dict[vlan_name]['vlan_type'] = 'ipv4'
        vlan_file_path_inside = '"/etc/' + 'dhcp/dhcpd/' + vlan_name + '.dhcpd.conf"'
        vlan_file_path = self.file_base + 'dhcp/dhcpd/' + vlan_name + '.dhcpd.conf'
        self.vlans_dict[vlan_name]['vlan_file_path'] = vlan_file_path_inside
        vlan_file = open(vlan_file_path, 'w')
        # zde bude write pro dhcp_header
        self.prepare_header_for_vlan_file(vlan_file, vlan_values, 'ipv4')
        vlan_file.write('group {\n')
        vlan_file.close()
        include_line = 'include    ' + vlan_file_path_inside + ';' + '\n'
        self.v4_includes = self.v4_includes + include_line
      else:
        self.vlans_dict[vlan_name]['vlan_type'] = 'ipv6'
        vlan_file_path_inside = '"/etc/' + 'dhcp/dhcpd6/' + vlan_name + '.dhcpd6.conf"'
        vlan_file_path = self.file_base + 'dhcp/dhcpd6/' + vlan_name + '.dhcpd6.conf'
        self.vlans_dict[vlan_name]['vlan_file_path'] = vlan_file_path_inside
        vlan_file = open(vlan_file_path, 'w')
        self.prepare_header_for_vlan_file(vlan_file, vlan_values, 'ipv6')
        vlan_file.write('group {\n')
        vlan_file.close()
        include_line = 'include    ' + vlan_file_path_inside + ';' + '\n'
        self.v6_includes = self.v6_includes + include_line
    v4_config = open(self.file_base + 'dhcp/dhcpd.conf', 'w')
    v4_config.write(self.v4_config_header)
    v4_config.write(self.v4_includes)
    v4_config.close()
    v6_config = open(self.file_base + 'dhcp/dhcpd6.conf', 'w' )
    v6_config.write(self.v6_config_header)
    v6_config.write(self.v6_includes)
    v6_config.close()


  def iterate_make_records_fill_files(self):
    """This function iterates hosts and vlans,
       makes records, and fill propper dhcp
       conf files."""
    for host in self.hosts_dict.keys():
      for ip in self.hosts_dict[host].keys():
        if '.' in ip:
          if not self.Validate_IPv4(ip):
            logging.basicConfig(
              filename='/var/log/dns-dhcp-generator.log', format='%(asctime)s %(message)s'
            )
            logging.warning(str(ip) + ' for host ' + host + ' is not valid.')
            if '-v' in sys.argv:
              print(str(ip) + ' for host ' + host + ' is not valid.')
            continue
        elif ':' in ip:
          if not self.Validate_IPv6(ip):
            logging.basicConfig(
              filename='/var/log/dns-dhcp-generator.log', format='%(asctime)s %(message)s'
            )
            logging.warning(str(ip) + ' for host ' + host + ' is not valid.')
            if '-v' in sys.argv:
              print(str(ip) + ' for host ' + host + ' is not valid.')
            continue
        # elif ip == 'dhcp_include':
        #   include_block = ''
          # for include_line in self.hosts_dict[host][ip]:
          #   include_block += '                include \"' + include_line + '\";\n'
          # if include_block != '':
          #   include_prepared = include_block
          #   print(include_prepared)

        for vlan in self.vlans_dict.keys():
            if self.vlans_dict[vlan]['regex'].search(ip):
              if self.vlans_dict[vlan]['vlan_type'] == 'ipv4':
                for mac in self.hosts_dict[host][ip]:
                  if not self.Validate_mac(mac):
                    logging.basicConfig(
                      filename='/var/log/dns-dhcp-generator.log', format='%(asctime)s %(message)s'
                    )
                    logging.warning(str(mac) + ' for host ' + host + ' and ip ' + str(ip) + ' is not valid.')
                    if '-v' in sys.argv:
                      print(str(mac) + ' for host ' + host + ' and ip ' + str(ip) + ' is not valid.')
                  mac_id = str(''.join(mac.split(':')[4:]))
                  vlan_file = open((self.vlans_dict[vlan]['vlan_file_path'].replace('/etc/', '/etc/puppetlabs/files/')).replace('\"',''), 'a')
                  record_body = self.v4_record % (
                    host.split('.')[0], vlan, mac_id, mac,
                    ip, host
                    )
                  if 'dhcp_include' in self.hosts_dict[host].keys():
                    for include_line in self.hosts_dict[host]['dhcp_include']:
                       record_body += '                include \"' + include_line + '\";\n'

                  # if 'include_prepared' in locals():
                  #   record_body += include_prepared
                  #   del include_prepared

                  record_body += '        }\n'

                  vlan_file.write(record_body)
                  vlan_file.close()
              elif self.vlans_dict[vlan]['vlan_type'] == 'ipv6':
                for mac in self.hosts_dict[host][ip]:
                  mac_id = str(''.join(mac.split(':')[4:]))
                  vlan_file = open((self.vlans_dict[vlan]['vlan_file_path'].replace('/etc/', '/etc/puppetlabs/files/')).replace('\"',''), 'a')
                  vlan_file.write(self.v6_record % (
                    host.split('.')[0], vlan, mac_id, mac,
                    ip, self.vlans_dict[vlan]['network'], host
                  ))
                  vlan_file.close()



    for vlan in self.vlans_dict.keys():
      vlan_file = open((self.vlans_dict[vlan]['vlan_file_path'].replace('/etc/', '/etc/puppetlabs/files/')).replace('\"',''), 'a')
      vlan_file.write('}')
      vlan_file.write('\n\n')
      vlan_file.close()



if __name__ == "__main__":
  HOSTS = load_host_files(HOSTS_DIRECTORY)
  dhcp_obj = DHCP_FZU_RECORDS(VLANS, HOSTS, FILE_BASE, PUPPET_DIRECTORY)
  dns_obj = DNS_FZU_RECORDS(VLANS, HOSTS, FILE_BASE, PUPPET_DIRECTORY)

