#!/usr/bin/env python3

"""
Cisco SSL VPN Heaven for macOS.
Intended to use with openconnect + Cisco SSL VPN.

Problem:
- VPN server configuration doesn't allow split tunneling which results in
default gateway being changed to VPN's one.
- Therefore default traffic is being routed through VPN gateway which results
in inability to access local/corporate network hosts/printer services etc.
- Cisco AnyConnect Agent Daemon monitors routing table and rewrites any manual
changes.

Solution:
- Since openconnect doesn't have any agent monitoring routing table, it and
other system configuration like WINS/DNS servers can be rewritten and reverted
back to previous state without breaking VPN connection.
- Moreover default gateway can be easily changed with several precautions:
    * TODO

TODO:
- Add docstrings.
- Add more logging.
- Move some constants to config file.
- Make ASN_REGEX a configurable list to support multiple organizations/ISPs.
- Add support of IPv6 ASN networks.
- Get rid of bash commands filtering (most time consuming).
---------------------------
Rewritten from my routes.sh
"""

import argparse
import csv
import inspect
import json
import logging
import os
import re
import subprocess
import sys
import zipfile
from functools import wraps
from io import BytesIO, TextIOWrapper
from pathlib import Path

import requests

BANNER = r"""

   _____ _____  _____  _____ ____
  / ____|_   _|/ ____|/ ____/ __ \
 | |      | | | (___ | |   | |  | |
 | |      | |  \___ \| |   | |  | |
 | |____ _| |_ ____) | |___| |__| |
  \_____|_____|_____/ \_____\____/
  / ____/ ____| |
 | (___| (___ | |
  \___ \\___ \| |
  ____) |___) | |____
 |_____/_____/|______|_
 \ \    / /  __ \| \ | |
  \ \  / /| |__) |  \| |
   \ \/ / |  ___/| . ` |
    \  /  | |    | |\  |
  _  \/_ _|_|__  |_|_\_|    ________ _   _
 | |  | |  ____|   /\ \    / /  ____| \ | |
 | |__| | |__     /  \ \  / /| |__  |  \| |
 |  __  |  __|   / /\ \ \/ / |  __| | . ` |
 | |  | | |____ / ____ \  /  | |____| |\  |
 |_|  |_|______/_/    \_\/   |______|_| \_|


"""

# From /etc/resolv.conf: "search <search_domain>"
CORPORATE_SEARCH_DOMAIN = ''

# Internal networks which will be routed through VPN interface
INTERNAL_IPS = []

# Dict, list of IP networks: {<network_name>: ['x.x.x.x', ...], ...}
VPN_NETWORKS = {}

ASN_REGEX = r'\b\b'
ASN_NETWORKS_FILE = ''

# Deprecated, now non issue.
QRATOR_IPS_FILE = 'qrator_ips.txt'

RESOLVER_DIR = '/etc/resolver'
DNS_CONF = {'vpn': [],
            'corporate': []}

# Emoji in bytes from https://apps.timwhitlock.info/emoji/tables/unicode
POO = b'\xF0\x9F\x92\xA9'.decode('utf-8')
HEART = b'\xE2\x9D\xA4'.decode('utf-8')

ASN_ARCHIVE_URL = 'https://geolite.maxmind.com/download/geoip/database/GeoLite2-ASN-CSV.zip'
GEOLITE_IPV4_CSV_FILENAME = 'GeoLite2-ASN-Blocks-IPv4.csv'
GEOLITE_IPV6_CSV_FILENAME = 'GeoLite2-ASN-Blocks-IPv6.csv'

INTERFACES = {'wifi': 'Wi-Fi', 'ether': 'Ethernet'}

EXIT_OK = 0
EXIT_ERROR = 1


def verify_result(func):
    """Decorator to check if result isn't empty."""
    @wraps(func)
    def verify_result_wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        _log = args[0]._log
        if not result:
           err_msg = f'[{func.__name__}] - Got empty result. Aborting'
           _log.error(err_msg)
           sys.exit(err_msg)
        return result
    return verify_result_wrapper


class CiscoSSLVPNHeavenError(Exception):
    """Base exception."""
    pass


class CiscoSSLVPNHeaven:
    """Cisco SSL VPN Heaven."""
    def __init__(self):
        self._log = logging.getLogger('CiscoSSLVPNHeaven')

    def cleanup(self):
        """Clean up after itself.

        Remove created files in /etc/resolver and delete directory if it's
        empty.
        """
        try:
            self._log.info('Starting cleanup')
            for key, paths in DNS_CONF.items():
                for path in paths:
                    path = Path(path)
                    if path.exists() and path.is_file():
                        self._log.debug('Deleting file %s', path)
                        os.remove(path)
                    else:
                        self._log.warning('Can\'t delete %s. '
                                          'File does not exist', path)
            path = Path(RESOLVER_DIR)
            if path.exists() and path.is_dir():
                if not os.listdir(path):
                    self._log.debug('Deleting directory %s', RESOLVER_DIR)
                    os.rmdir(path)
                else:
                    self._log.debug('Directory %s isn\'t empty. '
                                    'Won\'t delete', RESOLVER_DIR)
            else:
                self._log.warning('Can\'t delete . '
                                  'Directory doesn\'t exist', path)
            self._log.info('Cleanup has finished')
        except Exception:
            err_msg = 'Cleanup failed'
            self._log.exception(err_msg)
            return err_msg
        return EXIT_OK

    def restart_interfaces(self):
        """Restart network interfaces."""
        cmd_ifaces = "netstat -i | awk '/^en[0-9]+/ {{ print $1 | \"sort -u\" }}'"
        cmd_restart = inspect.cleandoc("""ifconfig {interface} down
                                          sleep 1
                                          ifconfig {interface} up""")
        try:
            network_ifaces = self._run_command(cmd_ifaces, split=True)

            # macOS routing table not always is being flushed on the first try,
            # let's do it five times.
            for i in range(5):
                self._run_command('route -n flush &>-')
            for interface in network_ifaces:
                self._log.info('Restarting interface %s', interface)
                cmd_run = cmd_restart.format(interface=interface)
                self._run_command(cmd_run)

        except Exception:
            err_msg = 'Couldn\'t restart interfaces'
            self._log.exception(err_msg)
            raise CiscoSSLVPNHeavenError(err_msg)

    def change_routes(self, interface):
        """Main method to change routes."""
        try:
            default_gw = self._get_default_gateway()
            tun_dev = self._get_tunnel_device()
            vpn_gw = self._get_vpn_gateway()
            vpn_dns = self._get_vpn_dns(tun_dev)

            eth_int = self._get_interface_name(INTERFACES[interface])
            domain_name = self._get_domain_name(eth_int)

            network_ids = self._get_network_ids()
            e_states_ipv4, network_ids_filtered = self._get_e_states_ipv4(network_ids)

            corporate_gw, corporate_dns, e_state_id_dns = \
                            self._get_corporate_dns_and_gw(e_states_ipv4,
                                                          eth_int,
                                                          network_ids_filtered)
            if default_gw == corporate_gw:
                self._log.warning('Default gateway %s is already '
                                  'the same as Corporate gateway '
                                  '{corporate_gw}. Aborting', default_gw)
                return EXIT_ERROR

            asn_networks = self._get_asn_networks()
            for networks in [*[x for x in VPN_NETWORKS.values()], INTERNAL_IPS,
                                                                 asn_networks]:
                self._add_routes(networks, vpn_gw)

            # Uncomment if you need to resolve IPv6 websites, but keep in mind
            # system will prefer IPv6 over IPv4 on any website which has IPv6
            # address.
            # self._fix_ipv6_settings(tun_dev)

            self._remove_overrideprimary_key(tun_dev)
            self._change_default_gateway(vpn_gw, corporate_gw)
            self._check_dns(corporate_dns, vpn_dns)
            self._modify_tun_dev_dns_settings(tun_dev, domain_name, corporate_dns)
            self._modify_global_dns_settings(domain_name, corporate_dns)
            self._add_corporate_search_domain(e_state_id_dns)

            self._log.info('Routes changed. Exiting.')
        except CiscoSSLVPNHeavenError as err:
            return str(err)
        except Exception:
            err_msg = 'Encountered an unknown error during changing routes'
            self._log.exception(err_msg)
            return err_msg
        return EXIT_OK

    def _run_command(self, cmd, strip=False, split=False):
        """Run shell command."""
        result = subprocess.check_output(cmd, shell=True, text=True)
        if strip:
            result = result.strip()
        if split:
            result = result.split()
        return result

    @verify_result
    def _get_default_gateway(self):
        """Get current default gateway IPv4 used by OS."""
        cmd = "netstat -nrf inet | awk '/link/ { next } /^(default|0\.0\.0\.0)/{ print $2; exit }'"
        try:
            def_gw = self._run_command(cmd, strip=True)
            self._log.debug('Default gateway: %s', def_gw)
        except Exception:
            err_msg = 'Couldn\'t get default gateway'
            self._log.exception(err_msg)
            raise CiscoSSLVPNHeavenError(err_msg)
        return def_gw

    @verify_result
    def _get_tunnel_device(self):
        """Get VPN interface name (tunnel device) e.g. utun1."""
        cmd = inspect.cleandoc("""scutil <<EOF | awk -F' : ' '/PrimaryService/ { print $2 }'
                                  open
                                  show State:/Network/Global/IPv4
                                  quit
                                  EOF""")
        try:
            tun_dev = self._run_command(cmd, strip=True)
            self._log.debug('Tunnel device: %s', tun_dev)
        except Exception:
            err_msg = 'Couldn\'t get tunnel device'
            self._log.exception(err_msg)
            raise CiscoSSLVPNHeavenError(err_msg)
        return tun_dev

    @verify_result
    def _get_vpn_gateway(self):
        """Get VPN gateway IPv4."""
        cmd = inspect.cleandoc("""scutil <<EOF | awk -F' : ' '/Router/ { print $2 }'
                                  open
                                  show State:/Network/Global/IPv4
                                  quit
                                  EOF""")
        try:
            vpn_gw = self._run_command(cmd, strip=True)
            self._log.debug('VPN gateway: %s', vpn_gw)
        except Exception:
            err_msg = 'Couldn\'t get VPN gateway'
            self._log.exception(err_msg)
            raise CiscoSSLVPNHeavenError(err_msg)
        return vpn_gw

    @verify_result
    def _get_interface_name(self, iface):
        """

        :param iface:
        :return:
        """
        cmd = f"networksetup -listallhardwareports | awk '/Hardware Port\: {iface}/{{ getline; print $2 }}'"
        try:
            eth_int = self._run_command(cmd, strip=True)
            self._log.debug('Interface name: %s', eth_int)
        except Exception:
            err_msg = 'Couldn\'t get interface name'
            self._log.exception(err_msg)
            raise CiscoSSLVPNHeavenError(err_msg)

        return eth_int

    @verify_result
    def _get_domain_name(self, eth_int):
        """

        :param eth_int:
        :return:
        """
        cmd = f"ipconfig getpacket {eth_int} 2>&- | awk '$1==\"domain_name\" {{ print $3 }}'"
        try:
            domain_name = self._run_command(cmd, strip=True)
            self._log.debug('Domain name: %s', domain_name)
        except Exception:
            err_msg = 'Couldn\'t get domain name'
            self._log.exception(err_msg)
            raise CiscoSSLVPNHeavenError(err_msg)

        return domain_name

    @verify_result
    def _get_network_ids(self):
        """

        :return:
        """
        cmd = "scutil <<<\"list\" | awk -F/ '/DNS$/ { if (length($(NF-1)) == 36 ) { print $(NF-1) } }' | sort -u"
        try:
            network_ids = self._run_command(cmd, split=True)
            self._log.debug('Network IDs: %s', json.dumps(network_ids))
        except Exception:
            err_msg = 'Couldn\'t get network ids'
            self._log.exception(err_msg)
            raise CiscoSSLVPNHeavenError(err_msg)
        return network_ids

    @verify_result
    def _get_e_states_ipv4(self, network_ids):
        """

        :param network_ids:
        :return:
        """
        e_states, network_ids_filtered = [], []
        cmd = "scutil <<<\"list\" | awk '/State.*{0}\/IPv4/{{ print $NF }}'"
        try:
            for nid in network_ids:
                cmd_run = cmd.format(nid)
                e_state = self._run_command(cmd_run, strip=True)
                if e_state:
                    e_states.append(e_state)
                    network_ids_filtered.append(nid)
            self._log.debug('e_states: %s', json.dumps(e_states))
            self._log.debug('Network IDs filtered: %s', json.dumps(network_ids_filtered))
        except Exception:
            err_msg = 'Couldn\'t get e_states_ipv4'
            self._log.exception(err_msg)
            raise CiscoSSLVPNHeavenError(err_msg)
        return e_states, network_ids_filtered

    @verify_result
    def _get_corporate_dns_and_gw(self, e_states, eth_int, network_ids):
        """

        :param e_states:
        :param eth_int:
        :param network_ids:
        :return:
        """
        e_tmp_cmd = "scutil <<<\"show {0}\" | awk '$1==\"InterfaceName\" {{ print $3 }}'"
        corporate_service_id_cmd = "awk -F/ '{{ if (length($(NF-1)) == 36 ) {{ print $(NF-1) }} }}' <<< {0}"
        corporate_gw_cmd = r'scutil <<<"show {0}" | grep -E "\bRouter\s" | grep -Eo "([0-9.]+){{4}}"'
        corporate_dns_cmd = r'scutil <<<"show State:/Network/Service/{0}/DNS" | grep -Eo "([0-9.]+){{4}}"'

        corporate_gw, corporate_dns, e_state_id_dns = None, [], None
        try:
            for index, e_state_id in enumerate(e_states):
                cmd_e = e_tmp_cmd.format(e_state_id)
                e_tmp = self._run_command(cmd_e, strip=True)
                if e_tmp == eth_int:
                    cmd_csi = corporate_service_id_cmd.format(e_state_id)
                    corporate_service_id = self._run_command(cmd_csi, strip=True)
                    self._log.debug('Corporate service id: %s', corporate_service_id)
                    cmd_cgw = corporate_gw_cmd.format(e_state_id)
                    corporate_gw = self._run_command(cmd_cgw, strip=True)
                    self._log.debug('Corporate gateway: %s', corporate_gw)

                    if not corporate_gw:
                        raise CiscoSSLVPNHeavenError('Corporate gateway '
                                                     'wasn\'t found')

                    cmd_cdns = corporate_dns_cmd.format(network_ids[index])
                    corporate_dns = self._run_command(cmd_cdns, split=True)
                    self._log.debug('Corporate DNS servers: %s', json.dumps(corporate_dns))
                    e_state_id_dns = f'State:/Network/Service/{corporate_service_id}/DNS'
                    break
        except CiscoSSLVPNHeavenError as err:
            self._log.exception(err)
            raise err
        except Exception:
            err_msg = 'Couldn\'t get corporate dns/gateway'
            self._log.exception(err_msg)
            raise CiscoSSLVPNHeavenError(err_msg)

        return corporate_gw, corporate_dns, e_state_id_dns

    @verify_result
    def _get_vpn_dns(self, tun_dev):
        """

        :param tun_dev:
        :return:
        """
        cmd_state = f"scutil <<<\"list\" | awk '/State.*{tun_dev}\/DNS/{{ print $NF }}'"
        cmd_vpn_dns = "scutil <<<\"show {0}\" | grep -Eo \"([0-9.]+){{4}}\""
        try:
            state = self._run_command(cmd_state, strip=True)
            cmd_vpn_dns = cmd_vpn_dns.format(state)
            vpn_dns = self._run_command(cmd_vpn_dns, split=True)
            self._log.debug('VPN DNS servers: %s', json.dumps(vpn_dns))
        except Exception:
            err_msg = 'Couldn\'t get VPN DNS servers'
            self._log.exception(err_msg)
            raise CiscoSSLVPNHeavenError(err_msg)
        return vpn_dns

    @verify_result
    def _get_asn_networks(self):
        """

        :return:
        """
        try:
            file = Path(ASN_NETWORKS_FILE)
            if file.exists() and file.is_file():
                self._log.debug('Reading IP networks from %s', ASN_NETWORKS_FILE)
                with open(ASN_NETWORKS_FILE, 'r') as fd:
                    networks = fd.read().splitlines()
            else:
                self._log.debug('File %s doesn\'t exist. '
                                'Downloading ASN database from MaxMind',
                                ASN_NETWORKS_FILE)
                res = requests.get(ASN_ARCHIVE_URL)

                self._log.debug('ASN database downloaded. Processing archive')
                archive = zipfile.ZipFile(BytesIO(res.content))
                for name in archive.namelist():
                    if name.endswith(GEOLITE_IPV4_CSV_FILENAME):
                        break
                csv_fd = archive.open(name, 'r')
                csv_fd = TextIOWrapper(csv_fd)

                networks = []
                for row in csv.DictReader(csv_fd):
                    if re.search(ASN_REGEX,
                                 row['autonomous_system_organization'].lower()):
                        networks.append(row['network'])
                with open(ASN_NETWORKS_FILE, 'w') as fd:
                    for ip in networks:
                        fd.write(f'{ip}\n')

            self._log.debug('IP networks (%s): %s',
                            len(networks), json.dumps(networks))
        except Exception:
            err_msg = 'Failed to get ASN Networks'
            self._log.exception(err_msg)
            raise CiscoSSLVPNHeavenError(err_msg)
        return networks

    def _add_routes(self, ips, vpn_gw):
        """

        :param ips:
        :param vpn_gw:
        """
        cmd = 'route -n add {0} {1} 1>&-'
        try:
            for ip in ips:
                cmd_run = cmd.format(ip, vpn_gw)
                self._run_command(cmd_run)
        except Exception:
            err_msg = 'Couldn\'t add routes to VPN gateway'
            self._log.exception(err_msg)
            raise CiscoSSLVPNHeavenError(err_msg)

    def _fix_ipv6_settings(self, tun_dev):
        """

        :param tun_dev:
        """
        cmd_get_ipv6 = f"scutil <<<\"show State:/Network/Interface/${tun_dev}/IPv6\" | awk '$1==\"Addresses\" {{ getline; getline; print $3 }}'"
        cmd_get_prefix_length = f"scutil <<<\"show State:/Network/Interface/${tun_dev}/IPv6\" | awk '$1==\"PrefixLength\" {{ getline; getline; print $3 }}'"

        try:
            self._log.debug('Fixing IPv6 settings')
            ipv6_address = self._run_command(cmd_get_ipv6, strip=True)
            prefix_length = self._run_command(cmd_get_prefix_length, strip=True)

            cmd_fix_ipv6 = inspect.cleandoc(f"""scutil <<EOF
                                            open
                                            remove State:/Network/Service/${tun_dev}/IPv6
                                            add State:/Network/Service/${tun_dev}/IPv6
                                            d.init
                                            d.add Addresses * ${ipv6_address}
                                            d.add InterfaceName ${tun_dev}
                                            d.add PrefixLength * ${prefix_length}
                                            d.add Router ${ipv6_address}
                                            set State:/Network/Service/${tun_dev}/IPv6
                                            quit
                                            EOF""")
            self._run_command(cmd_fix_ipv6)
        except Exception:
            err_msg = 'Couldn\'t fix IPv6 settings'
            self._log.exception(err_msg)
            raise CiscoSSLVPNHeavenError(err_msg)

    def _get_qrator_ips(self):
        """

        """
        pass

    def _add_qrator_ips(self):
        """

        """
        pass

    def _remove_overrideprimary_key(self, tun_dev):
        """

        :param tun_dev:
        """
        cmd = inspect.cleandoc(f"""scutil <<EOF
                                   open
                                   get State:/Network/Service/{tun_dev}/IPv4
                                   d.remove OverridePrimary
                                   set State:/Network/Service/{tun_dev}/IPv4
                                   quit
                                   EOF""")
        try:
            self._run_command(cmd)
            self._log.debug('Overrode Primary Key')
        except Exception:
            err_msg = 'Failed to override primary key'
            self._log.exception(err_msg)
            raise CiscoSSLVPNHeavenError(err_msg)

    def _change_default_gateway(self, vpn_gw, corporate_gw):
        """

        :param vpn_gw:
        :param corporate_gw:
        """
        self._log.info('Changing default gateway from %s to %s',
                       vpn_gw, corporate_gw)
        cmd = f'route -n change default {corporate_gw} 1>&-'
        try:
            self._run_command(cmd)
        except Exception:
            err_msg = 'Couldn\'t change default gateway'
            self._log.exception(err_msg)
            raise CiscoSSLVPNHeavenError(err_msg)

    def _check_dns(self, corporate_dns, vpn_dns):
        """

        :param corporate_dns:
        :param vpn_dns:
        """
        resolver = Path(RESOLVER_DIR)
        if not resolver.exists() or not resolver.is_dir():
            self._log.warning('%s directory doesn\'t exist, '
                              'will be created', RESOLVER_DIR)
            os.mkdir(RESOLVER_DIR)

            for dns_type, paths in DNS_CONF.items():
                dns_servers = vpn_dns if dns_type == 'vpn' else corporate_dns
                self._add_dns(paths, dns_servers)
        else:
            for dns_type, paths in DNS_CONF.items():
                dns_servers = vpn_dns if dns_type == 'vpn' else corporate_dns
                for path in paths:
                    if not Path(path).exists() or not Path(path).is_file():
                        self._log.warning('Path [] doesn\'t exist. Creating new',
                                          path)
                        self._add_dns([path, ], dns_servers)
                    else:
                        self._log.debug('Comparing DNS servers in %s', path)
                        existing_dns = []
                        with open(path, 'r') as fd:
                            for line in fd:
                                existing_dns.append(line.split()[1])
                        if sorted(dns_servers) != sorted(existing_dns):
                            # TODO: Append missing and don't rewrite file?
                            self._log.warning('DNS servers in %s doesn\'t '
                                              'match. Rewriting', path)
                            self._add_dns([path, ], dns_servers)

    def _add_dns(self, paths, dns_servers):
        """

        :param paths:
        :param dns_servers:
        """
        for path in paths:
            self._log.debug('Adding DNS servers %s to "%s"',
                            json.dumps(dns_servers), path)
            with open(path, 'w') as fd:
                for server in dns_servers:
                    fd.write(f'nameserver {server}\n')

    def _add_dns_setup(self, tun_dev, domain_name, corporate_dns):
        """

        :param tun_dev:
        :param domain_name:
        :param corporate_dns:
        """
        cmd = inspect.cleandoc(fr"""scutil <<EOF
                                    open
                                    get Setup:/Network/Service/{tun_dev}/DNS
                                    d.init
                                    d.add DomainName {domain_name}
                                    d.add ServerAddresses * $(sed 's/\n//g' <<< "{' '.join(corporate_dns)}")
                                    set Setup:/Network/Service/{tun_dev}/DNS
                                    quit
                                    EOF""")
        try:
            self._log.debug('Adding DNS Setup')
            self._run_command(cmd)
        except Exception:
            err_msg = 'Couldn\'t add DNS Setup'
            self._log.exception(err_msg)
            raise CiscoSSLVPNHeavenError(err_msg)

    def _add_dns_state(self, tun_dev, domain_name, corporate_dns):
        """

        :param tun_dev:
        :param domain_name:
        :param corporate_dns:
        """
        cmd = inspect.cleandoc(fr"""scutil <<EOF
                                    open
                                    get State:/Network/Service/{tun_dev}/DNS
                                    d.init
                                    d.add DomainName {domain_name}
                                    d.add ServerAddresses * $(sed 's/\n//g' <<< "{' '.join(corporate_dns)}")
                                    set State:/Network/Service/{tun_dev}/DNS
                                    quit
                                    EOF""")
        try:
            self._log.debug('Adding DNS State')
            self._run_command(cmd)
        except Exception:
            err_msg = 'Couldn\'t add DNS State'
            self._log.exception(err_msg)
            raise CiscoSSLVPNHeavenError(err_msg)

    def _modify_tun_dev_dns_settings(self, tun_dev, domain_name, corporate_dns):
        """

        :param tun_dev:
        :param domain_name:
        :param corporate_dns:
        """
        cmd = inspect.cleandoc(fr"""scutil <<EOF | sed 's/^[ ]*//g'
                                    open
                                    show Setup:/Network/Service/utun2/DNS
                                    quit
                                    EOF""")
        try:
            self._log.debug('In modify_tun_dev_dns_settings')
            setup_service = self._run_command(cmd, strip=True)
            if setup_service != 'No such key':
                self._add_dns_setup(tun_dev, domain_name, corporate_dns)
            self._add_dns_state(tun_dev, domain_name, corporate_dns)
        except Exception:
            err_msg = 'Couldn\'t modify tunnel device DNS settings'
            self._log.exception(err_msg)
            raise CiscoSSLVPNHeavenError(err_msg)

    def _modify_global_dns_settings(self, domain_name, corporate_dns):
        """

        :param domain_name:
        :param corporate_dns:
        """
        cmd = inspect.cleandoc(fr"""scutil <<EOF
                                    open
                                    get State:/Network/Global/DNS
                                    d.init
                                    d.add DomainName {domain_name}
                                    d.add ServerAddresses * $(sed 's/\n//g' <<< "{' '.join(corporate_dns)}")
                                    set State:/Network/Global/DNS
                                    quit
                                    EOF""")
        try:
            self._log.debug('In modify_global_dns_settings')
            self._run_command(cmd)
        except Exception:
            err_msg = 'Couldn\'t modify global DNS settings'
            self._log.exception(err_msg)
            raise CiscoSSLVPNHeavenError(err_msg)

    def _remove_search_domains_key(self, e_state_id_dns):
        """

        :param e_state_id_dns:
        """
        cmd = inspect.cleandoc(f"""scutil <<EOF
                                   open
                                   get {e_state_id_dns}
                                   d.remove SearchDomains
                                   set {e_state_id_dns}
                                   quit
                                   EOF""")
        try:
            self._run_command(cmd)
        except Exception:
            err_msg = 'Couldn\'t remove search domains key'
            self._log.exception(err_msg)
            raise CiscoSSLVPNHeavenError(err_msg)

    def _add_corporate_search_domain(self, e_state_id_dns):
        """

        :param e_state_id_dns:
        """
        cmd = inspect.cleandoc(fr"""scutil <<EOF
                                    open
                                    get {e_state_id_dns}
                                    d.add SearchDomains * {CORPORATE_SEARCH_DOMAIN}
                                    set {e_state_id_dns}
                                    quit
                                    EOF""")
        try:
            self._log.debug('In add_corporate_search_domain')
            self._run_command(cmd)
        except Exception:
            err_msg = 'Couldn\'t add corporate search domain'
            self._log.exception(err_msg)
            raise CiscoSSLVPNHeavenError(err_msg)

    def _check_external_ip(self):
        """

        """
        pass


def main():
    """Main function."""
    log_format = '%(asctime)s - %(name)s - %(levelname)s - [%(funcName)s] - %(message)s'
    logging.basicConfig(format=log_format, level=logging.DEBUG, stream=sys.stdout)
    # TODO: Different log handlers
    # file_handler = logging.FileHandler(
    #     '{0}.log'.format(os.path.splitext(os.path.basename(__file__))[0]))
    # file_handler.setFormatter(logging.Formatter(log_format))

    parser = argparse.ArgumentParser(description='Cisco SSL VPN Heaven')
    parser.add_argument('interface', choices=('wifi', 'ether'), default=None,
                        type=str, help='network interface')
    parser.add_argument('-c', '--cleanup', action='store_true',
                        default=False,
                        dest='cleanup',
                        help='perform clean up')
    parser.add_argument('-r', '--restart-interfaces', action='store_true',
                        default=False,
                        dest='restart_interfaces',
                        help='restart network interfaces')

    args = parser.parse_args()
    if len(sys.argv) not in (2, 3):
        parser.print_help()
        return EXIT_ERROR

    vpn_heaven = CiscoSSLVPNHeaven()

    if args.interface:
        return vpn_heaven.change_routes(interface=args.interface)
    elif args.cleanup:
        return vpn_heaven.cleanup()
    elif args.restart_interfaces:
        return vpn_heaven.restart_interfaces()


if __name__ == '__main__':
    if os.geteuid() != 0:
        print('Script needs to be run under root. Re-executing under root')
        os.execvp('sudo', ['sudo'] + sys.argv)

    print(BANNER)
    sys.exit(main())
