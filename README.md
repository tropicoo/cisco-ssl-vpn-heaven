Cisco SSL VPN Heaven
====================
**Cisco SSL VPN Heaven for macOS**

Tired of Cisco SSL AnyConnect and traffic being routed through VPN's gateaway because your VPN server doesn't allow 
split tunneling?

This script along with [OpenConnect](http://www.infradead.org/openconnect/) will make you feel better.

#### Problem
- VPN server configuration doesn't allow split tunneling which results in
default gateaway being changed to VPN's one.
- Therefore default traffic is being routed through VPN gateaway which results
in inability to access local/corporate network hosts/printer services etc.
- Cisco AnyConnect Agent Daemon monitors routing table and rewrites any manual
changes.

#### Solution
- Since openconnect doesn't have any agent monitoring routing table, it and
other system configuration like WINS/DNS servers can be rewritten and reverted
back to previous state without breaking VPN connection.
- Moreover default gateaway can be easily changed with several precautions:
    * TODO
    
```bash
$ ./routes.py ether
Script needs to be run under root. Re-executing under root
Password:


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



2019-04-19 18:27:08,955 - CiscoSSLVPNHeaven - DEBUG - [_get_default_gateaway] - Default gateaway: x.x.x.x
2019-04-19 18:27:08,979 - CiscoSSLVPNHeaven - DEBUG - [_get_tunnel_device] - Tunnel device: utun1
2019-04-19 18:27:09,004 - CiscoSSLVPNHeaven - DEBUG - [_get_vpn_gateaway] - VPN gateaway: x.x.x.x
2019-04-19 18:27:09,051 - CiscoSSLVPNHeaven - DEBUG - [_get_vpn_dns] - VPN DNS servers: ["xx.xx.xx.xx", "xy.xy.xy.xy"]
2019-04-19 18:27:09,101 - CiscoSSLVPNHeaven - DEBUG - [_get_interface_name] - Interface name: en0
2019-04-19 18:27:09,118 - CiscoSSLVPNHeaven - DEBUG - [_get_domain_name] - Domain name: ddns.hostname.com
2019-04-19 18:27:09,179 - CiscoSSLVPNHeaven - DEBUG - [_get_network_ids] - Network IDs: ["751E3001-C54F-43AD-AE41-99C124AE16F7", "E78A905E-156C-49B2-AA82-C076823BFC07"]
2019-04-19 18:27:09,223 - CiscoSSLVPNHeaven - DEBUG - [_get_e_states_ipv4] - e_states: ["State:/Network/Service/766E3001-C54F-43AD-AE41-99C124AE66F7/IPv4", "State:/Network/Service/E78A905E-156C-49B2-AA82-C076823BFC07/IPv4"]
2019-04-19 18:27:09,224 - CiscoSSLVPNHeaven - DEBUG - [_get_e_states_ipv4] - Network IDs filtered: ["751E3001-C54F-43AD-AE41-99C124AE16F7", "E78A905E-156C-49B2-AA82-C076823BFC07"]
2019-04-19 18:27:09,279 - CiscoSSLVPNHeaven - DEBUG - [_get_corporate_dns_and_gw] - Corporate service id: E78A905E-156C-49B2-AA82-C076823BFC07
2019-04-19 18:27:09,307 - CiscoSSLVPNHeaven - DEBUG - [_get_corporate_dns_and_gw] - Corporate gateaway: y.y.y.y
2019-04-19 18:27:09,327 - CiscoSSLVPNHeaven - DEBUG - [_get_corporate_dns_and_gw] - Corporate DNS servers: ["a.a.a.a", "b.b.b.b", "c.c.c.c"]
2019-04-19 18:27:09,328 - CiscoSSLVPNHeaven - DEBUG - [_get_asn_networks] - Reading IP networks from asn_ips.txt
2019-04-19 18:27:09,335 - CiscoSSLVPNHeaven - DEBUG - [_get_asn_networks] - IP networks (121): ["o.o.o.o/23", "e.e.e.e/21", ...]
2019-04-19 18:27:10,753 - CiscoSSLVPNHeaven - DEBUG - [_remove_overrideprimary_key] - Overrode Primary Key
2019-04-19 18:27:10,753 - CiscoSSLVPNHeaven - INFO - [_change_default_gateaway] - Changing default gateaway from x.x.x.x to y.y.y.y
2019-04-19 18:27:10,769 - CiscoSSLVPNHeaven - DEBUG - [_check_dns] - Comparing DNS servers in /etc/resolver/hostname1.com
2019-04-19 18:27:10,770 - CiscoSSLVPNHeaven - DEBUG - [_check_dns] - Comparing DNS servers in /etc/resolver/hostname2.com
2019-04-19 18:27:10,771 - CiscoSSLVPNHeaven - DEBUG - [_check_dns] - Comparing DNS servers in /etc/resolver/hostname3.com
2019-04-19 18:27:10,771 - CiscoSSLVPNHeaven - DEBUG - [_check_dns] - Comparing DNS servers in /etc/resolver/hostname4.com
2019-04-19 18:27:10,772 - CiscoSSLVPNHeaven - DEBUG - [_check_dns] - Comparing DNS servers in /etc/resolver/hostname5.com
2019-04-19 18:27:10,772 - CiscoSSLVPNHeaven - DEBUG - [_modify_tun_dev_dns_settings] - In modify_tun_dev_dns_settings
2019-04-19 18:27:10,806 - CiscoSSLVPNHeaven - DEBUG - [_add_dns_state] - Adding DNS State
2019-04-19 18:27:10,853 - CiscoSSLVPNHeaven - DEBUG - [_modify_global_dns_settings] - In modify_global_dns_settings
2019-04-19 18:27:10,883 - CiscoSSLVPNHeaven - DEBUG - [_add_corporate_search_domain] - In add_corporate_search_domain
2019-04-19 18:27:10,915 - CiscoSSLVPNHeaven - INFO - [change_routes] - Routes changed. Exiting.
```

Caution
-------
Current state: <b>Beta</b>.

If there is still no `Configuration` section in this README, don't run `routes.py`.
Some things firstly need to be explained and configured.


Requirements
------------
Python >= 3.6 because of `f-strings`.

Use [Homebrew](https://brew.sh/) to install the latest Python 3 on your macOS.

```
brew update && brew upgrade
brew install python
```

Installation
------------
```
git clone https://github.com/tropicoo/cisco-ssl-vpn-heaven.git
pip3 install requests
```

Configuration
-------------
> Currently configuration is being made by editing the script constants code itself.

> Currently all steps are required to be executed.

1. Find corporate search domain, which was changed by VPN server configuration.
It's located in `/etc/resolv.conf` and is written as `search <search_domain>`.
    
    Write it to the `CORPORATE_SEARCH_DOMAIN` variable:
    ```python
    # Example
    CORPORATE_SEARCH_DOMAIN = '<search_domain>'
    ```
2. Write internal IP/Networks to the `INTERNAL_IPS` variable, which will be routed through the VPN gateaway after
changing the gateaway.
    ```python
    # Example
    INTERNAL_IPS = ['8.8.8.8', '10.10/16', ...]
    ```
3. Write custom networks which should routed through VPN's gateaway to the `VPN_NETWORKS` variable.
    ```python
    # Example
    VPN_NETWORKS = {'yandex': ['5.45.192.0/18', ...], ...}
    ```
4. If you need to add specific networks to the VPN's gateaway, which belong to some public company, who has registered 
ASN number, write the 
name of company to the regex `ASN_REGEX` variable.
    ```python
    # Example
    ASN_REGEX = r'\bgoogle\b'
    ```
5. Networks from the previous step will be cached to the local file for reuse. Write the location to the 
`ASN_NETWORKS_FILE` variable.
    ```python
    # Example
    ASN_NETWORKS_FILE = '/tmp/asn_networks.txt'
    ```
6. If you need to resolve specific domains with VPN or corporate DNS servers, add them to the `DNS_CONF` variable.
Script will create files in the `/etc/resolver/` directory and write there appropriate DNS servers.
    ```python
    # Example
    DNS_CONF = {'vpn': [f'{RESOLVER_DIR}google.com', ...],
                'corporate': [f'{RESOLVER_DIR}amazon.com', ...]}
    ```

Usage
-----
> Script needs to be run as root using `sudo` or it will ask you for the root password and re-run the script under root.


#### Change routes
Script needs to know on which network device perform the actions.
If your main connection is going through the Ethernet, `ether` argument should be used, or `wifi` in case of Wi-Fi.
```bash
# Change routes on Ethernet interface
sudo python3 routes.py ether

# Or if on Wi-Fi network
sudo python3 routes.py wifi
```

#### Cleanup
Script can cleanup after itself by deleting created files and `/etc/resolver` directory if it's not empty.
```bash
# Perform cleanup
sudo python3 routes.py -c
```

#### Restart network interfaces
If something unexpected has happened and the networking stopped working (which really shouldn't happen)
restart all network interfaces.
```bash
# Restart all network interfaces
sudo python3 routes.py -r
```
