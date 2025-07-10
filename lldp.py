#!/usr/bin/env python3

# <xbar.title>LLDP Neighbors</xbar.title>
# <xbar.version>v1.0</xbar.version>
# <xbar.author>Karl Swanson</xbar.author>
# <xbar.author.github>karlcswanson</xbar.author.github>
# <xbar.desc>Display LLDP neighbor information</xbar.desc>
# <xbar.dependencies>python3,lldpd</xbar.dependencies>
# <xbar.abouturl>https://github.com/karlcswanson</xbar.abouturl>

# <swiftbar.refreshOnOpen>true</swiftbar.refreshOnOpen>
# <swiftbar.hideAbout>true</swiftbar.hideAbout>
# <swiftbar.hideRunInTerminal>true</swiftbar.hideRunInTerminal>
# <swiftbar.hideLastUpdated>true</swiftbar.hideLastUpdated>
# <swiftbar.hideDisablePlugin>true</swiftbar.hideDisablePlugin>
# <swiftbar.hideSwiftBar>true</swiftbar.hideSwiftBar>

import json
import subprocess
import sys
import re


def run_lldp_command():
    """Run the LLDP command and return parsed JSON data"""
    try:
        result = subprocess.run(['/usr/local/sbin/lldpcli', '-f', 'json0', 'show', 'neighbors', 'detail'],
                                capture_output=True, text=True, check=True)
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print("lldpcli Error")
        print("---")
        print(f"Failed to run lldpcli: {e}")
        print("Make sure lldpd is installed and running")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print("JSON Error")
        print("---")
        print(f"Failed to parse JSON: {e}")
        sys.exit(1)
    except FileNotFoundError:
        print("lldpcli Error")
        print("---")
        print("lldpcli command not found")
        print("Install lldpd: brew install lldpd")
        sys.exit(1)


def format_mac(mac_str):
    """Format MAC address for better readability"""
    return mac_str.upper()


def get_enabled_capabilities(capabilities):
    """Get list of enabled capabilities"""
    enabled = []
    for cap in capabilities:
        if cap.get('enabled', False):
            enabled.append(cap['type'])
    return enabled


def get_interface_info():
    """Get IP and MAC addresses for all network interfaces"""
    try:
        # Run ifconfig command to get interface information
        result = subprocess.run(['ifconfig'], capture_output=True, text=True, check=True)
        output = result.stdout

        # Parse the output to get interface information
        interfaces = {}
        current_interface = None

        for line in output.splitlines():
            # Match interface name line
            interface_match = re.match(r'^(\w+):', line)
            if interface_match:
                current_interface = interface_match.group(1)
                interfaces[current_interface] = {'ip': [], 'mac': None}
                continue

            # Match MAC address line
            mac_match = re.search(r'ether\s+([0-9a-f:]+)', line)
            if mac_match and current_interface:
                interfaces[current_interface]['mac'] = mac_match.group(1).upper()
                continue

            # Match IPv4 address line
            ipv4_match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', line)
            if ipv4_match and current_interface:
                interfaces[current_interface]['ip'].append(ipv4_match.group(1))
                continue

            # Match IPv6 address line
            ipv6_match = re.search(r'inet6\s+([0-9a-f:]+)', line)
            if ipv6_match and current_interface:
                interfaces[current_interface]['ip'].append(ipv6_match.group(1))
                continue

        return interfaces
    except subprocess.CalledProcessError:
        return {}


def get_vlan_info(interface, port):
    """Extract VLAN information from interface and port data if available"""
    vlans = []
    pvid = None

    # First check for VLAN information at the interface level
    if 'vlan' in interface:
        vlan_data = interface.get('vlan', [])
        if isinstance(vlan_data, list):
            for vlan in vlan_data:
                if isinstance(vlan, dict):
                    # Handle the format seen in the example: {"vlan-id": "4000", "pvid": true}
                    vlan_id = None
                    if 'vlan-id' in vlan:
                        vlan_id = vlan['vlan-id']
                    elif 'value' in vlan:
                        vlan_id = vlan['value']

                    if vlan_id:
                        vlans.append(vlan_id)
                        # Check if this is the PVID
                        if vlan.get('pvid', False):
                            pvid = vlan_id
                elif isinstance(vlan, str):
                    vlans.append(vlan)
        elif isinstance(vlan_data, dict):
            vlan_id = None
            if 'vlan-id' in vlan_data:
                vlan_id = vlan_data['vlan-id']
            elif 'value' in vlan_data:
                vlan_id = vlan_data['value']

            if vlan_id:
                vlans.append(vlan_id)
                # Check if this is the PVID
                if vlan_data.get('pvid', False):
                    pvid = vlan_id
        elif isinstance(vlan_data, str):
            vlans.append(vlan_data)

    # Then check for VLAN information in the port data
    # VLAN info might be in different locations depending on the device
    # Common locations: 'vlan', 'vlan-id', 'pvid', etc.
    for vlan_key in ['vlan', 'vlan-id', 'pvid']:
        if vlan_key in port:
            vlan_data = port.get(vlan_key, [])
            if isinstance(vlan_data, list):
                for vlan in vlan_data:
                    if isinstance(vlan, dict):
                        vlan_id = None
                        if 'value' in vlan:
                            vlan_id = vlan['value']
                        elif 'vlan-id' in vlan:
                            vlan_id = vlan['vlan-id']

                        if vlan_id:
                            vlans.append(vlan_id)
                            # Check if this is the PVID
                            if vlan.get('pvid', False):
                                pvid = vlan_id
                    elif isinstance(vlan, str):
                        vlans.append(vlan)
            elif isinstance(vlan_data, dict):
                vlan_id = None
                if 'value' in vlan_data:
                    vlan_id = vlan_data['value']
                elif 'vlan-id' in vlan_data:
                    vlan_id = vlan_data['vlan-id']

                if vlan_id:
                    vlans.append(vlan_id)
                    # Check if this is the PVID
                    if vlan_data.get('pvid', False):
                        pvid = vlan_id
            elif isinstance(vlan_data, str):
                vlans.append(vlan_data)

    return {'vlans': vlans, 'pvid': pvid}


def main():
    data = run_lldp_command()

    # Get all interfaces and filter out feth interfaces (ZeroTier/Netbird virtual interfaces)
    all_interfaces = data.get('lldp', [{}])[0].get('interface', [])
    interfaces = [iface for iface in all_interfaces if not iface.get('name', '').startswith('feth')]
    # interfaces = [iface for iface in all_interfaces]

    neighbor_count = len(interfaces)

    # Get local interface information
    local_interfaces = get_interface_info()

    # Menu bar title
    if neighbor_count == 0:
        print(" | sfimage=server.rack")
    else:
        print(f" | sfimage=server.rack")

    print("---")

    if neighbor_count == 0:
        print("No LLDP neighbors found")
        return

    # Header with refresh option
    print("Refresh | refresh=true sfimage=arrow.clockwise")
    print("---")

    # Display each neighbor
    for i, interface in enumerate(interfaces):
        interface_name = interface.get('name', 'Unknown')

        # Get chassis info
        chassis = interface.get('chassis', [{}])[0]
        chassis_name = chassis.get('name', [{}])[0].get('value', 'Unknown')
        chassis_id = chassis.get('id', [{}])[0].get('value', 'Unknown')
        chassis_descr = chassis.get('descr', [{}])[0].get('value', 'No description')

        # Get management IPs
        mgmt_ips = [ip.get('value', '') for ip in chassis.get('mgmt-ip', [])]

        # Get capabilities
        capabilities = get_enabled_capabilities(chassis.get('capability', []))

        # Get port info
        port = interface.get('port', [{}])[0]
        port_id = port.get('id', [{}])[0].get('value', 'Unknown')
        port_descr = port.get('descr', [{}])[0].get('value', 'Unknown')

        # Get VLAN info
        vlan_info = get_vlan_info(interface, port)
        vlans = vlan_info['vlans']
        pvid = vlan_info['pvid']

        # Interface header - clicking on interface name opens System Preferences Network pane for that interface
        escaped_interface_name = interface_name.replace('"', '\\"').replace("'", "\\'")

        print(f"{interface_name} | sfimage=cable.connector.horizontal")

        # Show local interface IP and MAC if available
        if interface_name in local_interfaces:
            local_info = local_interfaces[interface_name]
            if local_info['mac']:
                print(f"mac: {local_info['mac']} | bash='/bin/bash' param1='-c' param2='/bin/echo -n {local_info['mac']} | pbcopy' terminal=false")
            if local_info['ip']:
                for ip in local_info['ip']:
                    print(f"ip: {ip} | bash='/bin/bash' param1='-c' param2='/bin/echo -n {ip} | pbcopy' terminal=false")

        print("---")

        # Port information
        print(f"Port ID: {format_mac(port_id)} | bash='/bin/bash' param1='-c' param2='/bin/echo -n {format_mac(port_id)} | pbcopy' terminal=false")
        print(f"Port Desc: {port_descr} | bash='/bin/bash' param1='-c' param2='/bin/echo -n {port_descr} | pbcopy' terminal=false")

        # VLAN information
        if vlans:
            # Display all VLANs
            vlan_str = ', '.join(str(vlan) for vlan in vlans)
            print(f"VLANs: {vlan_str} | bash='/bin/bash' param1='-c' param2='/bin/echo -n \"{vlan_str}\" | pbcopy' terminal=false")

            # Display PVID if available
            if pvid:
                print(f"PVID: {pvid} | bash='/bin/bash' param1='-c' param2='/bin/echo -n \"{pvid}\" | pbcopy' terminal=false color=green")
        print("---")
        print(f"Host: {chassis_name} | bash='/bin/bash' param1='-c' param2='/bin/echo -n {chassis_name} | pbcopy' terminal=false")
        print(f"Chassis ID: {format_mac(chassis_id)} | bash='/bin/bash' param1='-c' param2='/bin/echo -n {format_mac(chassis_id)} | pbcopy' terminal=false")

        # Management IPs
        if mgmt_ips:
            print(f"Management IPs:")
            for ip in mgmt_ips:
                print(f"{ip} | bash='/bin/bash' param1='-c' param2='/bin/echo -n {ip} | pbcopy' terminal=false")


        # System description (truncated for menu)
        if chassis_descr and chassis_descr != 'No description':
            # Truncate long descriptions
            short_descr = chassis_descr[:50] + "..." if len(chassis_descr) > 50 else chassis_descr
            # Escape quotes and special characters in description
            escaped_descr = chassis_descr.replace('"', '\\"').replace("'", "\\'")
            print(f"System: {short_descr} | bash='/bin/bash' param1='-c' param2='/bin/echo -n \"{escaped_descr}\" | pbcopy' terminal=false")

        # Add separator if not last item
        if i < len(interfaces) - 1:
            print("---")


if __name__ == "__main__":
    main()
