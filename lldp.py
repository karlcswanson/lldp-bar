#!/usr/bin/env python3

# <xbar.title>LLDP-bar</xbar.title>
# <xbar.version>v2.0</xbar.version>
# <xbar.author>Karl Swanson</xbar.author>
# <xbar.author.github>karlcswanson</xbar.author.github>
# <xbar.desc>LLDP neighbors, IP/DHCP profile switcher, serial console launcher, and switch web/SSH in one menu.</xbar.desc>
# <xbar.dependencies>python3,lldpd</xbar.dependencies>
# <xbar.abouturl>https://github.com/karlcswanson</xbar.abouturl>

# <swiftbar.refreshOnOpen>true</swiftbar.refreshOnOpen>
# <swiftbar.hideAbout>true</swiftbar.hideAbout>
# <swiftbar.hideRunInTerminal>true</swiftbar.hideRunInTerminal>
# <swiftbar.hideLastUpdated>true</swiftbar.hideLastUpdated>
# <swiftbar.hideDisablePlugin>true</swiftbar.hideDisablePlugin>
# <swiftbar.hideSwiftBar>true</swiftbar.hideSwiftBar>

import glob
import ipaddress
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# ─── paths & constants ──────────────────────────────────────────────────────
NETWORKSETUP = '/usr/sbin/networksetup'
SCREEN = '/usr/bin/screen'
SCRIPT_PATH = Path(__file__).resolve()
PLUGIN_DIR = SCRIPT_PATH.parent
CONFIG_PATH = PLUGIN_DIR / 'netconfig.json'
CONFIG_EXAMPLE_PATH = PLUGIN_DIR / 'netconfig.example.json'

DEFAULT_BAUD_RATES = [9600, 19200, 38400, 57600, 115200]
DEFAULT_SSH_USER = 'admin'
SERIAL_EXCLUDE = ('Bluetooth', 'debug-console', 'wlan-debug')
LLDPCLI_DIRS = '/usr/local/sbin:/opt/homebrew/sbin:/opt/local/sbin'

_config_cache = None
_script_path = str(SCRIPT_PATH)


# ─── shared helpers ─────────────────────────────────────────────────────────
def run_quiet(args, timeout=5):
    """Run a read-only query command; return the CompletedProcess, or None if
    it can't be launched or doesn't finish in time. Callers check returncode."""
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def load_config():
    """Read netconfig.json once per process; a missing file means defaults
    (no profiles). Returns (data, error)."""
    global _config_cache
    if _config_cache is not None:
        return _config_cache, None
    if not CONFIG_PATH.exists():
        _config_cache = {}
        return _config_cache, None
    try:
        with open(CONFIG_PATH) as f:
            _config_cache = json.load(f) or {}
        return _config_cache, None
    except json.JSONDecodeError as e:
        return {}, f"JSON parse error in {CONFIG_PATH.name}: {e}"


def cfg(key, default=None):
    return load_config()[0].get(key) or default


def notify(title, message):
    """Send a macOS notification; LANG forces osascript to decode the -e arg as UTF-8."""
    env = os.environ.copy()
    env['LANG'] = 'en_US.UTF-8'
    env['LC_ALL'] = 'en_US.UTF-8'
    subprocess.run(['osascript', '-e',
        f'display notification {_q(message)} with title {_q(title)}'
    ], env=env, check=False)


def fail(message):
    notify("LLDP-bar", message)
    sys.exit(1)


def _q(value):
    """Quote a value for a SwiftBar param or AppleScript source: newlines
    collapse to spaces (both formats are line-based), `\\` and `"` are escaped."""
    s = ' '.join(str(value).split())
    s = s.replace('\\', '\\\\').replace('"', '\\"')
    return f'"{s}"'


def label(value, limit=0):
    """Sanitize a remote-supplied string for the label side of a menu line:
    whitespace collapses to single spaces and `|` (the SwiftBar action
    separator) is replaced so a hostile value can't inject menu actions."""
    s = ' '.join(str(value).split()).replace('|', '¦')
    if limit and len(s) > limit:
        s = s[:limit] + '…'
    return s


def action(shell, *params, terminal=False, refresh=False):
    """Build a SwiftBar trailing-pipe action with quoted shell + paramN entries."""
    parts = [f'shell={_q(shell)}']
    parts.extend(f'param{i}={_q(p)}' for i, p in enumerate(params, 1))
    parts.append(f'terminal={"true" if terminal else "false"}')
    if refresh:
        parts.append('refresh=true')
    return ' '.join(parts)


def pbcopy_action(value):
    """SwiftBar action that copies `value` to the clipboard via our `copy` subcommand."""
    return action(_script_path, 'copy', value)


def cmd_copy(value):
    subprocess.run(['/usr/bin/pbcopy'], input=str(value).encode('utf-8'), check=False)


# ─── LLDP ───────────────────────────────────────────────────────────────────
def run_lldp_command():
    """Run lldpcli; return (data, None) or (None, error)."""
    lldpcli = shutil.which('lldpcli', path=LLDPCLI_DIRS)
    if not lldpcli:
        return None, "lldpcli not found. Install lldpd: brew install lldpd"
    result = run_quiet([lldpcli, '-f', 'json0', 'show', 'neighbors', 'detail'])
    if result is None:
        return None, "lldpcli error: timed out"
    if result.returncode != 0:
        err = (result.stderr or '').strip()[:200]
        return None, f"lldpcli error: {err or result.returncode}"
    try:
        return json.loads(result.stdout), None
    except json.JSONDecodeError as e:
        return None, f"lldpcli error: {e}"


def get_interface_info():
    """Return {iface: {'mac': str|None, 'ip': [str, ...], 'active': bool}}
    from a single ifconfig pass."""
    result = run_quiet(['ifconfig'])
    if result is None or result.returncode != 0:
        return {}
    interfaces, cur = {}, None
    for line in result.stdout.splitlines():
        m = re.match(r'^(\w+):', line)
        if m:
            cur = m.group(1)
            interfaces[cur] = {'ip': [], 'mac': None, 'active': False}
            continue
        if not cur:
            continue
        if 'status: active' in line:
            interfaces[cur]['active'] = True
            continue
        m = re.search(r'ether\s+([0-9a-f:]+)', line)
        if m:
            interfaces[cur]['mac'] = m.group(1).upper()
            continue
        m = re.search(r'\binet6?\s+([0-9a-fA-F.:]+)', line)
        if m:
            interfaces[cur]['ip'].append(m.group(1))
    return interfaces


def get_vlan_info(interface, port):
    """Collect VLAN IDs from interface- and port-level entries; return (vlans, pvid)."""
    vlans, pvid = [], None
    candidates = []
    for src in (interface, port):
        for key in ('vlan', 'vlan-id', 'pvid'):
            data = src.get(key)
            if data is None:
                continue
            candidates.extend(data if isinstance(data, list) else [data])
    for c in candidates:
        if isinstance(c, dict):
            vid = c.get('vlan-id') or c.get('value')
            if vid:
                vlans.append(vid)
                if c.get('pvid'):
                    pvid = vid
        elif isinstance(c, str):
            vlans.append(c)
    return vlans, pvid


def render_switch_ip_actions(ip, ssh_user):
    bracket_ip = f"[{ip}]" if ':' in ip else ip
    print(f"--Open Web (HTTPS) | {action('/usr/bin/open', f'https://{bracket_ip}')}")
    print(f"--Open Web (HTTP) | {action('/usr/bin/open', f'http://{bracket_ip}')}")
    print(f"--SSH as {ssh_user} | {action(_script_path, 'ssh', ssh_user, ip)}")
    print(f"--Copy IP | {pbcopy_action(ip)}")


def render_lldp_neighbor(interface, local_interfaces, ssh_user):
    name = interface.get('name', 'Unknown')

    def cv(d, key, default='Unknown'):
        return d.get(key, [{}])[0].get('value', default)

    chassis = interface.get('chassis', [{}])[0]
    chassis_name = cv(chassis, 'name')
    chassis_id = cv(chassis, 'id').upper()
    chassis_descr = cv(chassis, 'descr', '')
    mgmt_ips = [ip.get('value', '') for ip in chassis.get('mgmt-ip', [])]

    port = interface.get('port', [{}])[0]
    port_id = cv(port, 'id').upper()
    port_descr = cv(port, 'descr')

    vlans, pvid = get_vlan_info(interface, port)

    print(f"{name} | sfimage=cable.connector.horizontal")

    local = local_interfaces.get(name)
    if local:
        if local['mac']:
            print(f"mac: {local['mac']} | {pbcopy_action(local['mac'])}")
        for ip in local['ip']:
            print(f"ip: {ip} | {pbcopy_action(ip)}")

    print("---")
    print(f"Port ID: {label(port_id)} | {pbcopy_action(port_id)}")
    print(f"Port Desc: {label(port_descr)} | {pbcopy_action(port_descr)}")

    if vlans:
        vlan_str = ', '.join(str(v) for v in vlans)
        print(f"VLANs: {label(vlan_str)} | {pbcopy_action(vlan_str)}")
        if pvid:
            print(f"PVID: {label(pvid)} | {pbcopy_action(pvid)} color=green")

    print("---")
    print(f"Host: {label(chassis_name)} | {pbcopy_action(chassis_name)}")
    print(f"Chassis ID: {label(chassis_id)} | {pbcopy_action(chassis_id)}")

    if mgmt_ips:
        print("Management IPs:")
        for ip in mgmt_ips:
            print(label(ip))
            render_switch_ip_actions(ip, ssh_user)

    if chassis_descr:
        print(f"System: {label(chassis_descr, 50)} | {pbcopy_action(chassis_descr)}")


# ─── netconfig (DHCP / static profile switcher) ─────────────────────────────
def normalize_profile(p):
    name = p.get('name')
    if not name:
        raise ValueError("missing 'name'")
    ip_raw = p.get('ip')
    if not ip_raw:
        raise ValueError("missing 'ip'")
    subnet = p.get('subnet')
    if '/' in str(ip_raw):
        spec = str(ip_raw)
    elif subnet:
        spec = f"{ip_raw}/{str(subnet).strip().lstrip('/')}"
    else:
        raise ValueError("missing 'subnet' (or use ip: x.x.x.x/NN)")
    try:
        iface = ipaddress.ip_interface(spec)
    except ValueError as e:
        raise ValueError(f"invalid ip/subnet: {e}")
    router = p.get('router')
    router = str(router).strip() if router else ''
    dns = p.get('dns')
    if isinstance(dns, str):
        dns = [d.strip() for d in dns.split(',') if d.strip()]
    return {'name': name, 'ip': str(iface.ip), 'subnet': str(iface.netmask), 'router': router, 'dns': dns}


def load_profiles():
    cfg_data, err = load_config()
    if err:
        return None, err
    out = []
    for p in cfg_data.get('profiles') or []:
        try:
            out.append(normalize_profile(p))
        except ValueError as e:
            return None, f"Profile '{p.get('name','?')}': {e}"
    return out, None


def get_network_services():
    """Return [(service_name, bsd_device), ...] for enabled services, in order.
    One `networksetup -listnetworkserviceorder` call provides both fields; disabled
    services have a `(*)` prefix and are skipped by the `^\\(\\d+\\)` match."""
    result = run_quiet([NETWORKSETUP, '-listnetworkserviceorder'])
    if result is None or result.returncode != 0:
        return []
    out, pending = [], None
    for line in result.stdout.splitlines():
        line = line.strip()
        m = re.match(r'^\(\d+\)\s+(.+)$', line)
        if m:
            pending = m.group(1).strip()
            continue
        if pending:
            m = re.search(r'Device:\s*([^\s,)]+)', line)
            if m:
                out.append((pending, m.group(1)))
                pending = None
    return out


def get_service_info(service):
    """Return {'method', 'ip'} for a service, or None if networksetup fails."""
    result = run_quiet([NETWORKSETUP, '-getinfo', service])
    if result is None or result.returncode != 0:
        return None
    info = {'method': 'Unknown', 'ip': ''}
    lines = result.stdout.splitlines()
    if lines:
        for tag in ('DHCP', 'Manual', 'BootP', 'Off'):
            if tag in lines[0]:
                info['method'] = tag
                break
    for line in lines:
        k, _, v = line.partition(':')
        if k.strip() == 'IP address':
            info['ip'] = v.strip()
    return info


def get_netconfig_state(iface_info):
    """Probe services whose device has an active link (per the shared ifconfig
    pass); return [(service_name, info), ...] in service order."""
    services = [s for s, dev in get_network_services()
                if (iface_info.get(dev) or {}).get('active')]
    if not services:
        return []
    with ThreadPoolExecutor(max_workers=8) as ex:
        infos = ex.map(get_service_info, services)
    return [(s, i) for s, i in zip(services, infos) if i]


def apply_profile(service, profile):
    subprocess.run([NETWORKSETUP, '-setmanual', service,
                    profile['ip'], profile['subnet'], profile['router']],
                   check=True, timeout=30)
    if profile['dns'] is None:
        return
    subprocess.run([NETWORKSETUP, '-setdnsservers', service, *(profile['dns'] or ['Empty'])],
                   check=True, timeout=30)


def cmd_apply(service, profile_name):
    profiles, err = load_profiles()
    if err:
        fail(err)
    match = next((p for p in profiles if p['name'] == profile_name), None)
    if not match:
        fail(f"Profile not found: {profile_name}")
    try:
        apply_profile(service, match)
        notify("LLDP-bar", f"{service} → {profile_name} ({match['ip']})")
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        fail(f"Failed: {e}")


def cmd_dhcp(service):
    try:
        subprocess.run([NETWORKSETUP, '-setdhcp', service], check=True, timeout=30)
        notify("LLDP-bar", f"{service} → DHCP")
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        fail(f"Failed: {e}")


def render_netconfig_section(active):
    profiles, err = load_profiles()

    print("IP Configuration | sfimage=network")
    if err:
        print(f"--⚠ {err}")
        print(f"--Open plugin folder | {action('/usr/bin/open', str(CONFIG_PATH.parent))}")
        return

    if not active:
        print("--No interfaces with active link")
        return

    for service, info in active:
        method = info['method']
        header = f"{service}  ·  {method}" + (f"  {info['ip']}" if info['ip'] else "")
        print(f"--{header}")

        dhcp_mark = '✓ ' if method == 'DHCP' else '   '
        print(f"----{dhcp_mark}DHCP | {action(_script_path, 'dhcp', service, refresh=True)}")

        if profiles:
            print("-------")
            for p in profiles:
                mark = '✓ ' if (method == 'Manual' and info['ip'] == p['ip']) else '   '
                print(f"----{mark}{p['name']}  ({p['ip']}) | {action(_script_path, 'apply', service, p['name'], refresh=True)}")

    if CONFIG_PATH.exists():
        print(f"--Edit {CONFIG_PATH.name} | {action('/usr/bin/open', str(CONFIG_PATH))}")
    else:
        print(f"--Create {CONFIG_PATH.name} (copy {CONFIG_EXAMPLE_PATH.name}) | {action('/usr/bin/open', str(PLUGIN_DIR))}")


# ─── SSH ────────────────────────────────────────────────────────────────────
def cmd_ssh(user, ip):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        notify("SSH", f"Invalid IP: {ip[:100]}")
        return
    env = os.environ.copy()
    env['LLDPBAR_SSH_CMD'] = f'ssh {shlex.quote(user)}@{ip}'
    subprocess.run([
        'osascript',
        '-e', 'tell application "Terminal" to do script (system attribute "LLDPBAR_SSH_CMD")',
        '-e', 'tell application "Terminal" to activate',
    ], env=env, check=False)


# ─── serial console ─────────────────────────────────────────────────────────
def render_serial_section():
    print("Serial Console | sfimage=terminal")
    ports = sorted(p for p in glob.glob('/dev/cu.*')
                   if not any(ex in p for ex in SERIAL_EXCLUDE))
    if not ports:
        print("--No serial ports detected")
        return
    try:
        rates = [int(r) for r in cfg('baud_rates', DEFAULT_BAUD_RATES)]
    except (TypeError, ValueError):
        rates = DEFAULT_BAUD_RATES
    for port in ports:
        print(f"--{port.replace('/dev/cu.', '')}")
        for rate in rates:
            print(f"----{rate} baud | {action(SCREEN, port, rate, terminal=True)}")


# ─── render & main ──────────────────────────────────────────────────────────
def render_footer(netconfig_state):
    print("---"); render_netconfig_section(netconfig_state)
    print("---"); render_serial_section()


def main():
    args = sys.argv[1:]
    if args:
        cmd, rest = args[0], args[1:]
        handlers = {'apply': (cmd_apply, 2), 'dhcp': (cmd_dhcp, 1),
                    'ssh': (cmd_ssh, 2), 'copy': (cmd_copy, 1)}
        func, arity = handlers.get(cmd, (None, -1))
        if func is None or len(rest) != arity:
            sys.exit(f"Unknown command: {args}")
        func(*rest)
        return

    # lldpcli is the slowest probe; run it concurrently with the ifconfig
    # pass and the networksetup fan-out (which is internally parallel).
    with ThreadPoolExecutor(max_workers=1) as pool:
        lldp_future = pool.submit(run_lldp_command)
        local_interfaces = get_interface_info()
        netconfig_state = get_netconfig_state(local_interfaces)
        data, lldp_err = lldp_future.result()

    print(" | sfimage=server.rack")
    print("---")

    if lldp_err:
        print(f"⚠ {lldp_err}")
        render_footer(netconfig_state)
        return

    all_interfaces = data.get('lldp', [{}])[0].get('interface', [])
    interfaces = [i for i in all_interfaces if not i.get('name', '').startswith('feth')]
    ssh_user = cfg('ssh_user', DEFAULT_SSH_USER)

    if not interfaces:
        print("No LLDP neighbors found")
        render_footer(netconfig_state)
        return

    for i, interface in enumerate(interfaces):
        render_lldp_neighbor(interface, local_interfaces, ssh_user)
        if i < len(interfaces) - 1:
            print("---")

    render_footer(netconfig_state)


if __name__ == "__main__":
    main()
