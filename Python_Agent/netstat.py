import copy
import crypt
import logging
import os
import shutil
import socket
import subprocess
import time
from hashlib import sha256
from pathlib import Path
from socket import SocketKind

import psutil
import spwd
from sh import ErrorReturnCode_1, ErrorReturnCode_255

from os_helper import CloudProvider, detect_cloud, is_debian, kernel_cmdline

def netstat_scan():
    """
    Returns all open inet connections with their addresses and PIDs.
    """
    count = 0
    connections = psutil.net_connections(kind='inet')
    return (
        [{
            'ip_version': 4 if c.family == socket.AF_INET else 6,
            'type': 'udp' if c.type == socket.SOCK_DGRAM else 'tcp',
            'local_address': c.laddr,
            'remote_address': c.raddr,
            'status': c.status if c.type == socket.SOCK_STREAM else None,
            'pid': c.pid
        } for c in connections if c.raddr],
        [{
            'ip_version': 4 if c.family == socket.AF_INET else 6,
            'host': c.laddr[0],
            'port': c.laddr[1],
            'proto': {SocketKind.SOCK_STREAM: 'tcp', SocketKind.SOCK_DGRAM: 'udp'}.get(c.type),
            'state': c.status if c.type == socket.SOCK_STREAM else None,
            'pid': c.pid
        } for c in connections if not c.raddr and c.laddr]
    )

def process_scan():
    processes = []
    for proc in psutil.process_iter():
        try:
            proc_info = proc.as_dict(attrs=['pid', 'name', 'cmdline', 'username'])
            cpuset = Path('/proc/{}/cpuset'.format(proc_info['pid']))
            if cpuset.exists():
                with cpuset.open() as cpuset_file:
                    if cpuset_file.read().startswith('/docker/'):
                        proc_info['container'] = 'docker'
            processes.append(proc_info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return processes

def cpu_vulnerabilities():
    """
    Query sysfs for CPU vulnerabilities mitigation.
    :return: A dict where
        'vendor': "Vendor ID" field returned by lscpu. Possible values: GenuineIntel, AuthenticAMD, ARM.
        'vulnerable': False if not vulnerable, True if vulnerable, None if in doubt. Present if vendor is GenuineIntel.
        'mitigations_disabled': whether any mitigation was disabled in kernel cmdline. Present if vulnerable is None.
    """
    from sh import lscpu
    os.environ['LC_ALL'] = 'en_US'  # switch language to English to be able to parse lscpu output.
    vendor_id = None
    for line in lscpu().stdout.decode().split('\n'):
        param = line.split(':', 1)
        if param and param[0] == 'Vendor ID':
            vendor_id = param[1].strip()
            break
    # TODO: switch LC_ALL back?

    res = {'vendor': vendor_id}
    if vendor_id != "GenuineIntel":
        # Not an Intel CPU, most probably not vulnerable
        return res

    sys_vulnerabilities = Path('/sys/devices/system/cpu/vulnerabilities')
    if not sys_vulnerabilities.is_dir():
        # Directory does not exist: either smth is bind-mounted over it or the kernel is too old.
        vulnerable = None
    else:
        vulnerable = False
        vulns = ['l1tf', 'meltdown', 'spectre_v1', 'spectre_v2']
        if detect_cloud() != CloudProvider.AMAZON:
            # AWS reports no mitigation for those vulnerabilities, as if they are not mitigated at all.
            # But we decided to trust AWS and assume it's not vulnerable.
            vulns += ['spec_store_bypass', 'mds']
        for name in vulns:
            status_file = sys_vulnerabilities / name
            if status_file.is_file():
                # If CPU is not prone to this vulnerability the status file will start with
                # 'Not affected' or 'Mitigation: ...'. Otherwise it will start with 'Vulnerable: ...'.
                if status_file.read_text().startswith('Vulnerable'):
                    vulnerable = True
                    break
            else:
                # Status file does not exist: smth is bind-mounted over it or the kernel is not completely patched.
                vulnerable = None
                break

    res['vulnerable'] = vulnerable

    # If we can't confidently tell if CPU is vulnerable we search cmdline for mitigation disablement params and let
    # the server do the rest.
    if vulnerable is None:
        mitigations_disabled = False
        mitigation_cmdline_params = {
            'nopti': '',
            'nospectre_v1': '',
            'nospectre_v2': '',
            'mds': 'off',
            'pti': 'off',
            'mitigations': 'off',
            'spectre_v2': 'off',
            'spectre_v2_user': 'off',
            'spec_store_bypass_disable': 'off'
        }
        cmdline = kernel_cmdline()
        for pname, pvalue in mitigation_cmdline_params.items():
            if cmdline.get(pname) == pvalue:
                mitigations_disabled = True
                break
        res['mitigations_disabled'] = mitigations_disabled

    return res

def is_app_armor_enabled():
    """
    Returns a True/False if AppArmor is enabled.
    """
    try:
        import LibAppArmor
    except ImportError:
        # If Python bindings for AppArmor are not installed (if we're
        # running on Jessie where we can't build python3-apparmor package)
        # we resort to calling aa-status executable.
        try:
            from sh import aa_status
        except ImportError:
            return False

        # Return codes (as per aa-status(8)):
        # 0   if apparmor is enabled and policy is loaded.
        # 1   if apparmor is not enabled/loaded.
        # 2   if apparmor is enabled but no policy is loaded.
        # 3   if the apparmor control files aren't available under /sys/kernel/security/.
        # 4   if the user running the script doesn't have enough privileges to read the apparmor
        #    control files.
        return aa_status(['--enabled'], _ok_code=[0, 1, 2, 3, 4]).exit_code in [0, 2]
    else:
        return LibAppArmor.aa_is_enabled() == 1

def selinux_status():
    """
    Returns a dict as similar to:
        {'enabled': False, 'mode': 'enforcing'}
    """
    selinux_enabled = False
    selinux_mode = None

    try:
        import selinux
    except ImportError:
        # If Python bindings for SELinux are not installed (if we're
        # running on Jessie where we can't build python3-selinux package)
        # we resort to calling sestatus executable.
        try:
            from sh import sestatus
        except ImportError:
            return {'enabled': False}

        # Manually parse out the output for SELinux status
        for line in sestatus().stdout.split(b'\n'):
            row = line.split(b':')

            if row[0].startswith(b'SELinux status'):
                selinux_enabled = row[1].strip() == b'enabled'

            if row[0].startswith(b'Current mode'):
                selinux_mode = row[1].strip()
    else:
        if selinux.is_selinux_enabled() == 1:
            selinux_enabled = True
            selinux_mode = {-1: None, 0: 'permissive', 1: 'enforcing'}[selinux.security_getenforce()]
    return {'enabled': selinux_enabled, 'mode': selinux_mode}



