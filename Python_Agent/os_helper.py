import hashlib
import os
import platform
import re
from os.path import isfile
from pathlib import Path
from enum import Enum
import pkg_resources


class CloudProvider(Enum):
    NONE = 0
    AMAZON = 1
    GOOGLE = 2
    MICROSOFT = 3


def get_os_release():
    """
    Returns a dict with the following items:
    distro: Concrete distro name. Examples: raspbian, ubuntu, debian, ubuntu-core.
    version: Short, numerical version. Examples: 9, 18.04, 18.
    distro_root: The root distro (from which the distro was branched). Optional. Examples: debian.
    full_version: Longer, human-readable version. Optional. Examples (last one is from ubuntu-core):
        "9 (stretch)", "18.04.3 LTS (Bionic Beaver)", 18
    codename: Distro version codename. Optional. Examples: stretch, bionic.
    """

    os_release = Path('/etc/os-release')
    # Normally this file should be present on any Linux system starting with Jessie (and not only Debian).

    # But we may be running in some pre-2012 system...
    if not os_release.is_file():
        # hopefully Python can give us at least some info
        # FIXME: linux_distribution is removed since Python 3.7
        name, version, codename = platform.linux_distribution()
        return {'distro': name, 'version': version, 'codename': codename}

    PARAM_NAMES = {
        'ID': 'distro',
        'ID_LIKE': 'distro_root',
        'VERSION_ID': 'version',
        'VERSION': 'full_version',
        'VERSION_CODENAME': 'codename'
    }
    with os_release.open() as os_release_file:
        lines = os_release_file.read().splitlines()
        os_info = {PARAM_NAMES[param]: value.strip('"') for param, value in map(
            lambda line: line.split('=', 1), lines) if param in PARAM_NAMES}
        # Set proper codename for Debian/Raspbian Jessie.
        if 'codename' not in os_info and os_info.get('distro', '') in ('debian', 'raspbian') and \
                os_info.get('version', '') == '8':
            os_info['codename'] = 'jessie'
        # Set proper codename for Amazon Linux 2.
        if 'codename' not in os_info and os_info.get('distro', '') == 'amzn' and os_info.get('version', '') == '2':
            os_info['codename'] = 'amzn2'
        return os_info


def is_debian():
    os_release = get_os_release()
    return os_release.get('distro_root', os_release['distro']) == 'debian'




def detect_cloud():
    bios_version = Path('/sys/devices/virtual/dmi/id/bios_version')
    if bios_version.is_file():
        bios_version = bios_version.read_text().strip()
        if bios_version == 'Google':
            return CloudProvider.GOOGLE
        elif bios_version.endswith('.amazon'):
            return CloudProvider.AMAZON
        else:
            chassis = Path('/sys/devices/virtual/dmi/id/chassis_asset_tag')
            if chassis.is_file() and chassis.read_text().strip() == '7783-7084-3265-9085-8269-3286-77':
                return CloudProvider.MICROSOFT
    return CloudProvider.NONE




def kernel_cmdline():
    """
    Parses kernel parameters (aka cmdline).
    :return: A dict where 'name' is kernel parameter name and 'value' is its value or empty string if no value provided.
    """
    cmdline_path = Path('/proc/cmdline')
    cmdline_matches = re.compile(r"([\w\-\.]+)(\=(\"[\w\W]+\"|[\w\S]+)?)?").findall(cmdline_path.read_text())
    return {name: value.strip('"') for name, _, value in cmdline_matches}


