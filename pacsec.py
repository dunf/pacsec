#!/usr/bin/python

import subprocess
import requests
import argparse


URL = 'https://security.archlinux.org/'
VERSION = '0.1.2'


def args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-V', '--version', action='version',
                        version='%(prog)s v{}'.format(VERSION))
    return parser.parse_args()


def request_data(url):
    r = requests.get(url)
    data = r.json()
    return data


def parse_installed_packages():
    pkgs = {}
    with open('/tmp/pacsec.tmp') as file:

        for line in file:
            if line.startswith('local'):
                line = line.split(' ')
                package = line[0].split('/')[1]
                version = line[1].strip('\n')
                pkgs[package] = version
    return pkgs


def compare_pkg_data(pkgs, installed_packages):
    # For each package in Arch security tracker, check against installed packages
    print("PACKAGE{:<11} VERSION{:<7} SEVERITY{:<2} STATUS{:<9} FIX{:<10} CVE"
          .format('', '', '', '', ''))
    for pkg in pkgs:
        for p in pkg['packages']:
            installed_version = installed_packages.get(p)
            if installed_version == pkg['affected']:
                print("{:<18} {:<14} {:<10} {:<12} {:<2} {} {:<8} {}".format(
                    p,
                    pkg['affected'],
                    pkg['severity'],
                    pkg['status'],
                    '',
                    pkg['fixed'],
                    '',
                    pkg['issues']
                ))


def main(argv):
    subprocess.run(['/usr/bin/pacman -Qs > /tmp/pacsec.tmp'],
                   shell=True, stdout=subprocess.PIPE)
    installed_packages = parse_installed_packages()
    data = request_data(URL + 'json')
    compare_pkg_data(data, installed_packages)


if __name__ == '__main__':
    args = args()
    main(args)
