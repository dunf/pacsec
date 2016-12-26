#!/usr/bin/python

import subprocess
import requests
import argparse


URL = 'https://security.archlinux.org/'
VERSION = '0.1.3'


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
    for pkg in pkgs:
        for p in pkg['packages']:
            installed_version = installed_packages.get(p)
            if installed_version == pkg['affected']:
                print('PACKAGE: {:<16}{}'.format('', p))
                print('AFFECTED VERSION: {:<7}{}'.format('', pkg['affected']))
                print('FIX: {:<20}{}'.format('', pkg['fixed']))
                print('STATUS: {:<17}{}'.format('', pkg['status']))
                print('VULNERABILITY: {:<10}{}'.format('', pkg['type']))
                print('SEVERITY: {:<15}{}'.format('', pkg['severity']))
                print('CVE: {:<20}{}\n'.format('', ', '.join(pkg['issues'])))


def main():
    subprocess.run(['/usr/bin/pacman -Qs > /tmp/pacsec.tmp'],
                   shell=True, stdout=subprocess.PIPE)
    installed_packages = parse_installed_packages()
    data = request_data(URL + 'json')
    compare_pkg_data(data, installed_packages)


if __name__ == '__main__':
    args = args()
    main()
