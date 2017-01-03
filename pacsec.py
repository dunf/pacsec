#!/usr/bin/python

import subprocess
import requests
import argparse


URL = 'https://security.archlinux.org/'
VERSION = '0.2.0'


def args():
    parser = argparse.ArgumentParser()
    mu = parser.add_mutually_exclusive_group()
    parser.add_argument('-V', '--version', action='version', version='%(prog)s v{}'.format(VERSION))
    mu.add_argument('-d', '--default', action='store_true', default=True)
    mu.add_argument('-s', '--summary', action='store_true', help='show summary of information')
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
    # For each pkg in the Arch security tracker, check against installed pkgs
    info = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
    for pkg in pkgs:
        for p in pkg['packages']:
            installed_version = installed_packages.get(p)
            if installed_version == pkg['affected'] and 'Not affected' not in pkg['status']:
                if args.summary:
                    info[pkg['severity']] += 1
                elif args.default:
                    print('PACKAGE: {:<16}{}'.format('', p))
                    print('AFFECTED VERSION: {:<7}{}'.format('', pkg['affected']))
                    print('FIX: {:<20}{}'.format('', pkg['fixed']))
                    print('STATUS: {:<17}{}'.format('', pkg['status']))
                    print('VULNERABILITY: {:<10}{}'.format('', pkg['type']))
                    print('SEVERITY: {:<15}{}'.format('', pkg['severity']))
                    print('CVE: {:<20}{}\n'.format('', ', '.join(pkg['issues'])))
    if args.summary:
        print('Critical severity: {:>4}'.format(info.get('Critical')))
        print('High severity: {:>8}'.format(info.get('High')))
        print('Medium severity: {:>6}'.format(info.get('Medium')))
        print('Low severity: {:>9}'.format(info.get('Low')))
        print('Vulnerable packages:  {}'.format(sum(info.values())))

def main():
    subprocess.run(['/usr/bin/pacman -Qs > /tmp/pacsec.tmp'], shell=True, stdout=subprocess.PIPE)
    installed_packages = parse_installed_packages()
    data = request_data(URL + 'json')
    compare_pkg_data(data, installed_packages)


if __name__ == '__main__':
    args = args()
    main()
