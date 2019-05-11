#!/usr/bin/env python

import sys
import subprocess
import requests
import argparse


URL = 'https://security.archlinux.org/issues/all/'
VERSION = '0.3.4'


def args():
    parser = argparse.ArgumentParser()
    mu = parser.add_mutually_exclusive_group()
    parser.add_argument(
        '-V', '-v', '--version', action='version', version='%(prog)s v{}'.format(VERSION))
    mu.add_argument('-s', '--summary', action='store_true', help='show summary of information')
    mu.add_argument('-f', '--fix', action='store_true',
                    help='show only vulnerabilities that have an available fix.')
    return parser.parse_args()


def request_data(url):
    try:
        r = requests.get(url)
        data = r.json()
        return data
    except requests.ConnectionError:
        print('No connection')
        sys.exit(1)


def parse_installed_packages(file):
    pkgs = {}
    for line in file:
        line = line.split(' ')
        package = line[0]
        version = line[1].strip('\n')
        pkgs[package] = version
    return pkgs


def compare_pkg_data(pkgs, installed_packages):
    # For each pkg in the Arch security tracker, check against installed pkgs
    info = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Unknown': 0}

    for pkg in pkgs:
        for p in pkg['packages']:
            installed_version = installed_packages.get(p)

            if installed_version == pkg['affected'] and 'Not affected' not in pkg['status']:
                if args.summary:
                    info[pkg['severity']] += 1
                elif args.fix:
                    if pkg['fixed'] is not None and 'Testing' not in pkg['status']:
                        default_output(p, pkg)
                else:   # No arguments
                    default_output(p, pkg)
    if args.summary:
        print('Critical severity: {:>4}'.format(info.get('Critical')))
        print('High severity: {:>8}'.format(info.get('High')))
        print('Medium severity: {:>6}'.format(info.get('Medium')))
        print('Low severity: {:>9}'.format(info.get('Low')))
        print('Unknown: {:>14}'.format(info.get('Unknown')))
        print('Vulnerable packages:  {}'.format(sum(info.values())))


def default_output(*pkg):
    print('PACKAGE: {:<16}{}'.format('', pkg[0]))
    print('AFFECTED VERSION: {:<7}{}'.format('', pkg[1].get('affected')))
    print('FIX: {:<20}{}'.format('', pkg[1].get('fixed')))
    print('STATUS: {:<17}{}'.format('', str(pkg[1].get('status'))))
    print('VULNERABILITY: {:<10}{}'.format('', pkg[1].get('type')))
    print('SEVERITY: {:<15}{}'.format('', pkg[1].get('severity')))
    print('CVE: {:<20}{}\n'.format('', ', '.join(pkg[1].get('issues'))))


def main():
    subprocess.run(['/usr/bin/pacman -Q > /tmp/pacsec.tmp'], shell=True, stdout=subprocess.PIPE)

    with open('/tmp/pacsec.tmp') as file:
        installed_packages = parse_installed_packages(file)

    data = request_data(URL + 'json')
    compare_pkg_data(data, installed_packages)


if __name__ == '__main__':
    args = args()
    main()
