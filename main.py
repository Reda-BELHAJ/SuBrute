import argparse
from traceback import print_tb

import urllib
import os
import dns.resolver

def is_valid_file(parser, arg):
    if not os.path.exists(arg):
        parser.error("The file \u001b[31m%s\u001b[0m does not exist!" % arg)
    else:
        return open(arg, 'r')

def get_default_wordlist():
    url = 'https://raw.githubusercontent.com/rbsec/dnscan/master/subdomains-1000.txt'
    print(f'\u001b[33mUsing Default Wordlist you can found it here: {url}\u001b[0m \n')

    def_array   = []
    response    = urllib.request.urlopen(url)

    for line in response:
        decoded_line = line.decode("utf-8").replace('\n', '')
        def_array.append(decoded_line)
    
    return def_array

def verbose_mode_check(args, sub, domain):
    if args.verbose:
        print(f'[-] {sub}.{domain} \u001b[31mInvalid\u001b[0m')

parser = argparse.ArgumentParser(description='\u001b[36mSuBrute is A Simple Subdomain Enumeration Tool \u001b[0m')
parser.add_argument('Dom',
                       metavar='Domain',
                       type=str,
                       help='Domain Name of the Taget [ex : example.com]')
parser.add_argument('-w', '--wordlist', 
                        nargs='?', 
                        help='Wordlist', 
                        metavar="FILE",
                        type=lambda x: is_valid_file(parser, x))
parser.add_argument('--verbose', '-v',
                        help="Increase Output Verbosity",
                        action='store_true')
parser.add_argument('--more', '-m',
                        help="",
                        action='store_true')

args            = parser.parse_args()

domain          = args.Dom
wordlist_file   = args.wordlist

sub_array       = []

wordlist_array = wordlist_file.read().splitlines() if wordlist_file else get_default_wordlist()

for sub in wordlist_array:
    try:
        ip_value = dns.resolver.resolve(f'{sub}.{domain}', 'A')

        if ip_value:
            sub_array.append(f'{sub}.{domain}')
            if f"{sub}.{domain}" in sub_array:
                print(f'[+] {sub}.{domain} \u001b[32mValid\u001b[0m')
                if args.more:
                    info = ip_value.rrset.to_text().replace('\n', '\n\t')
                    print(f'\t{info}')
        else:
            verbose_mode_check(args, sub, domain)
    except dns.resolver.NXDOMAIN:
        verbose_mode_check(args, sub, domain)
    except dns.resolver.NoAnswer:
        verbose_mode_check(args, sub, domain)
    except KeyboardInterrupt:
        quit()