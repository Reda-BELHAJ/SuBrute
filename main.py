import argparse

import urllib
import os
import dns.resolver

def is_valid_file(parser, arg):
    if not os.path.exists(arg):
        parser.error("The file \u001b[31m%s\u001b[0m does not exist!" % arg)
    else:
        return open(arg, 'r')

def get_default_wordlist():
    url = 'https://raw.githubusercontent.com/Reda-BELHAJ/SuBrute/main/wordlist.txt'
    print(f'[+] \u001b[33mUsing Default Wordlist you can found it here: {url}\u001b[0m \n')

    def_array   = []
    response    = urllib.request.urlopen(url)

    for line in response:
        decoded_line = line.decode("utf-8").replace('\n', '')
        def_array.append(decoded_line)
    
    return def_array

def verbose_mode_check(args, sub, domain):
    if args.verbose:
        print(f'[-] {sub}.{domain} \u001b[31mInvalid\u001b[0m')

def more_mode_check(args, ip_value):
    if args.more:
        print('\t\t |-', ip_value.rrset.to_text().replace('\n', '\n\t |- '))

parser = argparse.ArgumentParser(description='\u001b[36mSuBrute is A Simple Subdomain Enumeration Tool \u001b[0m')

parser.add_argument('Dom',
                       metavar='Domain',
                       type=str,
                       help='Domain Name of the Taget [ex : example.com]')
parser.add_argument('--wordlist', '-w',
                        nargs='?', 
                        help='Local wordlist path', 
                        metavar="FILE",
                        type=lambda x: is_valid_file(parser, x))
parser.add_argument('--verbose', '-v',
                        help="Increase Output Verbosity",
                        action='store_true')
parser.add_argument('--more', '-m',
                        help="Display more information about the Taget",
                        action='store_true')

args            = parser.parse_args()

domain          = args.Dom
wordlist_file   = args.wordlist

sub_array       = []

wordlist_array = wordlist_file.read().splitlines() if wordlist_file else get_default_wordlist()

print('[+] \u001b[36mEnumerating subdomains :\u001b[0m')

for sub in wordlist_array:
    try:
        ip_value = dns.resolver.resolve(f'{sub}.{domain}', 'A')

        if ip_value:
            sub_array.append(f'{sub}.{domain}')
            if f"{sub}.{domain}" in sub_array:
                print(f'\t• {sub}.{domain} \u001b[32mValid\u001b[0m')
                more_mode_check(args, ip_value)
        else:
            verbose_mode_check(args, sub, domain)
    except dns.resolver.NXDOMAIN:
        verbose_mode_check(args, sub, domain)
    except dns.resolver.NoAnswer:
        verbose_mode_check(args, sub, domain)
    except KeyboardInterrupt:
        quit()

print(f'[+] \u001b[36mTotal Unique Subdomains Found: {len(sub_array)}\u001b[0m')