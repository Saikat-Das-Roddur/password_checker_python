from itertools import count
import re
import requests
import hashlib
import sys

def request_api_data(query_pass):
    res = requests.get('https://api.pwnedpasswords.com/range/'+query_pass)
    if res.status_code != 200:
        raise RuntimeError(f'fetching error: {res.status_code}, check the api and try again')
    return res

def get_pass_leak_counts(res, hash_to_check):
    res = (line.split(':') for line in res.text.splitlines())
    for h, count in res:
        if h==hash_to_check:
            return count
    return 0

def pawned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5],sha1password[5:]
    res = request_api_data(first5_char)
    return get_pass_leak_counts(res, tail)


def main(args):
    for password in args:
        count =  pawned_api_check(password)
        if count:
            print(f'{password} was found {count} times... you should probably change your password!')
        else:
            print(f'{password} was not found. Carry on!')



main(sys.argv[1:])