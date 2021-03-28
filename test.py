import os
import string
import random

# Usernames generator
def username_generator(size=8, chars=string.ascii_lowercase):
    return ''.join(random.choice(chars) for _ in range(size))

# Generate usernames
usernames = ['205644941', 'botvimar'] + [username_generator() for i in range(28)]

# Test
for i, username in enumerate(usernames):
    print(f'------------------ username {i+1}/{len(usernames)}: {username} ------------------')
    os.system(f'python .\\aoi_ass1.py {username}')