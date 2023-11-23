import random
import string
import subprocess
import json
import os

alphabet = string.digits + string.ascii_letters

def gen_plaintexts():
    ''' generate random 8-character plaintexts '''
    return [''.join(random.choice(alphabet) for _ in range(8)) for _ in range(500)]

p = gen_plaintexts()

# Compile Blowfish
def compile_blowfish():
    args = ("/usr/bin/gcc", "blowfish.c", "main.c", "-o", "./blowfish", "-lm")
    rc = subprocess.call(args)
    if rc != 0:
        print("Error compiling Blowfish")
        exit()

# compile_blowfish()

# get the hamming weights after each Sbox for each plaintext
data = dict()
for i in p:
    args = ("./blowfish", i)
    result = subprocess.run(args, capture_output=True)
    data[i] = [int(i) for i in result.stdout.decode().split()]

# make sure we have 500 different plaintexts
assert len(data) == 500

if not os.path.isfile("data.json"):
    with open("data.json", "w") as fp:
        json.dump(data, fp, indent=2)
