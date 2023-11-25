import random
import string
import subprocess
import json
import os


def gen_plaintexts():
    alphabet = string.digits + string.ascii_letters
    return [''.join(random.choice(alphabet) for _ in range(8)) for _ in range(500)]


# Compile Blowfish
def compile_blowfish():
    args = ("/usr/bin/gcc", "blowfish.c", "main.c", "-o", "./blowfish", "-lm")
    rc = subprocess.call(args)
    if rc != 0:
        print("Error compiling Blowfish")
        exit()

# compile_blowfish()

# get the hamming weights after each Sbox for each plaintext
def gen_data():
    data = dict()
    p = gen_plaintexts()

    for i in p:
        args = ("./blowfish", i)
        result = subprocess.run(args, capture_output=True)
        data[i] = [int(i) for i in result.stdout.decode().split()]

    # make sure we have 500 different plaintexts
    assert len(data) == 500

    if not os.path.isfile("data.json"):
        with open("data.json", "w") as fp:
            json.dump(data, fp, indent=2)

guess = []
def model():
    with open("data.json", "r") as fp:
        data = json.load(fp)

    # test all possible keys for each plaintext
    for plaintext in data:
        args = ("./blowfish", plaintext)
        result = subprocess.run(args, capture_output=True)
        leakage = [int(i) for i in result.stdout.decode().split()]
        guess.extend([i for i, x in enumerate(leakage) if x == data[plaintext][3]])

    # FIXME this code is ugly, do this in numpy (which is also faster)
    # unique key guesses
    unique_guesses = set(guess)
    # map it in a dict with guess: count
    guess_dict = {}
    for i in unique_guesses:
        guess_dict[i] = guess.count(i)

    # sort it so the most popular guess is on top
    guess_dict = dict(sorted(guess_dict.items(), key=lambda x: x[1], reverse=True))

    # our first round key is 75ACA6F9
    for i, x in enumerate(guess_dict):
        print(f"{hex(x)}\t{guess_dict[x]}")
        if i == 4:
            break

model()
