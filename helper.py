import json
import random
import string
import subprocess


# Compile Blowfish
def compile_blowfish():
    args = ("/usr/bin/gcc", "blowfish.c", "main.c", "-o", "./blowfish", "-lm")
    rc = subprocess.call(args)
    if rc != 0:
        print("Error compiling Blowfish")
        exit()


# get the hamming weights after each Sbox for each plaintext
def gen_data():
    data = dict()
    alphabet = string.digits + string.ascii_letters
    p = [''.join(random.choice(alphabet) for _ in range(8)) for _ in range(100)]

    for i in p:
        args = ("./blowfish", "encrypt", i)
        result = subprocess.run(args, capture_output=True)
        data[i] = [int(i) for i in result.stdout.decode().split()]

    # make sure we have 100 different plaintexts
    assert len(data) == 100

    with open("data.json", "w") as fp:
        json.dump(data, fp, indent=2)


def model():
    with open("data.json", "r") as fp:
        data = json.load(fp)

    guess_dict = {}
    # test all possible keys for each plaintext
    for plaintext in data:
        args = ("./blowfish", "model", plaintext)
        result = subprocess.run(args, capture_output=True)
        lines = result.stdout.decode().split("\n")[:4]

        guess_dict[plaintext] = {}

        for index, line in enumerate(lines):
            leakage = [int(i) for i in line.split()]
            guess = [i for i, x in enumerate(leakage) if x == data[plaintext][index]]
            guess_dict[plaintext][index] = guess

    # FIXME this code is ugly, do this in numpy (which is also faster)
    # unique key guesses
    for i in range(4):
        all_guesses = []
        for item in guess_dict:
            all_guesses.extend(guess_dict[item][i])

        unique_guesses = set(all_guesses)
        a = {}
        for x in unique_guesses:
            a[x] = all_guesses.count(x)

        a = dict(sorted(a.items(), key=lambda x: x[1], reverse=True))

        print("Key hypothesis for keybyte %d" % i)
        for index, x in enumerate(a):
            print("%X\t%d" % (x, a[x]))
            if index == 3:
                break

compile_blowfish()
gen_data()
model()
