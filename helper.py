import json
import random
import string
import subprocess
import numpy as np


NO_OF_PLAINTEXTS = 100


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
    plaintexts = [''.join(random.choice(alphabet) for _ in range(8)) for _ in range(NO_OF_PLAINTEXTS)]

    for plaintext in plaintexts:
        args = ("./blowfish", "encrypt", plaintext)
        result = subprocess.run(args, capture_output=True)
        lines = result.stdout.decode().split('\n')
        for line in lines:
            if line:
                values = [int(i) for i in line.split()]
                data[plaintext] = values

    # make sure we have no duplikate plaintexts
    assert len(data) == NO_OF_PLAINTEXTS

    with open("data.json", "w") as fp:
        json.dump(data, fp, indent=2)


def model():
    with open("data.json", "r") as fp:
        data = json.load(fp)

    # build the trace array (HW of intermediate values during first round)
    trace_array = []
    for i in data:
        trace_array.append(data[i])

    # get the hamming weight for a single key guess (in this case 0)
    hw_array = []
    for plaintext in data:
        args = ("./blowfish", "model", plaintext)
        result = subprocess.run(args, capture_output=True)
        hw = [int(i) for i in result.stdout.decode().split()]
        hw_array.append(hw)

    trace_array = np.array(trace_array)
    hw_array = np.array(hw_array)

    # get the correlation across all intermediate values for each key hypothesis
    for i in range(256):
        print("Keyguess: %X" % i)

        # we use 9 intermediate values
        # test only the seocond value for now (which is after the 1st sbox)
        for j in [1]:
            # take a vertical slice as a sample
            hw_sample = hw_array[:, i]
            trace_sample = trace_array[:, j]

            pearson_corr = np.corrcoef(trace_sample, hw_sample)
            print("{:.2f}".format(abs(pearson_corr[0, 1])))


# compile_blowfish()
gen_data()
model()
