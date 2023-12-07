import json
import random
import string
import subprocess
import numpy as np


NO_OF_PLAINTEXTS = 50


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

    # make sure we have no duplicate plaintexts
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

    for key_byte in range(4):

        hw_array = []
        for plaintext in data:
            args = ("./blowfish", "model", plaintext)
            result = subprocess.run(args, capture_output=True)
            lines = result.stdout.decode().split("\n")[:-1]
            hw = [int(i) for i in lines[key_byte].split()]
            hw_array.append(hw)

        trace_array = np.array(trace_array)
        hw_array = np.array(hw_array)

        # get the correlation across all intermediate values for each key hypothesis
        all_corrs = []
        for i in range(256):

            corr = []
            # 9 intermediate values per round * 16 rounds = 144
            for j in range(144):
                # take a vertical slice as a sample
                hw_sample = hw_array[:, i]
                trace_sample = trace_array[:, j]

                pearson_corr = np.corrcoef(trace_sample, hw_sample)
                corr.append(float("%.2f" % abs(pearson_corr[0, 1])))
            all_corrs.append(corr)

        all_corrs = np.array(all_corrs)
        # get the value with the highest correlation
        key_guess = np.where(all_corrs == np.amax(all_corrs))

        print("Keyguess 0x%X, index %d" % (key_guess[0][0], key_guess[1][0]))


compile_blowfish()
# gen_data()
model()
