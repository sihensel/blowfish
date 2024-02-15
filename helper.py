import json
import subprocess
import numpy as np
from sage.all import *


NO_OF_PLAINTEXTS = 50


# Compile Blowfish
def compile_blowfish():
    args = ("/usr/bin/gcc", "blowfish.c", "main.c", "-o", "./blowfish", "-lm")
    rc = subprocess.call(args)
    if rc != 0:
        print("Error compiling Blowfish")
        exit()


def cpa():
    with open("data.json", "r") as fp:
        data = json.load(fp)

    trace_array = []
    for i in data:
        trace_array.append(data[i])

    hw_array = []
    for plaintext in data:
        args = ("./blowfish", "cpa", plaintext)
        result = subprocess.run(args, capture_output=True)
        hw = [int(i) for i in result.stdout.decode().split()]
        hw_array.append(hw)

    trace_array = np.array(trace_array)
    hw_array = np.array(hw_array)

    # get the correlation across all intermediate values for each key hypothesis
    all_corrs = []
    for i in range(256):

        corr = []
        # 9 intermediate values per round * 16 rounds + last 2 round keys = 146
        for j in range(146):
            # take a vertical slice as a sample
            hw_sample = hw_array[:, i]
            trace_sample = trace_array[:, j]

            pearson_corr = np.corrcoef(trace_sample, hw_sample)
            # print(float("%.2f" % abs(pearson_corr[0, 1])))
            corr.append(float("%.2f" % abs(pearson_corr[0, 1])))
        all_corrs.append(corr)

    # for i in all_corrs:
    #     print(i)
    all_corrs = np.array(all_corrs)
    print(all_corrs[:, 18])
    # get the value with the highest correlation
    key_guess = np.where(all_corrs == np.amax(all_corrs))

    print("Keyguess 0x%X, index %d" % (key_guess[0][0], key_guess[1][0]))


def reverse_engineer_sbox():
    R = IntegerModRing(2**32)
    # Y = [0x61ED6F99, 0x10A8021F, 0x59E97934]
    # Y = [0x936E4F71, 0xAC4F115B, 0x24DEE258]
    Y = [0xB4F3496B, 0x74067BEE, 0x61ED6F99]

    # for i in a:
    #     x = int.from_bytes(i.to_bytes(4, 'little'), 'big')
    #     Y.append(x)

    M = Matrix(R, [
        [1, 1, -2],
        [1, -2, 1],
        [-2, 1, 1]
    ])
    b = vector(R, [
        Y[0] + Y[1] - 2*Y[2],
        Y[0] - 2*Y[1] + Y[2],
        -2*Y[0] + Y[1] + Y[2]
    ])

    s = M.solve_right(b)
    print(s)
    for index, i in enumerate(s):
        print("%X" % i)
        a = (int(i) - Y[index]) % 2**32
        print("%X" % a)
        a = (int(i) + Y[index]) % 2**32
        print("%X" % a)
        a = (int(i) ^ Y[index]) % 2**32
        print("%X" % a)
        a = (int(i) * Y[index]) % 2**32
        print("%X" % a)
        print()
    print("actual value: %X" % 0x3D40B8A2)


# compile_blowfish()
# cpa()
reverse_engineer_sbox()
