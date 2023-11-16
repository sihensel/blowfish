import random
import string
import subprocess

alphabet = string.ascii_letters + string.digits

def gen_plaintexts():
    ''' generate random 8-character plaintexts '''
    return [''.join(random.choice(alphabet) for _ in range(8)) for _ in range(1)]

p = gen_plaintexts()

# Compile Blowfish
def compile_blowfish():
    args = ("/usr/bin/gcc", "blowfish.c", "main.c", "-o", "./blowfish", "-lm")
    rc = subprocess.call(args)
    if rc != 0:
        print("Error compiling Blowfish")

compile_blowfish()

# get the hamming weights
result = []
for i in p:
    args = ("./blowfish", str(i))
    popen = subprocess.Popen(args, stdout=subprocess.PIPE)
    popen.wait()
    output = popen.stdout.read()
    print("Plaintext", i)
    print(output.decode())
    # result.append([i, output.decode()])

# print(result)
