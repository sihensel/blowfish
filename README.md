# BLOWFISH ENCRYPTION ALGORITHM

Fork of [https://github.com/prophet6250/blowfish-implementation](https://github.com/prophet6250/blowfish-implementation).

## Compile the code

```sh
gcc blowfish.c main.c -o ./blowfish -lm
```

## Usage

```sh
./blowfish <arg> <plaintext>
```

`<arg>` can take the following parameters:

| Arg | Description |
| --- | --- |
| `encrypt` | Performs a regular Blowfish encryption |
| `sbox` | Attack model when attacking round keys via sboxes |
| `xor` | Attack model when attacking round keys via XOR operations |
| `feistel` | Attack model when attacking the result of `f()` |
| `print_feistel` | Print the result of `f()` for a given input |

`<plaintext>` consists of 8 input bytes in decimal form, delimited by a space, such as `1 2 3 4 5 6 7 8`.

The encryption key is hardcoded in `main.c`.

## Countermeasures

Countermeasures are implemented in the `countermeasures` directory, which contains a separate copy of the code.
Here, the blowfish binary only takes `<plaintext>` as an argument and always performs a regular Blowfish encryption.

---

*ORIGINAL README BELOW*


## ABOUT
My Implementation of the 64-bit Blowfish Cryptographic block cipher

**This is(never was) not meant to be used in production code, nor as a source of reference**. 
This was purely a programming excercise. Mistakes & vulnerabilities are bound to creeep into this code. 
So don't use this code in professional environments.

## REQUIREMENTS
My machine has `GCC version 9.2.0`. Although, any C compiler, with support of ISO C11 may be used 
to compile this code, preferably GCC version 4.9+

## COMPILE AND RUN
`gcc blowfish.c main.c -o ./blow -lm`

`./blow`

## HOW TO CHANGE PREDEFINED INPUTS
Inside `main.c`, there are two macro definitions, namely `#define PLAINTEXT` and `#define KEY`. 
Edit these values with your own custom plaintext and key values. Keep in mind, keysize should not 
be greater than 56 characters (preferable less than 55).

## RESOURCES USED
1. https://morf.lv/introduction-to-data-encryption (basic feistel cipher and then Blowfish using Qt and C++)
