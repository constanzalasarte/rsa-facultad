import random
from math import gcd
from sympy import mod_inverse


def get_e_value(phi):
    while True:
        e = random.randint(2, phi - 1)
        if gcd(e, phi) == 1:
            return e


class RSAKeyPair:
    def __init__(self, p, q):
        self.p = p
        self.q = q
        self.n = p * q
        self.phi = (p - 1) * (q - 1)

        self.e = get_e_value(self.phi)
        self.d = mod_inverse(self.e, self.phi)

        self.public_key = (self.n, self.e)
        self.private_key = self.d
    def __str__(self):
        return f"RSAKeyPair(p={self.p}, q={self.q}, n={self.n}, phi={self.phi}, e={self.e}, d={self.d}, public_key={self.public_key}, private_key={self.private_key})"

def encrypt(message, public_key):
    n, e = public_key

    return pow(message, e, n)

def generate_keypair(p, q):
    return RSAKeyPair(p, q)

if __name__ == "__main__":
    p = 61  # Example prime number
    q = 53  # Another example prime number

    key_pair = generate_keypair(p, q)
    print(key_pair)
    public_key = key_pair.public_key
    private_key = key_pair.private_key
    n = key_pair.n

    message = 123
    print(f"Original Message: {message}")

    ciphertext = encrypt(message, public_key)
    print(f"Ciphertext: {ciphertext}")

