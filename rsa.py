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


def extended_euclidean(a, b):
    if b == 0:
        return a, 1, 0
    else:
        gcd, x1, y1 = extended_euclidean(b, a % b)
        x = y1
        y = x1 - (a // b) * y1
        return gcd, x, y


def decrypt_trc(ciphertext, key_pair):
    p = key_pair.p
    q = key_pair.q
    d = key_pair.private_key
    n = key_pair.n

    dp = d % (p - 1)
    dq = d % (q - 1)

    a1 = pow(ciphertext % p, dp, p)
    a2 = pow(ciphertext % q, dq, q)

    # Coeficientes de Bézout: n1*p + n2*q = 1
    _, n1, n2 = extended_euclidean(p, q)

    m = (a1 * n2 * q + a2 * n1 * p) % n

    return m


if __name__ == "__main__":
    p = 383  # Example prime number
    q = 397  # Another example prime number

    key_pair = generate_keypair(p, q)
    print(key_pair)
    public_key = key_pair.public_key
    private_key = key_pair.private_key
    n = key_pair.n

    message = 123456
    print(f"Original Message: {message}")

    ciphertext = encrypt(message, public_key)
    print(f"Ciphertext: {ciphertext}")

    decrypted_message = decrypt_trc(ciphertext, key_pair)
    print(f"Deciphered message: {decrypted_message}")
