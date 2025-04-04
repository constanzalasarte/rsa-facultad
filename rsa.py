from math import gcd
from sympy import mod_inverse


def get_e_value(phi):
    for e in range(1, phi):
        # This is the formula to check if e is coprime with phi
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
