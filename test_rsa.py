import unittest
from rsa import generate_keypair, encrypt, extended_euclidean, decrypt_trc, custom_pow

class TestRSA(unittest.TestCase):
    def setUp(self):
        # Using small prime numbers for testing
        self.p = 383
        self.q = 397
        self.key_pair = generate_keypair(self.p, self.q)

    def test_custom_pow(self):
        """Test the custom modular exponentiation function"""
        # Test basic cases
        self.assertEqual(custom_pow(2, 3, 5), 3)  # 2^3 mod 5 = 8 mod 5 = 3
        self.assertEqual(custom_pow(3, 4, 7), 4)  # 3^4 mod 7 = 81 mod 7 = 4
        
        # Test with large numbers
        self.assertEqual(custom_pow(7, 3, 10), 3)  # 7^3 mod 10 = 343 mod 10 = 3
        
        # Test with exponent 0
        self.assertEqual(custom_pow(5, 0, 7), 1)  # Any number^0 mod n = 1
        
        # Test with modulus 1
        self.assertEqual(custom_pow(5, 3, 1), 0)  # Any number mod 1 = 0
        
        # Test with base larger than modulus
        self.assertEqual(custom_pow(12, 3, 5), 3)  # 12^3 mod 5 = 1728 mod 5 = 3

        # Test with large exponent
        self.assertEqual(custom_pow(2, 10, 1000), 24)  # 2^10 mod 1000 = 1024 mod 1000 = 24

        # Test with negative base
        self.assertEqual(custom_pow(-2, 3, 5), 2)  # (-2)^3 mod 5 = -8 mod 5 = 2

        # Test with zero base
        self.assertEqual(custom_pow(0, 5, 7), 0)  # 0^5 mod 7 = 0

        # Test with RSA-like numbers
        n = self.key_pair.n
        e = self.key_pair.e
        d = self.key_pair.private_key
        message = 123
        ciphertext = custom_pow(message, e, n)
        decrypted = custom_pow(ciphertext, d, n)
        self.assertEqual(decrypted, message)

    def test_custom_pow_against_builtin(self):
        """Test that custom_pow gives the same results as built-in pow"""
        test_cases = [
            (2, 3, 5),
            (3, 4, 7),
            (7, 3, 10),
            (5, 0, 7),
            (12, 3, 5),
            (2, 10, 1000),
            (-2, 3, 5),
            (0, 5, 7),
        ]

        for base, exp, mod in test_cases:
            self.assertEqual(custom_pow(base, exp, mod), pow(base, exp, mod),
                           f"Failed for base={base}, exp={exp}, mod={mod}")

    def test_custom_pow_edge_cases(self):
        """Test edge cases for custom_pow"""
        # Test with very large numbers
        self.assertEqual(custom_pow(2, 100, 1000), pow(2, 100, 1000))

        # Test with base = modulus
        self.assertEqual(custom_pow(5, 3, 5), 0)  # 5^3 mod 5 = 0

        # Test with base = modulus + 1
        self.assertEqual(custom_pow(6, 3, 5), 1)  # 6^3 mod 5 = 1

        # Test with exponent = 1
        self.assertEqual(custom_pow(3, 1, 7), 3)  # 3^1 mod 7 = 3

        # Test with exponent = 2
        self.assertEqual(custom_pow(3, 2, 7), 2)  # 3^2 mod 7 = 9 mod 7 = 2

    def test_extended_euclidean(self):
        """Test the extended Euclidean algorithm"""
        # Test case 1: Basic case
        gcd, x, y = extended_euclidean(48, 18)
        self.assertEqual(gcd, 6)
        self.assertEqual(48 * x + 18 * y, gcd)

        # Test case 2: Coprime numbers
        gcd, x, y = extended_euclidean(7, 5)
        self.assertEqual(gcd, 1)
        self.assertEqual(7 * x + 5 * y, gcd)

        # Test case 3: Same numbers
        gcd, x, y = extended_euclidean(10, 10)
        self.assertEqual(gcd, 10)
        self.assertEqual(10 * x + 10 * y, gcd)

        # Test case 4: RSA primes
        gcd, x, y = extended_euclidean(self.p, self.q)
        self.assertEqual(gcd, 1)  # Primes should be coprime
        self.assertEqual(self.p * x + self.q * y, gcd)

    def test_key_pair_generation(self):
        """Test that key pair is generated correctly"""
        self.assertEqual(self.key_pair.p, self.p)
        self.assertEqual(self.key_pair.q, self.q)
        self.assertEqual(self.key_pair.n, self.p * self.q)
        self.assertEqual(self.key_pair.phi, (self.p - 1) * (self.q - 1))
        
        # Test that e and d are valid
        self.assertTrue(1 < self.key_pair.e < self.key_pair.phi)
        self.assertTrue(1 < self.key_pair.d < self.key_pair.phi)
        
        # Test that e and d are multiplicative inverses
        self.assertEqual((self.key_pair.e * self.key_pair.d) % self.key_pair.phi, 1)

    def test_encryption_decryption(self):
        """Test that encryption and decryption work correctly"""
        message = 123
        n, e = self.key_pair.public_key
        d = self.key_pair.private_key

        # Encrypt
        ciphertext = encrypt(message, self.key_pair.public_key)
        
        # Decrypt using standard method
        decrypted = pow(ciphertext, d, n)
        self.assertEqual(decrypted, message)
        
        # Decrypt using Chinese Remainder Theorem
        decrypted_trc = decrypt_trc(ciphertext, self.key_pair)
        self.assertEqual(decrypted_trc, message)

    def test_multiple_messages(self):
        """Test encryption/decryption with multiple messages"""
        messages = [42, 123, 456, 789]
        n, e = self.key_pair.public_key
        d = self.key_pair.private_key

        for message in messages:
            ciphertext = encrypt(message, self.key_pair.public_key)
            
            # Test standard decryption
            decrypted = pow(ciphertext, d, n)
            self.assertEqual(decrypted, message)
            
            # Test CRT decryption
            decrypted_trc = decrypt_trc(ciphertext, self.key_pair)
            self.assertEqual(decrypted_trc, message)

    def test_message_limits(self):
        """Test that messages larger than n are handled correctly"""
        n, e = self.key_pair.public_key
        d = self.key_pair.private_key

        # Test with message equal to n
        message = n
        ciphertext = encrypt(message, self.key_pair.public_key)
        decrypted = pow(ciphertext, d, n)
        decrypted_trc = decrypt_trc(ciphertext, self.key_pair)
        self.assertEqual(decrypted, 0)  # Because n mod n = 0
        self.assertEqual(decrypted_trc, 0)

        # Test with message larger than n
        message = n + 1
        ciphertext = encrypt(message, self.key_pair.public_key)
        decrypted = pow(ciphertext, d, n)
        decrypted_trc = decrypt_trc(ciphertext, self.key_pair)
        self.assertEqual(decrypted, 1)  # Because (n+1) mod n = 1
        self.assertEqual(decrypted_trc, 1)

    def test_crt_decryption_components(self):
        """Test the components of CRT decryption"""
        message = 123
        ciphertext = encrypt(message, self.key_pair.public_key)
        
        # Get CRT components
        p = self.key_pair.p
        q = self.key_pair.q
        d = self.key_pair.private_key
        n = self.key_pair.n
        
        dp = d % (p - 1)
        dq = d % (q - 1)
        
        # Test that dp and dq are correct
        self.assertEqual(dp, d % (p - 1))
        self.assertEqual(dq, d % (q - 1))
        
        # Test that Bézout coefficients are correct
        _, n1, n2 = extended_euclidean(p, q)
        self.assertEqual(p * n1 + q * n2, 1)

if __name__ == '__main__':
    unittest.main() 