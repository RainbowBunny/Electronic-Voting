from Crypto.Util.number import GCD, getPrime
from random import randint
from elliptic_curve import ECCPoint
from hashlib import sha256

def get_random_relatively_prime_value(q: int) -> int:
    while True:
        rand = randint(1, q - 1)
        if GCD(rand, q) == 1:
            return rand

def generate_random_rsa_key() -> (int, int, int):
    while True:
        p = getPrime(1024)
        q = getPrime(1024)
        e = 65537
        if (p - 1) * (q - 1) % e == 0:
            continue
        return (p, q, e)

def hash_array_of_points(arr: list[ECCPoint], p) -> int:
    return sum([pow(point.x, point.y, p) for point in arr])

def generate_tuple(sum: int, n: int) -> list[list[int]]:
    if n == 1:
        return [[i] for i in range(sum + 1)]
    
    ans = []
    for i in range(sum + 1):
        sublist = generate_tuple(sum - i, n - 1)
        for j in sublist:
            ans.append(j + [i])
    return ans