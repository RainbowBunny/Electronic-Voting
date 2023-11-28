from functools import reduce
from hashlib import sha256
from random import shuffle
from elliptic_curve import EllipticCurve, ECCPoint
from itertools import combinations_with_replacement
from utils import get_random_relatively_prime_value, generate_random_rsa_key, hash_array_of_points, generate_tuple

class User:
    def __init__(self):
        self.p, self.q, self.e = generate_random_rsa_key() # private private public
        self.n = self.p * self.q # public
        self.phi = (self.p - 1) * (self.q - 1) # private
        self.d = pow(self.e, -1, self.phi) # private
    
    def sign(self, message: int):
        return pow(message, self.d, self.n)
    
    def vote(self, candidate: int, server_public_key: dict) \
            -> ((ECCPoint, ECCPoint), 
                (ECCPoint, ECCPoint), 
                (int, int), 
                (list[ECCPoint], list[ECCPoint], list[int], list[int])):
        order = server_public_key["order"]
        elliptic_curve = server_public_key["elliptic_curve"]
        assert type(elliptic_curve) == EllipticCurve
        P = server_public_key["P"]
        Q = server_public_key["Q"]
        r = get_random_relatively_prime_value(order)
        M = server_public_key["M"]
        
        if (candidate < 0 or candidate >= len(M)):
            raise Exception("Invalid candidate id: %d" % candidate)
        
        candidate_key = M[candidate]
        encrypted_message = (elliptic_curve.multiply(r, P),
                             elliptic_curve.add(candidate_key, elliptic_curve.multiply(r, Q)))
        signed_message = (ECCPoint(self.sign(encrypted_message[0].x), self.sign(encrypted_message[0].y)),
                          ECCPoint(self.sign(encrypted_message[1].x), self.sign(encrypted_message[1].y)))
        return (encrypted_message, 
                signed_message, 
                self.get_public_key(), 
                self.prove_of_work(candidate, r, encrypted_message, server_public_key))
    
    def prove_of_work(self, candidate: int, 
                      rp: int, 
                      encrypted_message: (ECCPoint, ECCPoint), 
                      server_public_key: dict) \
            -> (list[ECCPoint], list[ECCPoint], list[int], list[int]):
        Ap, Bp = encrypted_message
        order = server_public_key["order"]
        elliptic_curve = server_public_key["elliptic_curve"]
        assert type(elliptic_curve) == EllipticCurve
        P = server_public_key["P"]
        Q = server_public_key["Q"]
        M = server_public_key["M"]
        w = [get_random_relatively_prime_value(order) for i in range(len(M))]
        u = [get_random_relatively_prime_value(order) for i in range(len(M))]
        s = get_random_relatively_prime_value(order)
        A = [elliptic_curve.add(
            elliptic_curve.multiply(w[k], P),
            elliptic_curve.multiply(u[k], Ap)
        ) if k != candidate else elliptic_curve.multiply(s, P) for k in range(len(M))]
        B = [elliptic_curve.add(
            elliptic_curve.multiply(w[k], Q),
            elliptic_curve.multiply(u[k], elliptic_curve.sub(Bp, M[k]))
        ) if k != candidate else elliptic_curve.multiply(s, Q) for k in range(len(M))]
        
        chall = hash_array_of_points(A + B, elliptic_curve.p)
        u[candidate] += chall - sum(u)
        w[candidate] = s - u[candidate] * rp
        return (A, B, u, w)
    
    def get_public_key(self) -> (int, int):
        return (self.n, self.e)

class VotingServer:
    def __init__(self, number_of_candidate: int, maximum_number_of_voter: int):
        self.number_of_candidate = number_of_candidate
        self.number_of_voter = 0
        self.maximum_number_of_voters = maximum_number_of_voter
        self.set_up()
        self.votes = []
        self.election_data = {
            "voter_public_key": [],
            "voter_vote": [],
            "voter_signed_message": [],
            "voter_prove_of_work": [],
            "encrypted_package": [],
            "decrypted_package": [],
            "result_package": []
        }

    def set_up(self):
        self.elliptic_curve = EllipticCurve(
            a = 1268133167195989090596625406312984755854486256116,
            b = 386736940269827655214118852806596527602892573734,
            p = 1461501637330902918203684832716283019655932542983) # public
        self.order = 1461501637330902918203684149283858612734394057783 # public

        self.d = get_random_relatively_prime_value(self.order) # private
        self.P = self.elliptic_curve.gens() # public
        self.Q = self.elliptic_curve.multiply(self.d, self.P) # public
        self.M = [self.elliptic_curve.multiply(
                pow(self.maximum_number_of_voters + 1, i, self.order), self.P
            ) for i in range(self.number_of_candidate)] # public

    def get_public_key(self) -> dict:
        return {
                    "P": self.P, 
                    "Q": self.Q,
                    "order": self.order,
                    "elliptic_curve": self.elliptic_curve,
                    "M": self.M
                }
    
    def cast_vote(self, vote: 
                  ((ECCPoint, ECCPoint), 
                   (ECCPoint, ECCPoint), 
                   (int, int),
                   (list[ECCPoint], list[ECCPoint], list[int], list[int]))):
        encrypted_message = vote[0]
        signed_message = vote[1]
        public_key = vote[2]
        prove_of_work = vote[3]
        for i in range(2):
            assert type(encrypted_message[i]) == ECCPoint
            assert type(signed_message[i]) == ECCPoint
            self.verify_message(encrypted_message[i].x, signed_message[i].x, public_key)
            self.verify_message(encrypted_message[i].y, signed_message[i].y, public_key)
        
        if self.verify_vote(encrypted_message, prove_of_work):
            self.number_of_voter += 1
            self.votes.append(encrypted_message)
            self.election_data["voter_vote"].append(encrypted_message)
            self.election_data["voter_signed_message"].append(signed_message)
            self.election_data["voter_public_key"].append(public_key)
            self.election_data["voter_prove_of_work"].append(prove_of_work)
    
    def verify_message(self, message: int, signed_message: int, public_key: (int, int)) -> bool:
        n, e = public_key
        return pow(signed_message, e, n) == message
    
    def verify_vote(self, encrypted_message: (ECCPoint, ECCPoint), 
                    prove_of_work: (list[ECCPoint], list[ECCPoint], list[int], list[int])) -> bool:
        A, B, u, w = prove_of_work
        elliptic_curve = self.elliptic_curve
        P = self.P
        Q = self.Q
        Ap, Bp = encrypted_message
        if (len(A) != self.number_of_candidate or len(B) != self.number_of_candidate 
            or len(u) != self.number_of_candidate or len(w) != self.number_of_candidate):
            return False
        
        for i in range(self.number_of_candidate):
            if (A[i] != (elliptic_curve.add(
                elliptic_curve.multiply(w[i], P),
                elliptic_curve.multiply(u[i], Ap)
            ))):
                return False
            if (B[i] != (elliptic_curve.add(
                elliptic_curve.multiply(w[i], Q),
                elliptic_curve.multiply(u[i], elliptic_curve.sub(Bp, self.M[i]))
            ))):
                return False
        
        chall = hash_array_of_points(A + B, elliptic_curve.p)
        return chall == sum(u)
    
    def open_vote(self) -> list[int]:
        elliptic_curve = self.elliptic_curve
        sum_A = ECCPoint(0, 0, True)
        sum_B = ECCPoint(0, 0, True)
        for vote in self.votes:
            sum_A = elliptic_curve.add(sum_A, vote[0])
            sum_B = elliptic_curve.add(sum_B, vote[1])
        
        self.election_data["encrypted_package"].append((sum_A, sum_B))
        decrypted_S = elliptic_curve.sub(
            sum_B,
            elliptic_curve.multiply(self.d, sum_A)
        )
        self.election_data["decrypted_package"].append(decrypted_S)

        self.results = self.solve(decrypted_S, self.M, self.number_of_voter)
        self.election_data["result_package"].append(self.results)
        self.election_data["results"] = self.results
        return self.results
    
    def solve(self, decrypted_S: ECCPoint, M: list[ECCPoint], n: int) -> list[int]:
        elliptic_curve = self.elliptic_curve
        mid = len(M) // 2
        left_size, right_size = generate_tuple(n, mid), generate_tuple(n, len(M) - mid)
        data = [dict() for i in range(n + 1)]
        for tuple in left_size:
            cur_sum = 0
            pt = ECCPoint(0, 0, True)
            for i in range(len(tuple)):
                cur_sum += tuple[i]
                pt = elliptic_curve.add(pt, elliptic_curve.multiply(tuple[i], M[i]))
            data[cur_sum][pt] = tuple
        
        for tuple in right_size:
            cur_sum = 0
            pt = ECCPoint(0, 0, True)
            for i in range(len(tuple)):
                cur_sum += tuple[i]
                pt = elliptic_curve.add(pt, elliptic_curve.multiply(tuple[i], M[i + mid]))
            
            target = elliptic_curve.sub(decrypted_S, pt)
            if target in data[n - cur_sum]:
                return data[n - cur_sum][target] + tuple
        
        return None
    
    def public_result(self):
        return self.election_data
        
if __name__ == '__main__':
    from random import randint
    from pprint import pprint
    import time
    number_of_candidate = 4
    voting_server = VotingServer(number_of_candidate = 4, maximum_number_of_voter = 300)
    cnt = [0 for i in range(number_of_candidate)]
    now = time.time()
    for i in range(200):
        user = User()
        vote = randint(0, number_of_candidate - 1)
        cnt[vote] += 1
        user_vote = user.vote(vote, voting_server.get_public_key())
        voting_server.cast_vote(user_vote)
    
    print(f"Preprocess time: {time.time() - now}")
    now = time.time()
    print(cnt)
    print(voting_server.open_vote() == cnt)
    print(f"Opening vote time: {time.time() - now}")
    pprint(voting_server.public_result())