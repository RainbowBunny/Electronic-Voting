from Crypto.Util.number import inverse, getRandomRange

def square_root(a, p):
    #Tonelli–Shanks algorithm
    if legendre_symbol(a, p) != 1:
        return 0
    elif a == 0:
        return 0
    elif p == 2:
        return 0
    elif p % 4 == 3:
        return pow(a, (p + 1) // 4, p)

    s = p - 1
    e = 0
    while s % 2 == 0:
        s //= 2
        e += 1

    n = 2
    while legendre_symbol(n, p) != -1:
        n += 1

    x = pow(a, (s + 1) // 2, p)
    b = pow(a, s, p)
    g = pow(n, s, p)
    r = e

    while True:
        t = b
        m = 0
        for m in range(r):
            if t == 1:
                break
            t = pow(t, 2, p)

        if m == 0:
            return x

        gs = pow(g, 2 ** (r - m - 1), p)
        g = (gs * gs) % p
        x = (x * gs) % p
        b = (b * g) % p
        r = m

def legendre_symbol(a, p):
    ls = pow(a, (p - 1) // 2, p)
    return -1 if ls == p - 1 else ls

class ECCPoint:
    def __init__(self, x, y, origin: bool = False):
        self.x = x
        self.y = y
        self.origin = origin

    def is_origin(self) -> bool:
        return self.origin

    def __eq__(self, __value: object) -> bool:
        if isinstance(__value, ECCPoint):
            if self.is_origin():
                return __value.is_origin()
            return self.x == __value.x and self.y == __value.y
        
        return False
    
    def __hash__(self) -> int:
        return hash(self.x) ^ hash(self.y)
    
    def __repr__(self) -> str:
        return f"ECC Point ({self.x}, {self.y})"

class EllipticCurve:
    """
        Initializes a new EllipticCurve in the formed:
        y^2 = x^3 + ax + b mod p
    """
    def __init__(self, a: int, b: int, p: int):
        self.a = a
        self.b = b
        self.p = p

        if (4 * a ** 3 + 27 * b ** 2) % p == 0:
            raise Exception("Condition 4 * a ** 3 + 27 * b ** 2 != 0 is not satisfied!")
        
        self.a = (self.a % p + p) % p
        self.b = (self.b % p + p) % p

    def is_on_curve(self, point: ECCPoint) -> bool:
        if point.is_origin():
            return True
        x, y = point.x, point.y
        return (y ** 2 - x ** 3 - self.a * x - self.b) % self.p == 0
    
    def negation_point(self, point: ECCPoint) -> ECCPoint:
        if point.is_origin():
            return ECCPoint(0, 0, True)
        return ECCPoint(point.x, (self.p - point.y) % self.p)

    def add(self, point_1: ECCPoint, point_2: ECCPoint) -> ECCPoint:
        if not self.is_on_curve(point_1) or not self.is_on_curve(point_2):
            raise Exception("Adding point failed due to a point does not on the curve!")
        
        if point_1.is_origin():
            return point_2
        if point_2.is_origin():
            return point_1
        
        if self.negation_point(point_1) == point_2:
            return ECCPoint(0, 0, True)
        
        if point_1 != point_2:
            L = (point_2.y - point_1.y + self.p) * inverse(point_2.x - point_1.x + self.p, self.p) % self.p
        else:
            L = (3 * point_1.x ** 2 + self.a) * inverse(2 * point_1.y, self.p)
        
        return ECCPoint((L ** 2 - point_1.x - point_2.x + self.p) % self.p,
                        (L * (point_1.x - (L ** 2 - point_1.x - point_2.x)) - point_1.y) % self.p)
    
    def sub(self, point_1: ECCPoint, point_2: ECCPoint) -> ECCPoint:
        return self.add(point_1, self.negation_point(point_2))
        
    def multiply(self, value: int, point: ECCPoint) -> ECCPoint:
        if not self.is_on_curve(point):
            raise Exception("Multiply point failed due to a point does not on the curve!")
        if (value < 0):
            value = -value
            point = self.negation_point(point)
        
        ans, level = ECCPoint(0, 0, True), point
        while (value > 0):
            if (value % 2 == 1):
                ans = self.add(ans, level)
            level = self.add(level, level)
            value //= 2
        return ans
    
    def gens(self) -> ECCPoint:
        x = getRandomRange(1, self.p)
        while True:
            x = getRandomRange(1, self.p)
            y_square = (x ** 3 + self.a * x + self.b) % self.p
            if legendre_symbol(y_square, self.p) == 1:
                return ECCPoint(x, square_root(y_square, self.p))
    
    def __repr__(self) -> str:
        return f"Elliptic Curve in field {self.p}, equation: y^2 = x^3 + {self.a}x + {self.b}"

if __name__ == "__main__":
    ec = EllipticCurve(497, 1768, 9739)
    print(ec)
    print(ec.add(ECCPoint(5274, 2841), ECCPoint(5274, 2841))) # (7284, 2107)
    print(ec.add(ECCPoint(5274, 2841), ECCPoint(8669, 740))) # (1024, 4440)
    print(ec.multiply(1337, ECCPoint(5323, 5438))) # (1089, 6931)