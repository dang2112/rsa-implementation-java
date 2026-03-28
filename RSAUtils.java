import java.math.BigInteger;
import java.security.SecureRandom;

public class RSAUtils {
    private static final SecureRandom rand = new SecureRandom();
    private static final BigInteger TWO = BigInteger.valueOf(2);

    public static class KeyPair {
        public BigInteger e, d, p, q, n;

        public KeyPair(BigInteger e, BigInteger d, BigInteger p, BigInteger q) {
            this.e = e;
            this.d = d;
            this.p = p;
            this.q = q;
            this.n = p.multiply(q);
        }
    }

    public static BigInteger modExp(BigInteger base, BigInteger exp, BigInteger mod) {
        //fast modular exponentiation
        BigInteger result = BigInteger.ONE;
        base = base.mod(mod);

        while (exp.compareTo(BigInteger.ZERO) > 0) {
            if (exp.mod(BigInteger.TWO).equals(BigInteger.ONE)) {
                result = result.multiply(base).mod(mod);
            }

            exp = exp.divide(BigInteger.TWO);
            base = base.multiply(base).mod(mod);
        }

        return result;
    }

    public static BigInteger randomBetween(BigInteger min, BigInteger max) {
        BigInteger range = max.subtract(min);
        BigInteger result;

        do {
            result = new BigInteger(range.bitLength(), rand);
        } while (result.compareTo(range) > 0);

        return result.add(min);
    }

    public static boolean isProbablePrime(BigInteger n, int k) {
        //miller rabin
        if (n.compareTo(TWO) < 0) return false; //less than 2 is not prime
        if (n.equals(TWO)) return true; //2 is a prime
        if (n.mod(TWO).equals(BigInteger.ZERO)) return false; //divisible by 2 is not prime

        BigInteger d = n.subtract(BigInteger.ONE);
        int s = 0;

        while (d.mod(TWO).equals(BigInteger.ZERO)) {
            d = d.divide(TWO);
            s++;
        }

        for (int i = 0; i < k; i++) {
            BigInteger a = randomBetween(TWO, n.subtract(TWO));
            BigInteger x = modExp(a, d, n);

            if (x.equals(BigInteger.ONE) || x.equals(n.subtract(BigInteger.ONE)))
                continue;

            boolean continueOuter = false;
            for (int r = 0; r < s - 1; r++) {
                x = modExp(x, TWO, n);

                if (x.equals(n.subtract(BigInteger.ONE))) {
                    continueOuter = true;
                    break;
                }
            }

            if (continueOuter) continue;

            return false;
        }
        return true;
    }

    public static BigInteger generatePrime(int bits) {
        while (true) {
            BigInteger candidate = new BigInteger(bits, rand);
            candidate = candidate.setBit(bits - 1); //ensure size
            candidate = candidate.setBit(0);        //make odd

            if (isProbablePrime(candidate, 20)) {
                return candidate;
            }
        }
    }

    public static BigInteger gcd(BigInteger a, BigInteger b) {
        //euclidean algorithm: GCD(a,b) = HCD(b,a mod b)
        while (!b.equals(BigInteger.ZERO)) {
            BigInteger temp = b;
            b = a.mod(b);
            a = temp;
        }
        return a;
    }

    public static BigInteger[] extendedGCD(BigInteger a, BigInteger b) {
        //extended euclidean algorithm
        if (b.equals(BigInteger.ZERO)) {
            return new BigInteger[]{a, BigInteger.ONE, BigInteger.ZERO};
        }

        BigInteger[] vals = extendedGCD(b, a.mod(b));

        BigInteger d = vals[0];
        BigInteger x = vals[2];
        BigInteger y = vals[1].subtract(a.divide(b).multiply(vals[2]));

        return new BigInteger[]{d, x, y};
    }

    public static BigInteger modInverse(BigInteger e, BigInteger p, BigInteger q) {
        //decryption Key d is computed as e^-1 mod phi(n) (with encryption key e)
        //phi(n) is computed as (p-1)(q-1) => p and q are large prime numbers
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        BigInteger[] result = extendedGCD(e, phi);
        BigInteger x = result[1];

        if (x.compareTo(BigInteger.ZERO) < 0) {
            x = x.add(phi);
        }
        return x;
    }

    public static BigInteger modInverseWithPhi(BigInteger e, BigInteger phi) {
        //version with phi already calculated, used in generateKeys
        BigInteger[] result = extendedGCD(e, phi);
        BigInteger x = result[1];

        if (x.compareTo(BigInteger.ZERO) < 0) {
            x = x.add(phi);
        }
        return x;
    }

    public static KeyPair generateKeys(BigInteger p, BigInteger q) {
        //creates a random set of keys given 2 large prime numbers p and q, which
        //would be generated using generatePrime(); remember that p and q must not be equal
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        //System.out.println("PHI VALUE   " + phi);

        BigInteger e;
        do {
            e = new BigInteger(p.bitCount()/2, rand);
        } while (!gcd(e, phi).equals(BigInteger.ONE));

        BigInteger d = modInverseWithPhi(e, phi);

        return new KeyPair(e, d, p, q);
    }

    public static BigInteger encrypt(BigInteger message, BigInteger e, BigInteger n) {
        //remember: message must be less than n
        //RSA encryption: c = m^e mod n
        return modExp(message, e, n);
    }

    public static BigInteger decrypt(BigInteger cypher, BigInteger d, BigInteger n) {
        //RSA decryption: m = c^d mod n
        return modExp(cypher, d, n);
    }
}