import java.math.BigInteger;
import java.security.SecureRandom;

public class RSAUtils {
    private static final SecureRandom rand = new SecureRandom();
    private static final BigInteger TWO = BigInteger.valueOf(2);

    public static BigInteger modExp(BigInteger base, BigInteger exp, BigInteger mod) {
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
            candidate = candidate.setBit(bits - 1); // ensure size
            candidate = candidate.setBit(0);        // make odd

            if (isProbablePrime(candidate, 20)) {
                return candidate;
            }
        }
    }

    public static BigInteger gcd(BigInteger a, BigInteger b) {
        while (!b.equals(BigInteger.ZERO)) {
            BigInteger temp = b;
            b = a.mod(b);
            a = temp;
        }
        return a;
    }
}