import java.math.BigInteger;

public class AKSUtils {
    /**
     * Function check Prime
     */
    public static boolean isPrime(BigInteger n) {
        if (n.compareTo(BigInteger.ONE) <= 0) {
            return false;
        }
        if (n.equals(BigInteger.valueOf(2))) {
            return true;
        }

        // Step 1: Check perfect power
        if (isPerfectPower(n)) {
            return false;
        }

        // Step 2: Find r smallest such that ord_r(n) > log2(n)^2
        int log2n = n.bitLength();
        BigInteger log2nSq = BigInteger.valueOf((long) log2n * log2n);
        int r = 2;
        while (true) {
            if (n.mod(BigInteger.valueOf(r)).equals(BigInteger.ZERO)) {
                if (n.equals(BigInteger.valueOf(r))) {
                    return true;
                }
                return false;
            }
            BigInteger rBig = BigInteger.valueOf(r);
            BigInteger currentMod = n.mod(rBig);
            BigInteger acc = currentMod;
            boolean found = false;
            for (int i = 1; i <= log2nSq.intValue(); i++) {
                if (acc.equals(BigInteger.ONE)) {
                    found = true;
                    break;
                }
                acc = acc.multiply(currentMod).mod(rBig);
            }
            if (!found) {
                break;
            }
            r++;
        }

        // Step 3: Check GCD
        for (int a = 2; a <= r; a++) {
            BigInteger gcd = RSAUtils.gcd(BigInteger.valueOf(a), n); //self implemented gcd
            if (gcd.compareTo(BigInteger.ONE) > 0 && gcd.compareTo(n) < 0) {
                return false;
            }
        }

        // Step 4: Check small limit
        if (n.compareTo(BigInteger.valueOf(r)) <= 0) {
            return true;
        }

        // Step 5: Check polynomial identity
        int limit = (int) (Math.sqrt(totient(r)) * log2n);
        for (int a = 1; a <= limit; a++) {
            if (!testPolynomial(a, n, r)) {
                return false;
            }
        }

        // Step 6: Conclusion
        return true;
    }

    /**
     * HELPER FUNCTION
     */

    // Check whether n is a perfect power, i.e., whether n=a^b
    private static boolean isPerfectPower(BigInteger n) {
        int maxB = n.bitLength();
        for (int b = 2; b <= maxB; b++) {
            BigInteger a = kthRoot(n, b);
            if (RSAUtils.power(a, b).equals(n)) { //self implemented power
                return true;
            }
        }
        return false;
    }

    // Find the integer k-th root of n base-on Newton-Raphson method
    private static BigInteger kthRoot(BigInteger n, int k) {
        if (k == 1) {
            return n;
        }
        BigInteger kBig = BigInteger.valueOf(k);
        BigInteger kMinusOne = BigInteger.valueOf(k - 1);
        BigInteger s = n.add(BigInteger.ONE);
        BigInteger u = n;
        while (u.compareTo(s) < 0) {
            s = u;
            u = u.multiply(kMinusOne).add(n.divide(RSAUtils.power(u, k - 1))).divide(kBig); //self implemented power
        }
        return s;
    }

    // Euler's totient function
    private static int totient(int n) {
        int result = n;
        for (int p = 2; p * p <= n; p++) {
            if (n % p == 0) {
                while (n % p == 0) {
                    n /= p;
                }
                result -= result / p;
            }
        }
        if (n > 1) {
            result -= result / n;
        }
        return result;
    }

    /**
     * Check polynomial identity: (X + a)^n == X^n + a (mod X^r - 1, n)
     */
    private static boolean testPolynomial(int a, BigInteger n, int r) {
        BigInteger[] base = new BigInteger[r];
        for (int i = 0; i < r; i++) {
            base[i] = BigInteger.ZERO;
        }
        base[0] = BigInteger.valueOf(a).mod(n);
        if (r > 1) {
            base[1] = BigInteger.ONE;
        }
        BigInteger[] result = new BigInteger[r];
        for (int i = 0; i < r; i++) {
            result[i] = BigInteger.ZERO;
        }
        result[0] = BigInteger.ONE;
        BigInteger exp = n;
        while (exp.compareTo(BigInteger.ZERO) > 0) {
            if (exp.testBit(0)) {
                result = polyMul(result, base, r, n);
            }
            base = polyMul(base, base, r, n);
            exp = exp.shiftRight(1);
        }
        int nModR = n.mod(BigInteger.valueOf(r)).intValue();
        for (int i = 0; i < r; i++) {
            BigInteger expected = BigInteger.ZERO;
            if (i == 0) {
                expected = BigInteger.valueOf(a).mod(n);
            } else if (i == nModR) {
                expected = expected.add(BigInteger.ONE).mod(n);
            }
            if (!result[i].equals(expected)) {
                return false;
            }
        }
        return true;
    }

    // Multiply two polynomials modulo (X^r - 1, n)
    private static BigInteger[] polyMul(BigInteger[] p1, BigInteger[] p2, int r, BigInteger n) {
        BigInteger[] res = new BigInteger[r];
        for (int i = 0; i < r; i++) {
            res[i] = BigInteger.ZERO;
        }
        for (int i = 0; i < r; i++) {
            if (p1[i].equals(BigInteger.ZERO)) {
                continue;
            }
            for (int j = 0; j < r; j++) {
                if (p2[j].equals(BigInteger.ZERO)) {
                    continue;
                }
                int k = (i + j) % r;
                res[k] = res[k].add(p1[i].multiply(p2[j])).mod(n);
            }
        }
        return res;
    }

    /**
     * BENCHMARK
     */
    public static void main(String[] args) {
        System.out.println("=====================================================================");
        System.out.println("      SIMULATION AND EVALUATION OF AKS ALGORITHM");
        System.out.println("=====================================================================");

        runCorrect();
        runEvaluation();
    }

    private static void runCorrect() {
        System.out.println("\n=== TEST CASE CORRECTNESS ===");
        long[] testNumber = {
                17, // Small Prime
                21, // Small Composite
                343, // Composite but perfect power (7^3)
                8191 // Mersene Prime
        };
        for (long num : testNumber) {
            System.out.println("\n[+] RUNNING CORRECTNESS TEST FOR n = " + num);
            BigInteger n = BigInteger.valueOf(num);

            // AKS
            long startAKS = System.nanoTime();
            boolean resAKS = isPrime(n);
            long endAKS = System.nanoTime();

            // Miller-Rabin
            long startMR = System.nanoTime();
            boolean resMR = RSAUtils.isProbablePrime(n, 40);
            long endMR = System.nanoTime();

            // Result
            System.out.println(String.format("- Assessment from AKS         : %-9s, TIME: %.4f ms",
                    (resAKS ? "PRIME" : "COMPOSITE"), (endAKS - startAKS) / 1000000.0));
            System.out.println(String.format("- Assessment from Miller Rabin: %-9s, TIME: %.4f ms",
                    (resMR ? "PRIME" : "COMPOSITE"), (endMR - startMR) / 1000000.0));
            System.out.println("- Result Match                : " + (resAKS == resMR ? "PASS" : "FAIL"));
        }
    }

    private static void runEvaluation() {
        System.out.println("\n=== TEST CASE EVALUATION ===");

        int[] aksBits = { 16}; //i cant run anything more than this
        int[] mrBits = { 16, 24, 32, 40, 56, 64, 128, 256, 512 };

        System.out.println("\n=== EVALUATING MILLER-RABIN ALGORITHM ===");
        for (int bits : mrBits) {
            BigInteger testN = RSAUtils.generatePrime(bits);
            long startMR = System.nanoTime();
            boolean resMR = RSAUtils.isProbablePrime(testN, 40);
            long endMR = System.nanoTime();
            System.out.println(String.format("- Miller-Rabin (bits=%d): %-9s, TIME: %.4f ms",
                    bits, (resMR ? "PRIME" : "COMPOSITE"), (endMR - startMR) / 1000000.0));
        }

        System.out.println("\n=== EVALUATING AKS ALGORITHM ===");
        for (int bits : aksBits) {
            BigInteger testN = RSAUtils.generatePrime(bits);
            long startAKS = System.nanoTime();
            boolean resAKS = isPrime(testN);
            long endAKS = System.nanoTime();
            System.out.println(String.format("- AKS (bits=%d): %-9s, TIME: %.4f ms",
                    bits, (resAKS ? "PRIME" : "COMPOSITE"), (endAKS - startAKS) / 1000000.0));
        }
    }
}