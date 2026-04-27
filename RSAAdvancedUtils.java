import java.math.BigInteger;
import java.security.SecureRandom;

public class RSAAdvancedUtils {
    private static final SecureRandom rand = new SecureRandom();
    
    // Mảng các số nguyên tố nhỏ dùng để sàng lọc cực nhanh (Trial Division)
    private static final BigInteger[] SMALL_PRIMES = {
        BigInteger.valueOf(3), BigInteger.valueOf(5), BigInteger.valueOf(7),
        BigInteger.valueOf(11), BigInteger.valueOf(13), BigInteger.valueOf(17),
        BigInteger.valueOf(19), BigInteger.valueOf(23), BigInteger.valueOf(29),
        BigInteger.valueOf(31), BigInteger.valueOf(37), BigInteger.valueOf(41)
    };

    /**
     * 1. Sinh số nguyên tố SIÊU TỐC (Thay thế hoàn toàn hàm của RSAUtils)
     * Dùng Trial Division để lọc bớt 70% các số rác trước khi đưa vào Miller-Rabin.
     */
    public static BigInteger generateFastPrime(int bits) {
        while (true) {
            BigInteger candidate = new BigInteger(bits, rand);
            candidate = candidate.setBit(bits - 1); // Đảm bảo số bit (MSB = 1)
            candidate = candidate.setBit(0);        // Đảm bảo số lẻ (LSB = 1)

            // Sàng lọc bằng các số nguyên tố nhỏ
            boolean isDivisible = false;
            for (BigInteger p : SMALL_PRIMES) {
                if (candidate.mod(p).equals(BigInteger.ZERO)) {
                    isDivisible = true;
                    break;
                }
            }
            if (isDivisible) continue; // Bỏ qua sinh số khác ngay

            // Gọi mượn hàm kiểm tra Miller-Rabin
            if (RSAUtils.isProbablePrime(candidate, 20)) {
                return candidate;
            }
        }
    }

    /**
     * 2. Sinh Safe Prime chống Pollard p-1
     */
    public static BigInteger generateSafePrime(int bits) {
        BigInteger q, p;
        do {
            q = generateFastPrime(bits - 1); // Gọi hàm SIÊU TỐC ở trên
            p = q.multiply(BigInteger.valueOf(2)).add(BigInteger.ONE);
        } while (!RSAUtils.isProbablePrime(p, 20));
        return p;
    }

    /**
     * 3. Tạo cặp khóa mạnh & Vá lỗi treo vòng lặp e (Bypass RSAUtils.generateKeys)
     */
    public static RSAUtils.KeyPair generateStrongKeys(int bits) {
        BigInteger p = generateSafePrime(bits);
        BigInteger q;
        BigInteger minDiff = BigInteger.valueOf(2).pow(bits - 10);

        // Đảm bảo khoảng cách p, q đủ lớn chống Fermat Factorization
        do {
            q = generateSafePrime(bits);
        } while (p.equals(q) || p.subtract(q).abs().compareTo(minDiff) < 0);

        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

        // TỐI ƯU e: Cố định bằng số nguyên tố Fermat thứ 4 (chuẩn thực tế)
        BigInteger e = BigInteger.valueOf(65537);

        // Đảm bảo an toàn: Nếu xui xẻo gcd != 1, mới phải sinh e ngẫu nhiên (dùng bitLength)
        if (!RSAUtils.gcd(e, phi).equals(BigInteger.ONE)) {
            do {
                e = new BigInteger(p.bitLength() / 2, rand);
            } while (!RSAUtils.gcd(e, phi).equals(BigInteger.ONE));
        }

        // Gọi mượn hàm tính nghịch đảo từ code gốc của bạn
        BigInteger d = RSAUtils.modInverseWithPhi(e, phi);

        // Khởi tạo trực tiếp đối tượng KeyPair của nhóm bạn
        return new RSAUtils.KeyPair(e, d, p, q);
    }

    /**
     * 4. Giải mã tối ưu bằng Định lý số dư Trung Hoa (CRT)
     */
    public static BigInteger decryptCRT(BigInteger cypher, BigInteger p, BigInteger q, BigInteger d) {
        BigInteger pMinus1 = p.subtract(BigInteger.ONE);
        BigInteger qMinus1 = q.subtract(BigInteger.ONE);
        
        BigInteger dp = d.mod(pMinus1);
        BigInteger dq = d.mod(qMinus1);
        
        // Tính q_inv = q^-1 mod p
        BigInteger[] extGCD = RSAUtils.extendedGCD(q, p);
        BigInteger qInv = extGCD[1];
        if (qInv.compareTo(BigInteger.ZERO) < 0) {
            qInv = qInv.add(p);
        }

        // Bước giải mã trên module nhỏ
        BigInteger m1 = RSAUtils.modExp(cypher, dp, p);
        BigInteger m2 = RSAUtils.modExp(cypher, dq, q);

        // Bước kết hợp Garner
        BigInteger h = qInv.multiply(m1.subtract(m2)).mod(p);
        if (h.compareTo(BigInteger.ZERO) < 0) {
            h = h.add(p);
        }

        return m2.add(h.multiply(q));
    }
}