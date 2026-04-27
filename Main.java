import java.math.BigInteger;

public class Main {
    public static void main(String[] args) {
        int bitLength = 1024; // Có thể chỉnh lên 2048 để test cực hạn
        System.out.println("=== 1. GENERATING STRONG KEYS (" + bitLength + " bits) ===");
        
        long keyGenStart = System.nanoTime();
        // Sử dụng hàm sinh cặp khóa mạnh thay vì hàm cũ
        RSAUtils.KeyPair keys = RSAAdvancedUtils.generateStrongKeys(bitLength);
        long keyGenEnd = System.nanoTime();
        
        System.out.println("Key generation time: " + (keyGenEnd - keyGenStart) / 1_000_000 + " ms");
        System.out.println("Modulus (n) length: " + keys.n.bitLength() + " bits");

        // Message
        BigInteger message = new BigInteger("123456789987654321");
        BigInteger cypher = RSAUtils.encrypt(message, keys.e, keys.n);

        System.out.println("\n=== 2. BENCHMARKING DECRYPTION ===");
        int iterations = 100; // Số lần chạy để lấy trung bình

        // 2.1 Standard Decryption (Giải mã thuần)
        long standardTotalTime = 0;
        BigInteger decryptedStandard = null;
        for (int i = 0; i < iterations; i++) {
            long start = System.nanoTime();
            decryptedStandard = RSAUtils.decrypt(cypher, keys.d, keys.n);
            standardTotalTime += (System.nanoTime() - start);
        }
        double standardAvgTime = (standardTotalTime / (double) iterations) / 1_000_000.0;

        // 2.2 CRT Decryption (Giải mã CRT)
        long crtTotalTime = 0;
        BigInteger decryptedCRT = null;
        for (int i = 0; i < iterations; i++) {
            long start = System.nanoTime();
            decryptedCRT = RSAAdvancedUtils.decryptCRT(cypher, keys.p, keys.q, keys.d);
            crtTotalTime += (System.nanoTime() - start);
        }
        double crtAvgTime = (crtTotalTime / (double) iterations) / 1_000_000.0;

        // In kết quả
        System.out.println("Original Message : " + message);
        System.out.println("Standard Decrypt : " + decryptedStandard);
        System.out.println("CRT Decrypt      : " + decryptedCRT);
        
        System.out.println("\n--- Performance Results (Average over " + iterations + " runs) ---");
        System.out.printf("Standard Decryption Time : %.2f ms%n", standardAvgTime);
        System.out.printf("CRT Decryption Time      : %.2f ms%n", crtAvgTime);
        System.out.printf("Speedup Ratio            : %.2fx faster%n", (standardAvgTime / crtAvgTime));
    }
}