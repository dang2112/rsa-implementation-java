public static void main(String[] args) {
    //testing
    BigInteger p = RSAUtils.generatePrime(1024);
    BigInteger q; //ensure p is not equal to q
    do {
        q = RSAUtils.generatePrime(1024);
    } while (q.equals(p));
    RSAUtils.KeyPair keys = RSAUtils.generateKeys(p, q);

    BigInteger message = new BigInteger("123456");

    BigInteger cypher = RSAUtils.encrypt(message, keys.e, keys.n);
    BigInteger decrypted = RSAUtils.decrypt(cypher, keys.d, keys.n);

    System.out.println("Original: " + message);
    System.out.println("Cyphertext: " + cypher);
    System.out.println("Decrypted: " + decrypted);
    System.out.println("Prime p: " + keys.p);
    System.out.println("Prime q: " + keys.q);
    System.out.println("Encryption key: " + keys.e);
    System.out.println("Decryption key: " + keys.d);
    System.out.println("Modulus value n = p*q: " + keys.n);
}
