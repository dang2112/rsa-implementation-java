import java.awt.*;
import java.math.BigInteger;
import java.util.HexFormat;
import javax.swing.*;

public class RSAGui extends JFrame {
    private RSAUtils.KeyPair keys;
    private JTextField bitLengthField;
    private JTextField messageField;
    private JTextField iterationsField;
    private JTextArea outputArea;
    private JCheckBox paddingCheckBox;

    public RSAGui() {
        setTitle("RSA Implementation");
        setSize(800, 600);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        JPanel mainPanel = new JPanel(new BorderLayout());

        JPanel controlPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        gbc.gridx = 0; gbc.gridy = 0;
        controlPanel.add(new JLabel("Bit Length:"), gbc);
        gbc.gridx = 1;
        bitLengthField = new JTextField("100", 10);
        controlPanel.add(bitLengthField, gbc);

        gbc.gridx = 2;
        JButton genKeysBtn = new JButton("Generate Keys");
        genKeysBtn.addActionListener(e -> generateKeys());
        controlPanel.add(genKeysBtn, gbc);

        gbc.gridx = 0; gbc.gridy = 1;
        controlPanel.add(new JLabel("Message/Cipher:"), gbc);
        gbc.gridx = 1;
        messageField = new JTextField("123456789987654321", 20);
        controlPanel.add(messageField, gbc);

        gbc.gridx = 2;
        JButton encryptBtn = new JButton("Encrypt");
        encryptBtn.addActionListener(e -> encryptMessage());
        controlPanel.add(encryptBtn, gbc);
        gbc.gridx = 3;
        JButton decryptBtn = new JButton("Decrypt");
        decryptBtn.addActionListener(e -> decryptMessage());
        controlPanel.add(decryptBtn, gbc);

        gbc.gridx = 0; gbc.gridy = 2;
        controlPanel.add(new JLabel("Iterations:"), gbc);
        gbc.gridx = 1;
        iterationsField = new JTextField("100", 10);
        controlPanel.add(iterationsField, gbc);

        gbc.gridx = 2;
        JButton benchmarkBtn = new JButton("Run Benchmark");
        benchmarkBtn.addActionListener(e -> runBenchmark());
        controlPanel.add(benchmarkBtn, gbc);

        gbc.gridx = 3;
        paddingCheckBox = new JCheckBox("Use PKCS#1 v1.5 Padding");
        paddingCheckBox.setSelected(false);
        controlPanel.add(paddingCheckBox, gbc);

        mainPanel.add(controlPanel, BorderLayout.NORTH);

        outputArea = new JTextArea();
        outputArea.setEditable(false);
        mainPanel.add(new JScrollPane(outputArea), BorderLayout.CENTER);

        setContentPane(mainPanel);
    }

    private void generateKeys() {
        try {
            int bits = Integer.parseInt(bitLengthField.getText());
            outputArea.append("Generating keys...\n");
            long start = System.nanoTime();
            keys = RSAAdvancedUtils.generateStrongKeys(bits);
            long end = System.nanoTime();
            outputArea.append(String.format("Keys generated in %d ms%n", (end-start)/1_000_000));
            outputArea.append(String.format("Public (e,n): %s, %s%n", keys.e, keys.n));
            outputArea.append(String.format("Modulus (n) length: %s bits%n", keys.n.bitLength()));
        } catch (NumberFormatException ex) {
            outputArea.append("Invalid bit length\n");
        }
    }

    private void encryptMessage() {
        if (keys == null) { outputArea.append("Generate keys first\n"); return; }
        try {
            BigInteger msg = new BigInteger(messageField.getText());
            BigInteger cipher;
            if (paddingCheckBox.isSelected()) {
                cipher = RSAUtils.encryptWithPadding(msg, keys.e, keys.n);
                outputArea.append("Padded input bytes: " + HexFormat.of().formatHex(RSAUtils.paddingProc(msg, keys.e, keys.n)) + "\n");
                outputArea.append("Encrypted (with padding): " + cipher + "\n");
            } else {
                cipher = RSAUtils.encrypt(msg, keys.e, keys.n);
                outputArea.append("Encrypted (no padding): " + cipher + "\n");
            }
            messageField.setText(cipher.toString());
        } catch (NumberFormatException ex) {
            outputArea.append("Invalid message\n");
        } catch (IllegalArgumentException ex) {
            outputArea.append("Error: " + ex.getMessage() + "\n");
        }
    }

    private void decryptMessage() {
        if (keys == null) { outputArea.append("Generate keys first\n"); return; }
        try {
            BigInteger cipher = new BigInteger(messageField.getText());
            BigInteger decCRT;
            if (paddingCheckBox.isSelected()) {
                BigInteger dec = RSAUtils.decryptWithPadding(cipher, keys.d, keys.n);
                decCRT = RSAUtils.decryptWithPaddingCRT(cipher, keys.p, keys.q, keys.d);
                outputArea.append("Standard Decrypt (padded): " + dec + "\n");
                outputArea.append("CRT Decrypt (padded): " + decCRT + "\n");
            } else {
                BigInteger dec = RSAUtils.decrypt(cipher, keys.d, keys.n);
                decCRT = RSAAdvancedUtils.decryptCRT(cipher, keys.p, keys.q, keys.d);
                outputArea.append("Standard Decrypt: " + dec + "\n");
                outputArea.append("CRT Decrypt: " + decCRT + "\n");
            }
            messageField.setText(decCRT.toString());
        } catch (NumberFormatException ex) {
            outputArea.append("Invalid cipher\n");
        } catch (IllegalArgumentException ex) {
            outputArea.append("Error: " + ex.getMessage() + "\n");
        }
    }

    private void runBenchmark() {
        if (keys == null) { outputArea.append("Generate keys first\n"); return; }
        try {
            int iters = Integer.parseInt(iterationsField.getText());
            BigInteger message = new BigInteger(messageField.getText());

            outputArea.append(String.format("\n=== BENCHMARKING (Padding: %s, %d iterations) ===%n",
                paddingCheckBox.isSelected() ? "ON" : "OFF", iters));

            // Encrypt first
            BigInteger cipher;
            if (paddingCheckBox.isSelected()) {
                cipher = RSAUtils.encryptWithPadding(message, keys.e, keys.n);
            } else {
                cipher = RSAUtils.encrypt(message, keys.e, keys.n);
            }

            // Benchmark Standard Decryption
            long standardTotalTime = 0;
            BigInteger decryptedStandard = null;
            for (int i = 0; i < iters; i++) {
                long start = System.nanoTime();
                if (paddingCheckBox.isSelected()) {
                    decryptedStandard = RSAUtils.decryptWithPadding(cipher, keys.d, keys.n);
                } else {
                    decryptedStandard = RSAUtils.decrypt(cipher, keys.d, keys.n);
                }
                standardTotalTime += (System.nanoTime() - start);
            }
            double standardAvgTime = (standardTotalTime / (double) iters) / 1_000_000.0;

            // Benchmark CRT Decryption
            long crtTotalTime = 0;
            BigInteger decryptedCRT = null;
            for (int i = 0; i < iters; i++) {
                long start = System.nanoTime();
                if (paddingCheckBox.isSelected()) {
                    decryptedCRT = RSAUtils.decryptWithPaddingCRT(cipher, keys.p, keys.q, keys.d);
                } else {
                    decryptedCRT = RSAAdvancedUtils.decryptCRT(cipher, keys.p, keys.q, keys.d);
                }
                crtTotalTime += (System.nanoTime() - start);
            }
            double crtAvgTime = (crtTotalTime / (double) iters) / 1_000_000.0;

            outputArea.append("Original Message : " + message + "\n");
            outputArea.append("Standard Decrypt : " + decryptedStandard + "\n");
            outputArea.append("CRT Decrypt      : " + decryptedCRT + "\n");
            outputArea.append(String.format("\n--- Performance Results (Average over %d runs) ---%n", iters));
            outputArea.append(String.format("Standard Decryption Time : %.2f ms%n", standardAvgTime));
            outputArea.append(String.format("CRT Decryption Time      : %.2f ms%n", crtAvgTime));
            outputArea.append(String.format("Speedup Ratio            : %.2fx faster%n", (standardAvgTime / crtAvgTime)));
        } catch (NumberFormatException ex) {
            outputArea.append("Invalid iterations or message\n");
        } catch (IllegalArgumentException ex) {
            outputArea.append("Error: " + ex.getMessage() + "\n");
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new RSAGui().setVisible(true));
    }
}
