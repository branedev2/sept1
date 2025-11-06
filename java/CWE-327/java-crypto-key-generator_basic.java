import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class KeyGeneratorExamples {

    // True Positives (Vulnerable Code)

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
    public void bad_case_1() {
        try {
            // ruleid: java-crypto-key-generator
            KeyGenerator keyGen = KeyGenerator.getInstance("DES");
            SecretKey secretKey = keyGen.generateKey();
            System.out.println("Generated DES key: " + secretKey.toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_2() {
        try {
            // ruleid: java-crypto-key-generator
            KeyGenerator keyGen = KeyGenerator.getInstance("RC2");
            keyGen.init(64);
            SecretKey secretKey = keyGen.generateKey();
            System.out.println("Generated RC2 key: " + secretKey.toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_3() {
        try {
            // ruleid: java-crypto-key-generator
            KeyGenerator keyGen = KeyGenerator.getInstance("Blowfish");
            SecretKey secretKey = keyGen.generateKey();
            System.out.println("Generated Blowfish key: " + secretKey.toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_4() {
        try {
            String algorithm = "RC4";
            // ruleid: java-crypto-key-generator
            KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
            SecretKey secretKey = keyGen.generateKey();
            System.out.println("Generated RC4 key: " + secretKey.toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_5() {
        try {
            // ruleid: java-crypto-key-generator
            KeyGenerator keyGen = KeyGenerator.getInstance("HmacMD5");
            SecretKey secretKey = keyGen.generateKey();
            System.out.println("Generated HmacMD5 key: " + secretKey.toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_6() {
        try {
            // ruleid: java-crypto-key-generator
            KeyGenerator keyGen = KeyGenerator.getInstance("DESede"); // Triple DES
            SecretKey secretKey = keyGen.generateKey();
            System.out.println("Generated Triple DES key: " + secretKey.toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_7() {
        try {
            // ruleid: java-crypto-key-generator
            KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA1");
            SecretKey secretKey = keyGen.generateKey();
            System.out.println("Generated HmacSHA1 key: " + secretKey.toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_8() {
        try {
            String[] algorithms = {"AES", "DES", "RC4"};
            for (String algorithm : algorithms) {
                if (algorithm.equals("DES")) {
                    // ruleid: java-crypto-key-generator
                    KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
                    SecretKey secretKey = keyGen.generateKey();
                    System.out.println("Generated " + algorithm + " key: " + secretKey.toString());
                }
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_9() {
        try {
            String weakAlgorithm = "RC2";
            // ruleid: java-crypto-key-generator
            KeyGenerator keyGen = KeyGenerator.getInstance(weakAlgorithm);
            keyGen.init(128);
            SecretKey secretKey = keyGen.generateKey();
            System.out.println("Generated " + weakAlgorithm + " key: " + secretKey.toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_10() {
        try {
            if (System.currentTimeMillis() % 2 == 0) {
                // ruleid: java-crypto-key-generator
                KeyGenerator keyGen = KeyGenerator.getInstance("DES");
                SecretKey secretKey = keyGen.generateKey();
                System.out.println("Generated DES key: " + secretKey.toString());
            } else {
                // This is a true negative, but it's inside a true positive function
                KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                SecretKey secretKey = keyGen.generateKey();
                System.out.println("Generated AES key: " + secretKey.toString());
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_11() {
        try {
            for (int i = 0; i < 3; i++) {
                String algorithm;
                switch (i) {
                    case 0:
                        algorithm = "AES";
                        break;
                    case 1:
                        algorithm = "HmacSHA256";
                        break;
                    default:
                        algorithm = "RC4";
                        // ruleid: java-crypto-key-generator
                        KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
                        SecretKey secretKey = keyGen.generateKey();
                        System.out.println("Generated " + algorithm + " key: " + secretKey.toString());
                }
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_12() {
        try {
            // ruleid: java-crypto-key-generator
            KeyGenerator keyGen = KeyGenerator.getInstance("HmacMD5");
            keyGen.init(new SecureRandom());
            SecretKey secretKey = keyGen.generateKey();
            System.out.println("Generated HmacMD5 key with SecureRandom: " + secretKey.toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_13() {
        try {
            String algorithm = getWeakAlgorithm();
            // ruleid: java-crypto-key-generator
            KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
            SecretKey secretKey = keyGen.generateKey();
            System.out.println("Generated " + algorithm + " key: " + secretKey.toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    private String getWeakAlgorithm() {
        return "DES";
    }

    public void bad_case_14() {
        try {
            // ruleid: java-crypto-key-generator
            KeyGenerator keyGen = KeyGenerator.getInstance("RC4");
            keyGen.init(128, new SecureRandom());
            SecretKey secretKey = keyGen.generateKey();
            System.out.println("Generated RC4 key with SecureRandom and 128 bits: " + secretKey.toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_15() {
        class CryptoHelper {
            public SecretKey generateKey(String algorithm) throws NoSuchAlgorithmException {
                KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
                return keyGen.generateKey();
            }
        }

        try {
            CryptoHelper helper = new CryptoHelper();
            // ruleid: java-crypto-key-generator
            SecretKey secretKey = helper.generateKey("DESede");
            System.out.println("Generated Triple DES key via helper: " + secretKey.toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    // True Negatives (Secure Code)

    public void good_case_1() {
        try {
            // ok: java-crypto-key-generator
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            SecretKey secretKey = keyGen.generateKey();
            System.out.println("Generated AES key: " + secretKey.toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void good_case_2() {
        try {
            // ok: java-crypto-key-generator
            KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
            SecretKey secretKey = keyGen.generateKey();
            System.out.println("Generated HmacSHA256 key: " + secretKey.toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void good_case_3() {
        try {
            // ok: java-crypto-key-generator
            KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA384");
            keyGen.init(new SecureRandom());
            SecretKey secretKey = keyGen.generateKey();
            System.out.println("Generated HmacSHA384 key with SecureRandom: " + secretKey.toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void good_case_4() {
        try {
            String algorithm = "HmacSHA512";
            // ok: java-crypto-key-generator
            KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
            SecretKey secretKey = keyGen.generateKey();
            System.out.println("Generated " + algorithm + " key: " + secretKey.toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void good_case_5() {
        try {
            // ok: java-crypto-key-generator
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey secretKey = keyGen.generateKey();
            System.out.println("Generated AES-256 key: " + secretKey.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_6() {
        try {
            String[] algorithms = {"AES", "HmacSHA256", "HmacSHA512"};
            for (String algorithm : algorithms) {
                // ok: java-crypto-key-generator
                KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
                SecretKey secretKey = keyGen.generateKey();
                System.out.println("Generated " + algorithm + " key: " + secretKey.toString());
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void good_case_7() {
        try {
            String secureAlgorithm = getSecureAlgorithm();
            // ok: java-crypto-key-generator
            KeyGenerator keyGen = KeyGenerator.getInstance(secureAlgorithm);
            SecretKey secretKey = keyGen.generateKey();
            System.out.println("Generated " + secureAlgorithm + " key: " + secretKey.toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    private String getSecureAlgorithm() {
        return "HmacSHA256";
    }

    public void good_case_8() {
        try {
            if (System.currentTimeMillis() % 2 == 0) {
                // ok: java-crypto-key-generator
                KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                keyGen.init(256, new SecureRandom());
                SecretKey secretKey = keyGen.generateKey();
                System.out.println("Generated AES-256 key with SecureRandom: " + secretKey.toString());
            } else {
                // ok: java-crypto-key-generator
                KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA512");
                SecretKey secretKey = keyGen.generateKey();
                System.out.println("Generated HmacSHA512 key: " + secretKey.toString());
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void good_case_9() {
        try {
            for (int i = 0; i < 3; i++) {
                String algorithm;
                switch (i) {
                    case 0:
                        algorithm = "AES";
                        break;
                    case 1:
                        algorithm = "HmacSHA256";
                        break;
                    default:
                        algorithm = "HmacSHA512";
                }
                // ok: java-crypto-key-generator
                KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
                SecretKey secretKey = keyGen.generateKey();
                System.out.println("Generated " + algorithm + " key: " + secretKey.toString());
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void good_case_10() {
        class SecureCryptoHelper {
            public SecretKey generateKey(String algorithm) throws NoSuchAlgorithmException {
                KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
                return keyGen.generateKey();
            }
        }

        try {
            SecureCryptoHelper helper = new SecureCryptoHelper();
            // ok: java-crypto-key-generator
            SecretKey secretKey = helper.generateKey("AES");
            System.out.println("Generated AES key via helper: " + secretKey.toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void good_case_11() {
        try {
            // ok: java-crypto-key-generator
            KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA224");
            SecretKey secretKey = keyGen.generateKey();
            System.out.println("Generated HmacSHA224 key: " + secretKey.toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void good_case_12() {
        try {
            // ok: java-crypto-key-generator
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(192);
            SecretKey secretKey = keyGen.generateKey();
            System.out.println("Generated AES-192 key: " + secretKey.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_13() {
        try {
            String[] secureAlgorithms = {"AES", "HmacSHA224", "HmacSHA256", "HmacSHA384", "HmacSHA512"};
            int index = (int) (System.currentTimeMillis() % secureAlgorithms.length);
            String algorithm = secureAlgorithms[index];
            
            // ok: java-crypto-key-generator
            KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
            SecretKey secretKey = keyGen.generateKey();
            System.out.println("Generated " + algorithm + " key: " + secretKey.toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void good_case_14() {
        try {
            // ok: java-crypto-key-generator
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128, new SecureRandom());
            SecretKey secretKey = keyGen.generateKey();
            System.out.println("Generated AES-128 key with SecureRandom: " + secretKey.toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void good_case_15() {
        try {
            String algorithm = "AES";
            int keySize = 256;
            
            // ok: java-crypto-key-generator
            KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
            try {
                keyGen.init(keySize);
            } catch (Exception e) {
                // Fallback to 128 if JCE jurisdiction policy files not installed
                keyGen.init(128);
            }
            SecretKey secretKey = keyGen.generateKey();
            System.out.println("Generated AES key with fallback: " + secretKey.toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}
// {/fact}