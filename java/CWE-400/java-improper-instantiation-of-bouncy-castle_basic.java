import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Provider;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class BouncyCastleExamples {

    // True Positives (Vulnerable/Insecure Code)

// {fact rule=resource-leak@v1.0 defects=1}
    public void bad_case_1() {
        // Direct instantiation of BouncyCastleProvider without adding to Security
        // ruleid: java-improper-instantiation-of-bouncy-castle
        BouncyCastleProvider provider = new BouncyCastleProvider();
        
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", provider);
            // Use cipher for encryption/decryption
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_2() {
        try {
            // Creating multiple instances of BouncyCastleProvider
            // ruleid: java-improper-instantiation-of-bouncy-castle
            BouncyCastleProvider provider1 = new BouncyCastleProvider();
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", provider1);
            
            // Another instance in the same method
            // ruleid: java-improper-instantiation-of-bouncy-castle
            BouncyCastleProvider provider2 = new BouncyCastleProvider();
            Cipher cipher = Cipher.getInstance("AES", provider2);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_3() {
        try {
            // Using provider in a loop, creating new instance each time
            for (int i = 0; i < 5; i++) {
                // ruleid: java-improper-instantiation-of-bouncy-castle
                BouncyCastleProvider provider = new BouncyCastleProvider();
                MessageDigest digest = MessageDigest.getInstance("SHA-256", provider);
                // Use digest
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_4() {
        // Instantiating with different constructor parameters
        // ruleid: java-improper-instantiation-of-bouncy-castle
        BouncyCastleProvider provider = new BouncyCastleProvider();
        
        try {
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG", provider);
            // Use random
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_5() {
        // Creating provider and using it for signature
        // ruleid: java-improper-instantiation-of-bouncy-castle
        Provider bcProvider = new BouncyCastleProvider();
        
        try {
            Signature signature = Signature.getInstance("SHA256withRSA", bcProvider);
            // Use signature
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_6() {
        try {
            // Creating provider in a conditional block
            if (System.currentTimeMillis() % 2 == 0) {
                // ruleid: java-improper-instantiation-of-bouncy-castle
                BouncyCastleProvider provider = new BouncyCastleProvider();
                KeyGenerator keyGen = KeyGenerator.getInstance("AES", provider);
                // Use keyGen
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_7() {
        // Using provider for MAC_REDACTED_TWILIO_ID
        // ruleid: java-improper-instantiation-of-bouncy-castle
        BouncyCastleProvider bcProvider = new BouncyCastleProvider();
        
        try {
            Mac hmac = Mac.getInstance("HmacSHA256", bcProvider);
            // Use hmac
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_8() {
        // Creating provider in a try-catch block
        try {
            // ruleid: java-improper-instantiation-of-bouncy-castle
            BouncyCastleProvider provider = new BouncyCastleProvider();
            Cipher cipher = Cipher.getInstance("IDEA", provider);
            // Use cipher
        } catch (Exception e) {
            // Even in exception handling, still creating a new provider
            // ruleid: java-improper-instantiation-of-bouncy-castle
            BouncyCastleProvider fallbackProvider = new BouncyCastleProvider();
            try {
                Cipher fallbackCipher = Cipher.getInstance("AES", fallbackProvider);
                // Use fallback cipher
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
    }

    public void bad_case_9() {
        // Creating provider and assigning to variable with different name
        // ruleid: java-improper-instantiation-of-bouncy-castle
        Provider cryptoProvider = new BouncyCastleProvider();
        
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA", cryptoProvider);
            // Use keyGen
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_10() {
        // Using provider with a switch statement
        String algorithm = "RSA";
        
        switch (algorithm) {
            case "RSA":
                // ruleid: java-improper-instantiation-of-bouncy-castle
                BouncyCastleProvider rsaProvider = new BouncyCastleProvider();
                try {
                    Cipher rsaCipher = Cipher.getInstance("RSA", rsaProvider);
                    // Use rsaCipher
                } catch (Exception e) {
                    e.printStackTrace();
                }
                break;
            case "AES":
                // ruleid: java-improper-instantiation-of-bouncy-castle
                BouncyCastleProvider aesProvider = new BouncyCastleProvider();
                try {
                    Cipher aesCipher = Cipher.getInstance("AES", aesProvider);
                    // Use aesCipher
                } catch (Exception e) {
                    e.printStackTrace();
                }
                break;
        }
    }

    public void bad_case_11() {
        // Creating provider in a nested method call
        try {
            // ruleid: java-improper-instantiation-of-bouncy-castle
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", new BouncyCastleProvider());
            // Use keyGen
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_12() {
        // Creating provider and using it for multiple operations
        // ruleid: java-improper-instantiation-of-bouncy-castle
        BouncyCastleProvider provider = new BouncyCastleProvider();
        
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", provider);
            MessageDigest digest = MessageDigest.getInstance("SHA-512", provider);
            SecureRandom random = SecureRandom.getInstance("DEFAULT", provider);
            // Use all these instances
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_13() {
        // Creating provider with a ternary operator
        boolean useStrongCrypto = true;
        
        try {
            // ruleid: java-improper-instantiation-of-bouncy-castle
            Provider provider = useStrongCrypto ? new BouncyCastleProvider() : Security.getProvider("SUN");
            Cipher cipher = Cipher.getInstance("AES", provider);
            // Use cipher
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_14() {
        // Creating provider and storing in an array
        Provider[] providers = new Provider[1];
        // ruleid: java-improper-instantiation-of-bouncy-castle
        providers[0] = new BouncyCastleProvider();
        
        try {
            Cipher cipher = Cipher.getInstance("Blowfish", providers[0]);
            // Use cipher
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_15() {
        // Creating provider with a method reference
        Runnable task = () -> {
            // ruleid: java-improper-instantiation-of-bouncy-castle
            BouncyCastleProvider provider = new BouncyCastleProvider();
            try {
                KeyGenerator keyGen = KeyGenerator.getInstance("DES", provider);
                // Use keyGen
            } catch (Exception e) {
                e.printStackTrace();
            }
        };
        
        task.run();
    }

    // True Negatives (Safe/Secure Code)

    public void good_case_1() {
        // Adding provider to Security once
        // ok: java-improper-instantiation-of-bouncy-castle
        Security.addProvider(new BouncyCastleProvider());
        
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            // Use cipher for encryption/decryption
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_2() {
        // Using provider by name after adding it to Security
        try {
            // ok: java-improper-instantiation-of-bouncy-castle
            if (Security.getProvider("BC") == null) {
                Security.addProvider(new BouncyCastleProvider());
            }
            
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
            // Use keyGen
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_3() {
        // Using default provider without specifying BouncyCastle
        try {
            // ok: java-improper-instantiation-of-bouncy-castle
            Cipher cipher = Cipher.getInstance("AES");
            // Use cipher
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_4() {
        // Using a different provider
        try {
            // ok: java-improper-instantiation-of-bouncy-castle
            Cipher cipher = Cipher.getInstance("AES", "SunJCE");
            // Use cipher
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_5() {
        // Adding provider at a specific position
        // ok: java-improper-instantiation-of-bouncy-castle
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256", "BC");
            // Use digest
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_6() {
        // Using provider in a loop after adding it once
        // ok: java-improper-instantiation-of-bouncy-castle
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        
        try {
            for (int i = 0; i < 5; i++) {
                MessageDigest digest = MessageDigest.getInstance("SHA-256", "BC");
                // Use digest
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_7() {
        // Using provider for MAC_REDACTED_TWILIO_ID after adding it once
        // ok: java-improper-instantiation-of-bouncy-castle
        Security.addProvider(new BouncyCastleProvider());
        
        try {
            Mac hmac = Mac.getInstance("HmacSHA256", "BC");
            SecretKey key = new SecretKeySpec(new byte[16], "HmacSHA256");
            hmac.init(key);
            // Use hmac
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_8() {
        // Using provider in a try-catch block after adding it once
        // ok: java-improper-instantiation-of-bouncy-castle
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        
        try {
            Cipher cipher = Cipher.getInstance("IDEA", "BC");
            // Use cipher
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            try {
                // Fallback to a different algorithm but still using BC provider
                Cipher fallbackCipher = Cipher.getInstance("AES", "BC");
                // Use fallback cipher
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_9() {
        // Using provider with a switch statement after adding it once
        // ok: java-improper-instantiation-of-bouncy-castle
        Security.addProvider(new BouncyCastleProvider());
        
        String algorithm = "RSA";
        
        try {
            switch (algorithm) {
                case "RSA":
                    Cipher rsaCipher = Cipher.getInstance("RSA", "BC");
                    // Use rsaCipher
                    break;
                case "AES":
                    Cipher aesCipher = Cipher.getInstance("AES", "BC");
                    // Use aesCipher
                    break;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_10() {
        // Using provider for multiple operations after adding it once
        // ok: java-improper-instantiation-of-bouncy-castle
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
            MessageDigest digest = MessageDigest.getInstance("SHA-512", "BC");
            SecureRandom random = SecureRandom.getInstance("DEFAULT", "BC");
            // Use all these instances
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_11() {
        // Using provider with a ternary operator after adding it once
        // ok: java-improper-instantiation-of-bouncy-castle
        Security.addProvider(new BouncyCastleProvider());
        
        boolean useBouncyCastle = true;
        
        try {
            String providerName = useBouncyCastle ? "BC" : "SUN";
            Cipher cipher = Cipher.getInstance("AES", providerName);
            // Use cipher
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_12() {
        // Using provider by retrieving it from Security
        try {
            // ok: java-improper-instantiation-of-bouncy-castle
            if (Security.getProvider("BC") == null) {
                Security.addProvider(new BouncyCastleProvider());
            }
            
            Provider bcProvider = Security.getProvider("BC");
            Cipher cipher = Cipher.getInstance("AES", bcProvider);
            // Use cipher
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_13() {
        // Using provider with a lambda after adding it once
        // ok: java-improper-instantiation-of-bouncy-castle
        Security.addProvider(new BouncyCastleProvider());
        
        Runnable task = () -> {
            try {
                KeyGenerator keyGen = KeyGenerator.getInstance("DES", "BC");
                // Use keyGen
            } catch (Exception e) {
                e.printStackTrace();
            }
        };
        
        task.run();
    }

    public void good_case_14() {
        // Using provider with a method reference after adding it once
        // ok: java-improper-instantiation-of-bouncy-castle
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        
        try {
            // Get all available algorithms for KeyPairGenerator from BC
            Provider bcProvider = Security.getProvider("BC");
            bcProvider.getServices().stream()
                .filter(service -> "KeyPairGenerator".equals(service.getType()))
                .forEach(service -> {
                    try {
                        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(service.getAlgorithm(), "BC");
                        // Use keyGen
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_15() {
        // Using provider after checking if it's already registered
        try {
            // ok: java-improper-instantiation-of-bouncy-castle
            Provider[] providers = Security.getProviders();
            boolean bcExists = false;
            
            for (Provider provider : providers) {
                if (provider.getName().equals("BC")) {
                    bcExists = true;
                    break;
                }
            }
            
            if (!bcExists) {
                Security.addProvider(new BouncyCastleProvider());
            }
            
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            // Use cipher
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
// {/fact}