import java.security.Security;
import java.security.Provider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.jcajce.provider.symmetric.AES;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.jce.provider.JCEECPublicKey;
import org.bouncycastle.jce.provider.JDKKeyPairGenerator;
import org.bouncycastle.jce.provider.JDKMessageDigest;
import org.bouncycastle.jce.provider.JCEBlockCipher;
import org.bouncycastle.jce.provider.JCEKeyGenerator;
import org.bouncycastle.jce.provider.JDKKeyFactory;
import org.bouncycastle.jce.provider.JCESecretKeyFactory;
import org.bouncycastle.jce.provider.JDKPSSSigner;
import org.bouncycastle.jce.provider.JCEElGamalCipher;
import org.bouncycastle.jce.provider.JDKDSASigner;
import org.bouncycastle.jce.provider.JDKDigestSignature;
import org.bouncycastle.jce.provider.JCEStreamCipher;
import org.bouncycastle.jce.provider.JCEMac;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.security.Signature;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Mac;
import java.math.BigInteger;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Callable;

// Security Issue: Improper instantiation of BouncyCastle provider directly instead of using Security.addProvider()

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1() {
    // Basic encryption with direct BouncyCastle instantiation
    try {
        // ruleid: java-improper-instantiation-of-bouncy-castle
        BouncyCastleProvider provider = new BouncyCastleProvider();
        
        KeyGenerator keyGen = KeyGenerator.getInstance("AES", provider);
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", provider);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        
        byte[] data = "Sensitive data".getBytes();
        byte[] encrypted = cipher.doFinal(data);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_2() {
    // Digital signature with direct provider instantiation
    try {
        // ruleid: java-improper-instantiation-of-bouncy-castle
        Provider bcProvider = new BouncyCastleProvider();
        
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA", bcProvider);
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        
        Signature signature = Signature.getInstance("SHA256withRSA", bcProvider);
        signature.initSign(keyPair.getPrivate());
        
        byte[] message = "Message to sign".getBytes();
        signature.update(message);
        byte[] signatureBytes = signature.sign();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_3() {
    // Message digest with direct provider instantiation
    try {
        // ruleid: java-improper-instantiation-of-bouncy-castle
        BouncyCastleProvider bcProvider = new BouncyCastleProvider();
        
        MessageDigest digest = MessageDigest.getInstance("SHA-3", bcProvider);
        byte[] input = "Hash this message".getBytes();
        byte[] hash = digest.digest(input);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_4() {
    // HMAC_REDACTED_TWILIO_ID with direct provider instantiation
    try {
        // ruleid: java-improper-instantiation-of-bouncy-castle
        Provider provider = new BouncyCastleProvider();
        
        KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256", provider);
        SecretKey key = keyGen.generateKey();
        
        Mac mac = Mac.getInstance("HmacSHA256", provider);
        mac.init(key);
        
        byte[] message = "Authenticate this message".getBytes();
        byte[] authCode = mac.doFinal(message);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_5() {
    // Key pair generation with direct provider instantiation
    try {
        // ruleid: java-improper-instantiation-of-bouncy-castle
        Provider bcProvider = new BouncyCastleProvider();
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA", bcProvider);
        keyGen.initialize(256);
        KeyPair keyPair = keyGen.generateKeyPair();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_6() {
    // Multiple instances in different methods
    try {
        // ruleid: java-improper-instantiation-of-bouncy-castle
        BouncyCastleProvider provider = new BouncyCastleProvider();
        
        // Using BC for AES key generation
        KeyGenerator keyGen = KeyGenerator.getInstance("AES", provider);
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();
        
        useKey(key);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

private void useKey(SecretKey key) {
    try {
        // ruleid: java-improper-instantiation-of-bouncy-castle
        BouncyCastleProvider provider = new BouncyCastleProvider();
        
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", provider);
        // Use cipher with the key
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_7() {
    // In a multi-threaded environment
    ExecutorService executor = Executors.newFixedThreadPool(5);
    
    Callable<byte[]> encryptTask = () -> {
        try {
            // ruleid: java-improper-instantiation-of-bouncy-castle
            BouncyCastleProvider provider = new BouncyCastleProvider();
            
            KeyGenerator keyGen = KeyGenerator.getInstance("AES", provider);
            keyGen.init(256);
            SecretKey key = keyGen.generateKey();
            
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", provider);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            
            return cipher.doFinal("Sensitive data".getBytes());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    };
    
    try {
        Future<byte[]> future = executor.submit(encryptTask);
        byte[] result = future.get();
        executor.shutdown();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_8() {
    // Using BC for ElGamal encryption
    try {
        // ruleid: java-improper-instantiation-of-bouncy-castle
        Provider bcProvider = new BouncyCastleProvider();
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ElGamal", bcProvider);
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        Cipher cipher = Cipher.getInstance("ElGamal/None/PKCS1Padding", bcProvider);
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        
        byte[] data = "Sensitive data".getBytes();
        byte[] encrypted = cipher.doFinal(data);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_9() {
    // Using BC for ECDH key agreement
    try {
        // ruleid: java-improper-instantiation-of-bouncy-castle
        BouncyCastleProvider provider = new BouncyCastleProvider();
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDH", provider);
        keyGen.initialize(256);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        // Use the key pair for ECDH operations
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_10() {
    // Using BC for DSA signatures
    try {
        // ruleid: java-improper-instantiation-of-bouncy-castle
        Provider bcProvider = new BouncyCastleProvider();
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", bcProvider);
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        Signature signature = Signature.getInstance("SHA256withDSA", bcProvider);
        signature.initSign(keyPair.getPrivate());
        
        byte[] message = "Message to sign".getBytes();
        signature.update(message);
        byte[] signatureBytes = signature.sign();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_11() {
    // Using BC for RIPEMD160 hash
    try {
        // ruleid: java-improper-instantiation-of-bouncy-castle
        BouncyCastleProvider provider = new BouncyCastleProvider();
        
        MessageDigest digest = MessageDigest.getInstance("RIPEMD160", provider);
        byte[] input = "Hash this message".getBytes();
        byte[] hash = digest.digest(input);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_12() {
    // Using BC for Blowfish encryption
    try {
        // ruleid: java-improper-instantiation-of-bouncy-castle
        Provider bcProvider = new BouncyCastleProvider();
        
        KeyGenerator keyGen = KeyGenerator.getInstance("Blowfish", bcProvider);
        SecretKey key = keyGen.generateKey();
        
        Cipher cipher = Cipher.getInstance("Blowfish/CBC/PKCS7Padding", bcProvider);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        
        byte[] data = "Sensitive data".getBytes();
        byte[] encrypted = cipher.doFinal(data);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_13() {
    // Using BC for GOST hash
    try {
        // ruleid: java-improper-instantiation-of-bouncy-castle
        BouncyCastleProvider provider = new BouncyCastleProvider();
        
        MessageDigest digest = MessageDigest.getInstance("GOST3411", provider);
        byte[] input = "Hash this message".getBytes();
        byte[] hash = digest.digest(input);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_14() {
    // Using BC for IDEA encryption
    try {
        // ruleid: java-improper-instantiation-of-bouncy-castle
        Provider bcProvider = new BouncyCastleProvider();
        
        KeyGenerator keyGen = KeyGenerator.getInstance("IDEA", bcProvider);
        SecretKey key = keyGen.generateKey();
        
        Cipher cipher = Cipher.getInstance("IDEA/CBC/PKCS7Padding", bcProvider);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        
        byte[] data = "Sensitive data".getBytes();
        byte[] encrypted = cipher.doFinal(data);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_15() {
    // Using BC for ECIES encryption
    try {
        // ruleid: java-improper-instantiation-of-bouncy-castle
        BouncyCastleProvider provider = new BouncyCastleProvider();
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", provider);
        keyGen.initialize(256);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        Cipher cipher = Cipher.getInstance("ECIES", provider);
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        
        byte[] data = "Sensitive data".getBytes();
        byte[] encrypted = cipher.doFinal(data);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1() {
    // Basic encryption with proper provider registration
    try {
        // ok: java-improper-instantiation-of-bouncy-castle
        Security.addProvider(new BouncyCastleProvider());
        
        KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BC");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        
        byte[] data = "Sensitive data".getBytes();
        byte[] encrypted = cipher.doFinal(data);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_2() {
    // Digital signature with proper provider registration
    try {
        // ok: java-improper-instantiation-of-bouncy-castle
        Security.addProvider(new BouncyCastleProvider());
        
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        
        Signature signature = Signature.getInstance("SHA256withRSA", "BC");
        signature.initSign(keyPair.getPrivate());
        
        byte[] message = "Message to sign".getBytes();
        signature.update(message);
        byte[] signatureBytes = signature.sign();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_3() {
    // Message digest with proper provider registration
    try {
        // ok: java-improper-instantiation-of-bouncy-castle
        Security.addProvider(new BouncyCastleProvider());
        
        MessageDigest digest = MessageDigest.getInstance("SHA-3", "BC");
        byte[] input = "Hash this message".getBytes();
        byte[] hash = digest.digest(input);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_4() {
    // HMAC_REDACTED_TWILIO_ID with proper provider registration
    try {
        // ok: java-improper-instantiation-of-bouncy-castle
        Security.addProvider(new BouncyCastleProvider());
        
        KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256", "BC");
        SecretKey key = keyGen.generateKey();
        
        Mac mac = Mac.getInstance("HmacSHA256", "BC");
        mac.init(key);
        
        byte[] message = "Authenticate this message".getBytes();
        byte[] authCode = mac.doFinal(message);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_5() {
    // Key pair generation with proper provider registration
    try {
        // ok: java-improper-instantiation-of-bouncy-castle
        Security.addProvider(new BouncyCastleProvider());
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA", "BC");
        keyGen.initialize(256);
        KeyPair keyPair = keyGen.generateKeyPair();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_6() {
    // Using provider position for priority
    try {
        // ok: java-improper-instantiation-of-bouncy-castle
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");  // Will use BC as first provider
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();
        
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");  // Will use BC as first provider
        // Use cipher
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_7() {
    // In a multi-threaded environment with proper provider registration
    // Register the provider once at application startup
    // ok: java-improper-instantiation-of-bouncy-castle
    Security.addProvider(new BouncyCastleProvider());
    
    ExecutorService executor = Executors.newFixedThreadPool(5);
    
    Callable<byte[]> encryptTask = () -> {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BC");
            keyGen.init(256);
            SecretKey key = keyGen.generateKey();
            
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            
            return cipher.doFinal("Sensitive data".getBytes());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    };
    
    try {
        Future<byte[]> future = executor.submit(encryptTask);
        byte[] result = future.get();
        executor.shutdown();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_8() {
    // Using BC for ElGamal encryption with proper provider registration
    try {
        // ok: java-improper-instantiation-of-bouncy-castle
        Security.addProvider(new BouncyCastleProvider());
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ElGamal", "BC");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        Cipher cipher = Cipher.getInstance("ElGamal/None/PKCS1Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        
        byte[] data = "Sensitive data".getBytes();
        byte[] encrypted = cipher.doFinal(data);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_9() {
    // Using BC for ECDH key agreement with proper provider registration
    try {
        // ok: java-improper-instantiation-of-bouncy-castle
        Security.addProvider(new BouncyCastleProvider());
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDH", "BC");
        keyGen.initialize(256);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        // Use the key pair for ECDH operations
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_10() {
    // Using BC for DSA signatures with proper provider registration
    try {
        // ok: java-improper-instantiation-of-bouncy-castle
        Security.addProvider(new BouncyCastleProvider());
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "BC");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        Signature signature = Signature.getInstance("SHA256withDSA", "BC");
        signature.initSign(keyPair.getPrivate());
        
        byte[] message = "Message to sign".getBytes();
        signature.update(message);
        byte[] signatureBytes = signature.sign();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_11() {
    // Using BC for RIPEMD160 hash with proper provider registration
    try {
        // ok: java-improper-instantiation-of-bouncy-castle
        Security.addProvider(new BouncyCastleProvider());
        
        MessageDigest digest = MessageDigest.getInstance("RIPEMD160", "BC");
        byte[] input = "Hash this message".getBytes();
        byte[] hash = digest.digest(input);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_12() {
    // Using BC for Blowfish encryption with proper provider registration
    try {
        // ok: java-improper-instantiation-of-bouncy-castle
        Security.addProvider(new BouncyCastleProvider());
        
        KeyGenerator keyGen = KeyGenerator.getInstance("Blowfish", "BC");
        SecretKey key = keyGen.generateKey();
        
        Cipher cipher = Cipher.getInstance("Blowfish/CBC/PKCS7Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        
        byte[] data = "Sensitive data".getBytes();
        byte[] encrypted = cipher.doFinal(data);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_13() {
    // Using BC for GOST hash with proper provider registration
    try {
        // ok: java-improper-instantiation-of-bouncy-castle
        Security.addProvider(new BouncyCastleProvider());
        
        MessageDigest digest = MessageDigest.getInstance("GOST3411", "BC");
        byte[] input = "Hash this message".getBytes();
        byte[] hash = digest.digest(input);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_14() {
    // Using BC for IDEA encryption with proper provider registration
    try {
        // ok: java-improper-instantiation-of-bouncy-castle
        Security.addProvider(new BouncyCastleProvider());
        
        KeyGenerator keyGen = KeyGenerator.getInstance("IDEA", "BC");
        SecretKey key = keyGen.generateKey();
        
        Cipher cipher = Cipher.getInstance("IDEA/CBC/PKCS7Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        
        byte[] data = "Sensitive data".getBytes();
        byte[] encrypted = cipher.doFinal(data);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_15() {
    // Using BC for ECIES encryption with proper provider registration
    try {
        // ok: java-improper-instantiation-of-bouncy-castle
        Security.addProvider(new BouncyCastleProvider());
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
        keyGen.initialize(256);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        
        byte[] data = "Sensitive data".getBytes();
        byte[] encrypted = cipher.doFinal(data);
    } catch (Exception e) {
        e.printStackTrace();
    }
}