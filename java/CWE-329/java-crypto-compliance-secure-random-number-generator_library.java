import java.security.SecureRandom;
import java.util.Random;
import java.util.UUID;
import org.apache.commons.lang3.RandomUtils;
import org.apache.commons.math3.random.RandomDataGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.bouncycastle.crypto.prng.FixedSecureRandom;
import org.bouncycastle.util.encoders.Hex;
import javax.crypto.KeyGenerator;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import com.google.common.io.BaseEncoding;
import org.apache.shiro.crypto.RandomNumberGenerator;
import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.apache.shiro.util.SimpleByteSource;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.GenerateRandomRequest;
import com.google.crypto.tink.subtle.Random;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import java.nio.ByteBuffer;
import java.util.Base64;
import org.apache.commons.codec.binary.Base32;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorConfig;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.KeyRepresentation;

// Security Issue: Using insecure random number generators can lead to predictable random values

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1() {
    // Using java.util.Random for generating session IDs
    // ruleid: java-crypto-compliance-secure-random-number-generator
    Random random = new Random();
    String sessionId = String.valueOf(random.nextLong());
    System.out.println("Generated session ID: " + sessionId);
}

public void bad_case_2() {
    // Using Math.random() for generating authentication tokens
    StringBuilder token = new StringBuilder();
    for (int i = 0; i < 32; i++) {
        // ruleid: java-crypto-compliance-secure-random-number-generator
        int randomChar = (int) (Math.random() * 62);
        token.append("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".charAt(randomChar));
    }
    System.out.println("Generated auth token: " + token.toString());
}

public void bad_case_3() {
    // Using Apache Commons RandomUtils for generating password reset tokens
    byte[] tokenBytes = new byte[16];
    for (int i = 0; i < tokenBytes.length; i++) {
        // ruleid: java-crypto-compliance-secure-random-number-generator
        tokenBytes[i] = (byte) RandomUtils.nextInt(0, 256);
    }
    String resetToken = BaseEncoding.base64().encode(tokenBytes);
    System.out.println("Password reset token: " + resetToken);
}

public void bad_case_4() {
    // Using Apache Commons Math for generating initialization vectors for encryption
    try {
        String plaintext = "Sensitive data to encrypt";
        byte[] key = "0123456789abcdef".getBytes();
        
        // ruleid: java-crypto-compliance-secure-random-number-generator
        RandomDataGenerator randomDataGenerator = new RandomDataGenerator();
        byte[] iv = new byte[16];
        for (int i = 0; i < iv.length; i++) {
            iv[i] = (byte) randomDataGenerator.nextInt(0, 255);
        }
        
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        byte[] encrypted = cipher.doFinal(plaintext.getBytes());
        System.out.println("Encrypted data: " + Base64.getEncoder().encodeToString(encrypted));
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_5() {
    // Using UUID.randomUUID() for generating encryption keys
    try {
        // ruleid: java-crypto-compliance-secure-random-number-generator
        UUID uuid = UUID.randomUUID();
        byte[] keyBytes = ByteBuffer.allocate(16)
                .putLong(uuid.getMostSignificantBits())
                .putLong(uuid.getLeastSignificantBits())
                .array();
        
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        
        String plaintext = "Sensitive information";
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
        System.out.println("Encrypted: " + Base64.getEncoder().encodeToString(encryptedBytes));
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_6() {
    // Using custom weak random number generator for JJWT library token generation
    // ruleid: java-crypto-compliance-secure-random-number-generator
    Random random = new Random();
    byte[] key = new byte[32];
    random.nextBytes(key);
    
    String jwtToken = Jwts.builder()
            .setSubject("user123")
            .signWith(Keys.hmacShaKeyFor(key), SignatureAlgorithm.HS256)
            .compact();
    System.out.println("JWT Token: " + jwtToken);
}

public void bad_case_7() {
    // Using java.util.Random for Auth0 JWT library
    try {
        // ruleid: java-crypto-compliance-secure-random-number-generator
        Random random = new Random();
        byte[] keyBytes = new byte[32];
        random.nextBytes(keyBytes);
        
        Algorithm algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID(keyBytes);
        String token = JWT.create()
                .withIssuer("auth0")
                .withSubject("user123")
                .sign(algorithm);
        System.out.println("Auth0 JWT: " + token);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_8() {
    // Using Math.random for generating salt in password hashing
    try {
        String password = "userPassword123";
        byte[] salt = new byte[16];
        for (int i = 0; i < salt.length; i++) {
            // ruleid: java-crypto-compliance-secure-random-number-generator
            salt[i] = (byte) (Math.random() * 256);
        }
        
        String saltHex = Hex.toHexString(salt);
        System.out.println("Salt for password hashing: " + saltHex);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_9() {
    // Using java.util.Random for generating OTP codes
    // ruleid: java-crypto-compliance-secure-random-number-generator
    Random random = new Random();
    int otpCode = 100000 + random.nextInt(900000); // 6-digit OTP
    System.out.println("Generated OTP: " + otpCode);
}

public void bad_case_10() {
    // Using Math.random for generating CSRF tokens in a web application
    StringBuilder csrfToken = new StringBuilder();
    for (int i = 0; i < 16; i++) {
        // ruleid: java-crypto-compliance-secure-random-number-generator
        int index = (int) (Math.random() * 16);
        csrfToken.append("0123456789abcdef".charAt(index));
    }
    System.out.println("CSRF Token: " + csrfToken.toString());
}

public void bad_case_11() {
    // Using java.util.Random for generating nonce values in OAuth flow
    // ruleid: java-crypto-compliance-secure-random-number-generator
    Random random = new Random();
    byte[] nonceBytes = new byte[16];
    random.nextBytes(nonceBytes);
    String nonce = Base64.getEncoder().encodeToString(nonceBytes);
    System.out.println("OAuth nonce: " + nonce);
}

public void bad_case_12() {
    // Using RandomUtils for generating API keys
    StringBuilder apiKey = new StringBuilder("api_");
    for (int i = 0; i < 32; i++) {
        // ruleid: java-crypto-compliance-secure-random-number-generator
        char c = (char) RandomUtils.nextInt(97, 123); // a-z
        apiKey.append(c);
    }
    System.out.println("Generated API Key: " + apiKey.toString());
}

public void bad_case_13() {
    // Using java.util.Random for generating encryption initialization vectors with Bouncy Castle
    try {
        // ruleid: java-crypto-compliance-secure-random-number-generator
        Random random = new Random();
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        
        byte[] key = "0123456789abcdef".getBytes();
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        
        System.out.println("IV for Bouncy Castle encryption: " + Hex.toHexString(iv));
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_14() {
    // Using Math.random for generating TOTP secrets with Google Authenticator
    try {
        byte[] secretBytes = new byte[20]; // 160 bits
        for (int i = 0; i < secretBytes.length; i++) {
            // ruleid: java-crypto-compliance-secure-random-number-generator
            secretBytes[i] = (byte) (Math.random() * 256);
        }
        
        Base32 base32 = new Base32();
        String secret = base32.encodeToString(secretBytes);
        
        System.out.println("TOTP Secret: " + secret);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_15() {
    // Using java.util.Random for generating device identifiers
    // ruleid: java-crypto-compliance-secure-random-number-generator
    Random random = new Random();
    StringBuilder deviceId = new StringBuilder();
    for (int i = 0; i < 4; i++) {
        int segment = random.nextInt(65536);
        deviceId.append(String.format("%04x", segment));
        if (i < 3) deviceId.append("-");
    }
    System.out.println("Device ID: " + deviceId.toString());
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1() {
    // Using SecureRandom for generating session IDs
    // ok: java-crypto-compliance-secure-random-number-generator
    SecureRandom secureRandom = new SecureRandom();
    String sessionId = String.valueOf(secureRandom.nextLong());
    System.out.println("Generated secure session ID: " + sessionId);
}

public void good_case_2() {
    // Using SecureRandom for generating authentication tokens
    // ok: java-crypto-compliance-secure-random-number-generator
    SecureRandom secureRandom = new SecureRandom();
    StringBuilder token = new StringBuilder();
    for (int i = 0; i < 32; i++) {
        int randomChar = secureRandom.nextInt(62);
        token.append("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".charAt(randomChar));
    }
    System.out.println("Generated secure auth token: " + token.toString());
}

public void good_case_3() {
    // Using Spring Security's KeyGenerators for password reset tokens
    // ok: java-crypto-compliance-secure-random-number-generator
    String resetToken = KeyGenerators.string().generateKey();
    System.out.println("Secure password reset token: " + resetToken);
}

public void good_case_4() {
    // Using SecureRandom for generating initialization vectors for encryption
    try {
        String plaintext = "Sensitive data to encrypt";
        byte[] key = "0123456789abcdef".getBytes();
        
        // ok: java-crypto-compliance-secure-random-number-generator
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[16];
        secureRandom.nextBytes(iv);
        
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        byte[] encrypted = cipher.doFinal(plaintext.getBytes());
        System.out.println("Securely encrypted data: " + Base64.getEncoder().encodeToString(encrypted));
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_5() {
    // Using KeyGenerator for generating secure encryption keys
    try {
        // ok: java-crypto-compliance-secure-random-number-generator
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        byte[] keyBytes = keyGenerator.generateKey().getEncoded();
        
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        
        String plaintext = "Sensitive information";
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
        System.out.println("Securely encrypted: " + Base64.getEncoder().encodeToString(encryptedBytes));
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_6() {
    // Using SecureRandom for JJWT library token generation
    // ok: java-crypto-compliance-secure-random-number-generator
    SecureRandom secureRandom = new SecureRandom();
    byte[] key = new byte[32];
    secureRandom.nextBytes(key);
    
    String jwtToken = Jwts.builder()
            .setSubject("user123")
            .signWith(Keys.hmacShaKeyFor(key), SignatureAlgorithm.HS256)
            .compact();
    System.out.println("Secure JWT Token: " + jwtToken);
}

public void good_case_7() {
    // Using SecureRandom for Auth0 JWT library
    try {
        // ok: java-crypto-compliance-secure-random-number-generator
        SecureRandom secureRandom = new SecureRandom();
        byte[] keyBytes = new byte[32];
        secureRandom.nextBytes(keyBytes);
        
        Algorithm algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID(keyBytes);
        String token = JWT.create()
                .withIssuer("auth0")
                .withSubject("user123")
                .sign(algorithm);
        System.out.println("Secure Auth0 JWT: " + token);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_8() {
    // Using SecureRandom for generating salt in password hashing
    try {
        String password = "userPassword123";
        // ok: java-crypto-compliance-secure-random-number-generator
        SecureRandom secureRandom = new SecureRandom();
        byte[] salt = new byte[16];
        secureRandom.nextBytes(salt);
        
        String saltHex = Hex.toHexString(salt);
        System.out.println("Secure salt for password hashing: " + saltHex);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_9() {
    // Using SecureRandom for generating OTP codes
    // ok: java-crypto-compliance-secure-random-number-generator
    SecureRandom secureRandom = new SecureRandom();
    int otpCode = 100000 + secureRandom.nextInt(900000); // 6-digit OTP
    System.out.println("Secure OTP: " + otpCode);
}

public void good_case_10() {
    // Using SecureRandom for generating CSRF tokens in a web application
    // ok: java-crypto-compliance-secure-random-number-generator
    SecureRandom secureRandom = new SecureRandom();
    StringBuilder csrfToken = new StringBuilder();
    for (int i = 0; i < 16; i++) {
        int index = secureRandom.nextInt(16);
        csrfToken.append("0123456789abcdef".charAt(index));
    }
    System.out.println("Secure CSRF Token: " + csrfToken.toString());
}

public void good_case_11() {
    // Using Apache Shiro's SecureRandomNumberGenerator for nonce values in OAuth flow
    // ok: java-crypto-compliance-secure-random-number-generator
    RandomNumberGenerator rng = new SecureRandomNumberGenerator();
    String nonce = rng.nextBytes(16).toBase64();
    System.out.println("Secure OAuth nonce: " + nonce);
}

public void good_case_12() {
    // Using AWS KMS for generating API keys
    try {
        // ok: java-crypto-compliance-secure-random-number-generator
        AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
        GenerateRandomRequest request = new GenerateRandomRequest().withNumberOfBytes(16);
        byte[] randomBytes = kmsClient.generateRandom(request).getPlaintext().array();
        
        String apiKey = "api_" + BaseEncoding.base64Url().omitPadding().encode(randomBytes);
        System.out.println("Secure API Key: " + apiKey);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_13() {
    // Using Bouncy Castle's FixedSecureRandom for encryption initialization vectors
    try {
        // ok: java-crypto-compliance-secure-random-number-generator
        SecureRandom secureRandom = new SecureRandom();
        byte[] seed = new byte[16];
        secureRandom.nextBytes(seed);
        
        FixedSecureRandom fixedSecureRandom = new FixedSecureRandom(seed);
        byte[] iv = new byte[16];
        fixedSecureRandom.nextBytes(iv);
        
        byte[] key = "0123456789abcdef".getBytes();
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        
        System.out.println("Secure IV for Bouncy Castle encryption: " + Hex.toHexString(iv));
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_14() {
    // Using Google Authenticator with SecureRandom for generating TOTP secrets
    try {
        // ok: java-crypto-compliance-secure-random-number-generator
        GoogleAuthenticatorConfig config = new GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder()
            .setKeyRepresentation(KeyRepresentation.BASE32)
            .build();
        
        GoogleAuthenticator gAuth = new GoogleAuthenticator(config);
        GoogleAuthenticatorKey key = gAuth.createCredentials();
        
        String secret = key.getKey();
        System.out.println("Secure TOTP Secret: " + secret);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_15() {
    // Using Google Tink's Random for generating device identifiers
    // ok: java-crypto-compliance-secure-random-number-generator
    byte[] bytes = Random.randBytes(16);
    StringBuilder deviceId = new StringBuilder();
    for (int i = 0; i < 4; i++) {
        int value = ((bytes[i*4] & 0xFF) << 24) | 
                   ((bytes[i*4+1] & 0xFF) << 16) | 
                   ((bytes[i*4+2] & 0xFF) << 8) | 
                   (bytes[i*4+3] & 0xFF);
        deviceId.append(String.format("%08x", value));
        if (i < 3) deviceId.append("-");
    }
    System.out.println("Secure Device ID: " + deviceId.toString());
}