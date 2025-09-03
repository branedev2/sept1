import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.util.Base64;
import java.nio.charset.StandardCharsets;

// For Spring Framework examples
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

// For Apache HttpClient examples
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.entity.StringEntity;

// For Bouncy Castle examples
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

// For Jasypt examples
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.encryption.pbe.config.SimpleStringPBEConfig;

// For Google Tink examples
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AeadKeyTemplates;

// For AWS SDK examples
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.EncryptRequest;
import com.amazonaws.services.kms.model.EncryptResult;
import com.amazonaws.services.kms.model.DecryptRequest;
import java.nio.ByteBuffer;

// For OkHttp examples
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.RequestBody;

// For Retrofit examples
import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;
import retrofit2.http.Body;
import retrofit2.http.POST;

// For Conscrypt examples
import org.conscrypt.Conscrypt;

// For Apache Shiro examples
import org.apache.shiro.crypto.AesCipherService;
import org.apache.shiro.util.ByteSource;

// For Java EE Security examples
import javax.security.enterprise.identitystore.Pbkdf2PasswordHash;

// For Nimbus JOSE+JWT examples
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.DirectEncrypter;

// For Picketbox examples
import org.picketbox.datasource.security.SecureIdentityLoginModule;

// For ESAPI examples
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encryptor;
import org.owasp.esapi.crypto.CipherText;

// Security Issue: Improper use of cryptographic APIs can lead to vulnerabilities like weak encryption algorithms, insecure padding modes, lack of integrity checks, and insufficient key sizes

// True Positive Examples (Vulnerable/Insecure Code)
public class CryptoVulnerabilities {

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) throws Exception {
        // Using javax.crypto with weak algorithm (DES)
        String algorithm = request.getParameter("algorithm");
        if (algorithm == null) {
            algorithm = "DES"; // Default to weak algorithm
        }
        
        // ruleid: java-crypto-compliance-cipher
        Cipher cipher = Cipher.getInstance(algorithm);
        SecretKeySpec keySpec = new SecretKeySpec("12345678".getBytes(), algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        
        String data = request.getParameter("data");
        byte[] encrypted = cipher.doFinal(data.getBytes());
        System.out.println(Base64.getEncoder().encodeToString(encrypted));
    }

    @RestController
    public class bad_case_2 {
        // Using Spring Framework with ECB mode (no IV)
        @RequestMapping("/encrypt")
        public String encryptData(@RequestParam String data) throws Exception {
            // ruleid: java-crypto-compliance-cipher
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            SecretKeySpec keySpec = new SecretKeySpec("0123456789abcdef".getBytes(), "AES");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            
            byte[] encrypted = cipher.doFinal(data.getBytes());
            return Base64.getEncoder().encodeToString(encrypted);
        }
    }

    public void bad_case_3() throws Exception {
        // Using Bouncy Castle with insufficient key size
        BouncyCastleProvider provider = new BouncyCastleProvider();
        
        byte[] key = new byte[8]; // 64-bit key (too short)
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(key);
        new SecureRandom().nextBytes(iv);
        
        // ruleid: java-crypto-compliance-cipher
        CBCBlockCipher blockCipher = new CBCBlockCipher(new AESEngine());
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(blockCipher, new PKCS7Padding());
        ParametersWithIV params = new ParametersWithIV(new KeyParameter(key), iv);
        cipher.init(true, params);
        
        // Process data
        byte[] data = "Sensitive data".getBytes();
        byte[] output = new byte[cipher.getOutputSize(data.length)];
        int len = cipher.processBytes(data, 0, data.length, output, 0);
        cipher.doFinal(output, len);
    }

    public void bad_case_4(HttpServletRequest request) {
        // Using Jasypt with weak algorithm (PBEWithMD5AndDES)
        StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
        SimpleStringPBEConfig config = new SimpleStringPBEConfig();
        
        // ruleid: java-crypto-compliance-cipher
        config.setAlgorithm("PBEWithMD5AndDES");
        config.setPassword(request.getParameter("password"));
        config.setKeyObtentionIterations(1000);
        encryptor.setConfig(config);
        
        String encrypted = encryptor.encrypt(request.getParameter("data"));
        System.out.println(encrypted);
    }

    public void bad_case_5(HttpServletRequest request) throws Exception {
        // Using Apache Shiro with weak key size
        AesCipherService cipherService = new AesCipherService();
        
        // ruleid: java-crypto-compliance-cipher
        cipherService.setKeySize(64); // Weak key size
        
        String password = request.getParameter("password");
        ByteSource key = ByteSource.Util.bytes(password.getBytes());
        String data = request.getParameter("data");
        
        ByteSource encrypted = cipherService.encrypt(data.getBytes(), key.getBytes());
        System.out.println(encrypted.toHex());
    }

    public void bad_case_6(HttpServletRequest request) throws Exception {
        // Using javax.crypto with static IV
        byte[] staticIv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        IvParameterSpec ivSpec = new IvParameterSpec(staticIv);
        
        // ruleid: java-crypto-compliance-cipher
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec("0123456789abcdef".getBytes(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        
        String data = request.getParameter("data");
        byte[] encrypted = cipher.doFinal(data.getBytes());
        System.out.println(Base64.getEncoder().encodeToString(encrypted));
    }

    public void bad_case_7(HttpServletRequest request) throws Exception {
        // Using AWS KMS with weak encryption context
        AWSKMS kmsClient = AWSKMSClientBuilder.defaultClient();
        String keyId = request.getParameter("keyId");
        String data = request.getParameter("data");
        
        // ruleid: java-crypto-compliance-cipher
        EncryptRequest encryptRequest = new EncryptRequest()
            .withKeyId(keyId)
            .withPlaintext(ByteBuffer.wrap(data.getBytes()));
        
        EncryptResult encryptResult = kmsClient.encrypt(encryptRequest);
        ByteBuffer ciphertextBlob = encryptResult.getCiphertextBlob();
    }

    public void bad_case_8(HttpServletRequest request) throws Exception {
        // Using Nimbus JOSE+JWT with weak encryption method
        String key = request.getParameter("key");
        byte[] keyBytes = key.getBytes();
        
        // ruleid: java-crypto-compliance-cipher
        JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256);
        Payload payload = new Payload(request.getParameter("data"));
        
        JWEObject jweObject = new JWEObject(header, payload);
        jweObject.encrypt(new DirectEncrypter(keyBytes));
        
        String serializedJWE = jweObject.serialize();
        System.out.println(serializedJWE);
    }

    public void bad_case_9(HttpServletRequest request) throws Exception {
        // Using ESAPI with weak transform
        Encryptor encryptor = ESAPI.encryptor();
        String plaintext = request.getParameter("data");
        
        // ruleid: java-crypto-compliance-cipher
        CipherText ciphertext = encryptor.encrypt(
            new javax.crypto.spec.SecretKeySpec("0123456789abcdef".getBytes(), "AES"),
            plaintext,
            "AES/ECB/PKCS5Padding"  // Weak mode (ECB)
        );
        
        String encrypted = ciphertext.getBase64EncodedRawCipherText();
        System.out.println(encrypted);
    }

    public void bad_case_10(HttpServletRequest request) throws Exception {
        // Using javax.crypto with null padding
        String data = request.getParameter("data");
        
        // ruleid: java-crypto-compliance-cipher
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec("0123456789abcdef".getBytes(), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(new byte[16]);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        
        // Pad data manually to block size
        int blockSize = cipher.getBlockSize();
        int padding = blockSize - (data.getBytes().length % blockSize);
        byte[] paddedData = new byte[data.getBytes().length + padding];
        System.arraycopy(data.getBytes(), 0, paddedData, 0, data.getBytes().length);
        
        byte[] encrypted = cipher.doFinal(paddedData);
        System.out.println(Base64.getEncoder().encodeToString(encrypted));
    }

    public void bad_case_11(HttpServletRequest request) throws Exception {
        // Using Picketbox with weak hash algorithm
        String password = request.getParameter("password");
        
        // ruleid: java-crypto-compliance-cipher
        String hashedPassword = SecureIdentityLoginModule.encode(password, "MD5");
        System.out.println("Hashed password: " + hashedPassword);
    }

    public void bad_case_12(HttpServletRequest request) throws Exception {
        // Using javax.crypto with RC4 (stream cipher with known vulnerabilities)
        String data = request.getParameter("data");
        
        // ruleid: java-crypto-compliance-cipher
        Cipher cipher = Cipher.getInstance("RC4");
        SecretKeySpec keySpec = new SecretKeySpec("0123456789abcdef".getBytes(), "RC4");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        
        byte[] encrypted = cipher.doFinal(data.getBytes());
        System.out.println(Base64.getEncoder().encodeToString(encrypted));
    }

    @RestController
    public class bad_case_13 {
        // Using Spring Framework with Blowfish (insufficient key size by default)
        @PostMapping("/encrypt-blowfish")
        public String encryptWithBlowfish(@RequestBody String data) throws Exception {
            // ruleid: java-crypto-compliance-cipher
            Cipher cipher = Cipher.getInstance("Blowfish/CBC/PKCS5Padding");
            SecretKeySpec keySpec = new SecretKeySpec("01234567".getBytes(), "Blowfish");
            IvParameterSpec ivSpec = new IvParameterSpec(new byte[8]);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            
            byte[] encrypted = cipher.doFinal(data.getBytes());
            return Base64.getEncoder().encodeToString(encrypted);
        }
    }

    public void bad_case_14(HttpServletRequest request) throws Exception {
        // Using javax.crypto with 3DES (vulnerable to Sweet32 attack)
        String data = request.getParameter("data");
        
        // ruleid: java-crypto-compliance-cipher
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        byte[] keyBytes = "0123456789abcdef01234567".getBytes();
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "DESede");
        IvParameterSpec ivSpec = new IvParameterSpec(new byte[8]);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        
        byte[] encrypted = cipher.doFinal(data.getBytes());
        System.out.println(Base64.getEncoder().encodeToString(encrypted));
    }

    public void bad_case_15(HttpServletRequest request) throws Exception {
        // Using javax.crypto with user-controlled algorithm
        String algorithm = request.getParameter("algorithm");
        String mode = request.getParameter("mode");
        String padding = request.getParameter("padding");
        String fullTransformation = algorithm + "/" + mode + "/" + padding;
        
        // ruleid: java-crypto-compliance-cipher
        Cipher cipher = Cipher.getInstance(fullTransformation);
        SecretKeySpec keySpec = new SecretKeySpec("0123456789abcdef".getBytes(), algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        
        String data = request.getParameter("data");
        byte[] encrypted = cipher.doFinal(data.getBytes());
        System.out.println(Base64.getEncoder().encodeToString(encrypted));
    }

    // True Negative Examples (Safe/Secure Code)
    public void good_case_1(HttpServletRequest request) throws Exception {
        // Using javax.crypto with strong algorithm and mode
        // ok: java-crypto-compliance-cipher
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();
        
        byte[] iv = new byte[12];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        
        String data = request.getParameter("data");
        byte[] encrypted = cipher.doFinal(data.getBytes());
        System.out.println(Base64.getEncoder().encodeToString(encrypted));
    }

    @RestController
    public class good_case_2 {
        // Using Spring Framework with secure mode and random IV
        @RequestMapping("/secure-encrypt")
        public String encryptDataSecurely(@RequestParam String data) throws Exception {
            // ok: java-crypto-compliance-cipher
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey key = keyGen.generateKey();
            
            byte[] iv = new byte[16];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            
            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            byte[] encrypted = cipher.doFinal(data.getBytes());
            
            // Combine IV and ciphertext for storage/transmission
            byte[] combined = new byte[iv.length + encrypted.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);
            
            return Base64.getEncoder().encodeToString(combined);
        }
    }

    public void good_case_3() throws Exception {
        // Using Bouncy Castle with sufficient key size
        BouncyCastleProvider provider = new BouncyCastleProvider();
        
        byte[] key = new byte[32]; // 256-bit key (strong)
        byte[] iv = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(key);
        random.nextBytes(iv);
        
        // ok: java-crypto-compliance-cipher
        CBCBlockCipher blockCipher = new CBCBlockCipher(new AESEngine());
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(blockCipher, new PKCS7Padding());
        ParametersWithIV params = new ParametersWithIV(new KeyParameter(key), iv);
        cipher.init(true, params);
        
        // Process data
        byte[] data = "Sensitive data".getBytes();
        byte[] output = new byte[cipher.getOutputSize(data.length)];
        int len = cipher.processBytes(data, 0, data.length, output, 0);
        cipher.doFinal(output, len);
    }

    public void good_case_4(HttpServletRequest request) {
        // Using Jasypt with strong algorithm
        StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
        SimpleStringPBEConfig config = new SimpleStringPBEConfig();
        
        // ok: java-crypto-compliance-cipher
        config.setAlgorithm("PBEWITHHMAC_REDACTED_TWILIO_ID_256");
        config.setPassword("strong-password-not-from-request");
        config.setKeyObtentionIterations(10000);
        encryptor.setConfig(config);
        
        String encrypted = encryptor.encrypt(request.getParameter("data"));
        System.out.println(encrypted);
    }

    public void good_case_5(HttpServletRequest request) throws Exception {
        // Using Google Tink for secure encryption
        AeadConfig.register();
        
        // ok: java-crypto-compliance-cipher
        KeysetHandle keysetHandle = KeysetHandle.generateNew(
            AeadKeyTemplates.AES256_GCM);
        
        Aead aead = keysetHandle.getPrimitive(Aead.class);
        
        byte[] plaintext = request.getParameter("data").getBytes(StandardCharsets.UTF_8);
        byte[] associatedData = "associated data".getBytes(StandardCharsets.UTF_8);
        
        byte[] ciphertext = aead.encrypt(plaintext, associatedData);
        System.out.println(Base64.getEncoder().encodeToString(ciphertext));
    }

    public void good_case_6(HttpServletRequest request) throws Exception {
        // Using javax.crypto with random IV
        // ok: java-crypto-compliance-cipher
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();
        
        byte[] iv = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        
        String data = request.getParameter("data");
        byte[] encrypted = cipher.doFinal(data.getBytes());
        
        // Store IV with ciphertext
        byte[] combined = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);
        
        System.out.println(Base64.getEncoder().encodeToString(combined));
    }

    public void good_case_7(HttpServletRequest request) throws Exception {
        // Using AWS KMS with encryption context for additional security
        AWSKMS kmsClient = AWSKMSClientBuilder.defaultClient();
        String keyId = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
        String data = request.getParameter("data");
        
        // Create encryption context
        java.util.Map<String, String> encryptionContext = new java.util.HashMap<>();
        encryptionContext.put("Purpose", "Data encryption");
        encryptionContext.put("Department", "IT Security");
        
        // ok: java-crypto-compliance-cipher
        EncryptRequest encryptRequest = new EncryptRequest()
            .withKeyId(keyId)
            .withPlaintext(ByteBuffer.wrap(data.getBytes()))
            .withEncryptionContext(encryptionContext);
        
        EncryptResult encryptResult = kmsClient.encrypt(encryptRequest);
        ByteBuffer ciphertextBlob = encryptResult.getCiphertextBlob();
    }

    public void good_case_8(HttpServletRequest request) throws Exception {
        // Using Nimbus JOSE+JWT with strong encryption method
        String data = request.getParameter("data");
        
        // Generate a strong key
        byte[] keyBytes = new byte[32]; // 256 bits
        SecureRandom random = new SecureRandom();
        random.nextBytes(keyBytes);
        
        // ok: java-crypto-compliance-cipher
        JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256GCM);
        Payload payload = new Payload(data);
        
        JWEObject jweObject = new JWEObject(header, payload);
        jweObject.encrypt(new DirectEncrypter(keyBytes));
        
        String serializedJWE = jweObject.serialize();
        System.out.println(serializedJWE);
    }

    public void good_case_9(HttpServletRequest request) throws Exception {
        // Using ESAPI with strong transform
        Encryptor encryptor = ESAPI.encryptor();
        String plaintext = request.getParameter("data");
        
        // Generate a strong key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();
        
        // ok: java-crypto-compliance-cipher
        CipherText ciphertext = encryptor.encrypt(
            key,
            plaintext,
            "AES/GCM/NoPadding"  // Strong mode with AEAD
        );
        
        String encrypted = ciphertext.getBase64EncodedRawCipherText();
        System.out.println(encrypted);
    }

    public void good_case_10(HttpServletRequest request) throws Exception {
        // Using Apache Shiro with strong key size
        AesCipherService cipherService = new AesCipherService();
        
        // ok: java-crypto-compliance-cipher
        cipherService.setKeySize(256); // Strong key size
        
        // Generate a secure key instead of using password directly
        byte[] key = new byte[32];
        SecureRandom random = new SecureRandom();
        random.nextBytes(key);
        ByteSource keySource = ByteSource.Util.bytes(key);
        
        String data = request.getParameter("data");
        ByteSource encrypted = cipherService.encrypt(data.getBytes(), keySource.getBytes());
        System.out.println(encrypted.toHex());
    }

    public void good_case_11(HttpServletRequest request) throws Exception {
        // Using Java EE Security with PBKDF2 for password hashing
        Pbkdf2PasswordHash pbkdf2Hash = new javax.security.enterprise.identitystore.Pbkdf2PasswordHash() {
            @Override
            public String generate(char[] password) {
                return "PBKDF2WithHmacSHA256:2048:base64encodedSalt:base64encodedHash";
            }

            @Override
            public boolean verify(char[] password, String hashedPassword) {
                return true; // Simplified for example
            }
        };
        
        java.util.Map<String, String> parameters = new java.util.HashMap<>();
        parameters.put("Pbkdf2PasswordHash.Algorithm", "PBKDF2WithHmacSHA512");
        parameters.put("Pbkdf2PasswordHash.Iterations", "210000");
        parameters.put("Pbkdf2PasswordHash.SaltSizeBytes", "32");
        parameters.put("Pbkdf2PasswordHash.KeySizeBytes", "32");
        
        // ok: java-crypto-compliance-cipher
        pbkdf2Hash.initialize(parameters);
        
        String password = request.getParameter("password");
        String hashedPassword = pbkdf2Hash.generate(password.toCharArray());
        System.out.println("Hashed password: " + hashedPassword);
    }

    public void good_case_12(HttpServletRequest request) throws Exception {
        // Using Conscrypt provider for modern TLS
        java.security.Provider provider = Conscrypt.newProvider();
        java.security.Security.insertProviderAt(provider, 1);
        
        // ok: java-crypto-compliance-cipher
        javax.net.ssl.SSLContext sslContext = javax.net.ssl.SSLContext.getInstance("TLSv1.3", provider);
        sslContext.init(null, null, null);
        
        // Create an HTTPS connection using the secure SSL context
        javax.net.ssl.HttpsURLConnection connection = 
            (javax.net.ssl.HttpsURLConnection) new java.net.URL("https://example.com").openConnection();
        connection.setSSLSocketFactory(sslContext.getSocketFactory());
        
        // Process request parameter
        String requestData = request.getParameter("data");
        connection.setRequestProperty("User-Data", requestData);
        
        connection.connect();
        // Read response...
    }

    @RestController
    public class good_case_13 {
        // Using OkHttp with secure TLS configuration
        @PostMapping("/secure-request")
        public String makeSecureRequest(@RequestBody String requestData) throws Exception {
            // ok: java-crypto-compliance-cipher
            OkHttpClient client = new OkHttpClient.Builder()
                .connectionSpecs(java.util.Collections.singletonList(
                    new okhttp3.ConnectionSpec.Builder(okhttp3.ConnectionSpec.MODERN_TLS)
                        .tlsVersions(okhttp3.TlsVersion.TLS_1_2, okhttp3.TlsVersion.TLS_1_3)
                        .cipherSuites(
                            okhttp3.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                            okhttp3.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                            okhttp3.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                            okhttp3.CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                            okhttp3.CipherSuite.TLS_ECDHE_ECDSA_WITH_CHAC_REDACTED_TWILIO_ID_POLY1305_SHA256,
                            okhttp3.CipherSuite.TLS_ECDHE_RSA_WITH_CHAC_REDACTED_TWILIO_ID_POLY1305_SHA256
                        )
                        .build()
                ))
                .build();
            
            Request request = new Request.Builder()
                .url("https://api.example.com/data")
                .post(RequestBody.create(requestData, okhttp3.MediaType.parse("application/json")))
                .build();
            
            try (Response response = client.newCall(request).execute()) {
                return response.body().string();
            }
        }
    }

    public void good_case_14(HttpServletRequest request) throws Exception {
        // Using javax.crypto with ChaCha20-Poly1305 (modern AEAD cipher)
        String data = request.getParameter("data");
        
        // ok: java-crypto-compliance-cipher
        Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
        
        KeyGenerator keyGen = KeyGenerator.getInstance("ChaCha20");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();
        
        byte[] nonce = new byte[12];
        SecureRandom random = new SecureRandom();
        random.nextBytes(nonce);
        
        javax.crypto.spec.ChaCha20ParameterSpec paramSpec = 
            new javax.crypto.spec.ChaCha20ParameterSpec(nonce, 1);
        
        cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);
        
        byte[] encrypted = cipher.doFinal(data.getBytes());
        
        // Store nonce with ciphertext
        byte[] combined = new byte[nonce.length + encrypted.length];
        System.arraycopy(nonce, 0, combined, 0, nonce.length);
        System.arraycopy(encrypted, 0, combined, nonce.length, encrypted.length);
        
        System.out.println(Base64.getEncoder().encodeToString(combined));
    }

    public interface ApiService {
        @POST("data")
        retrofit2.Call<String> sendData(@Body String data);
    }

    public void good_case_15(HttpServletRequest request) {
        // Using Retrofit with secure TLS configuration
        String data = request.getParameter("data");
        
        // Configure TLS versions and cipher suites
        okhttp3.ConnectionSpec spec = new okhttp3.ConnectionSpec.Builder(okhttp3.ConnectionSpec.MODERN_TLS)
            .tlsVersions(okhttp3.TlsVersion.TLS_1_2, okhttp3.TlsVersion.TLS_1_3)
            .cipherSuites(
                okhttp3.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                okhttp3.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                okhttp3.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                okhttp3.CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            )
            .build();
        
        // ok: java-crypto-compliance-cipher
        OkHttpClient client = new OkHttpClient.Builder()
            .connectionSpecs(java.util.Collections.singletonList(spec))
            .build();
        
        Retrofit retrofit = new Retrofit.Builder()
            .baseUrl("https://api.example.com/")
            .client(client)
            .addConverterFactory(GsonConverterFactory.create())
            .build();
        
        ApiService service = retrofit.create(ApiService.class);
        retrofit2.Call<String> call = service.sendData(data);
        
        try {
            retrofit2.Response<String> response = call.execute();
            System.out.println("Response: " + response.body());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
// {/fact}