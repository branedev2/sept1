import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

// Standard libraries
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.io.IOException;

// Web frameworks and HTTP libraries
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import com.squareup.okhttp.MediaType;
import com.squareup.okhttp.RequestBody;
import org.apache.commons.codec.binary.Hex;

// Security libraries
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

// Cloud SDKs
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.EncryptRequest;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.models.EncryptionAlgorithm;

// Security Issue: Using static or predictable Initialization Vectors (IVs) for cryptographic ciphers

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1() {
    try {
        // Using javax.crypto with static IV
        String key = "0123456789abcdef";
        // ruleid: java-crypto-insecure-iv
        byte[] iv = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        
        IvParameterSpec ivspec = new IvParameterSpec(iv);
        SecretKeySpec keyspec = new SecretKeySpec(key.getBytes(), "AES");
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keyspec, ivspec);
        
        String plaintext = "sensitive data";
        byte[] encrypted = cipher.doFinal(plaintext.getBytes());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_2() {
    try {
        // Using BouncyCastle with hardcoded IV
        // ruleid: java-crypto-insecure-iv
        byte[] iv = "1234567890abcdef".getBytes();
        byte[] key = new byte[16];
        SecureRandom.getInstanceStrong().nextBytes(key);
        
        KeyParameter keyParam = new KeyParameter(key);
        ParametersWithIV params = new ParametersWithIV(keyParam, iv);
        
        CBCBlockCipher blockCipher = new CBCBlockCipher(new AESEngine());
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(blockCipher);
        cipher.init(true, params);
        
        byte[] input = "sensitive data".getBytes();
        byte[] output = new byte[cipher.getOutputSize(input.length)];
        int len = cipher.processBytes(input, 0, input.length, output, 0);
        cipher.doFinal(output, len);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_3() {
    try {
        // Using Spring RestController with static IV from request parameter
        String encryptionKey = "ThisIsASecretKey";
        // ruleid: java-crypto-insecure-iv
        byte[] iv = new byte[16];
        Arrays.fill(iv, (byte) 0x00);
        
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(encryptionKey.getBytes(), "AES");
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        
        String plainText = "Data from Spring controller";
        byte[] encrypted = cipher.doFinal(plainText.getBytes());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_4() {
    try {
        // Using Apache HttpClient with predictable IV
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpGet request = new HttpGet("https://api.example.com/data");
        
        // ruleid: java-crypto-insecure-iv
        byte[] iv = new byte[16];
        for (int i = 0; i < iv.length; i++) {
            iv[i] = (byte) i; // Predictable pattern
        }
        
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec keySpec = new SecretKeySpec("secretkey1234567".getBytes(), "AES");
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        
        // Process response and encrypt
        String responseBody = "response data";
        byte[] encrypted = cipher.doFinal(responseBody.getBytes());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_5() {
    try {
        // Using OkHttp with constant IV
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
            .url("https://api.example.com/data")
            .build();
        
        // ruleid: java-crypto-insecure-iv
        byte[] iv = "ConstantIvVector!".getBytes();
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec keySpec = new SecretKeySpec("AES-Key-12345678".getBytes(), "AES");
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        
        Response response = client.newCall(request).execute();
        String responseData = response.body().string();
        byte[] encrypted = cipher.doFinal(responseData.getBytes());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_6() {
    try {
        // Using AWS KMS with static IV
        AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
        
        // ruleid: java-crypto-insecure-iv
        byte[] iv = "StaticIvForAWS!!".getBytes();
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        
        SecretKeySpec keySpec = new SecretKeySpec("AWSSecretKey12345".getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        
        String sensitiveData = "AWS credentials and secrets";
        byte[] encrypted = cipher.doFinal(sensitiveData.getBytes());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_7() {
    try {
        // Using Google Cloud KMS with zero-filled IV
        // ruleid: java-crypto-insecure-iv
        byte[] iv = new byte[16];
        Arrays.fill(iv, (byte) 0);
        
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec keySpec = new SecretKeySpec("GCPSecretKey12345".getBytes(), "AES");
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        
        String cloudData = "Google Cloud sensitive data";
        byte[] encrypted = cipher.doFinal(cloudData.getBytes());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_8() {
    try {
        // Using Azure Key Vault with predictable IV
        // ruleid: java-crypto-insecure-iv
        byte[] iv = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec keySpec = new SecretKeySpec("AzureKeyVaultKey".getBytes(), "AES");
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        
        String azureData = "Azure Key Vault secrets";
        byte[] encrypted = cipher.doFinal(azureData.getBytes());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_9() {
    try {
        // Using Retrofit HTTP client with static IV
        // ruleid: java-crypto-insecure-iv
        byte[] iv = "RetrofitStaticIV".getBytes();
        
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec keySpec = new SecretKeySpec("RetrofitSecretKey".getBytes(), "AES");
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        
        String apiResponse = "Retrofit API response data";
        byte[] encrypted = cipher.doFinal(apiResponse.getBytes());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_10() {
    try {
        // Using Jersey client with constant IV
        // ruleid: java-crypto-insecure-iv
        byte[] iv = Base64.getDecoder().decode("MDEyMzQ1Njc4OWFiY2RlZg=="); // Constant base64 encoded IV
        
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec keySpec = new SecretKeySpec("JerseyClientKey12".getBytes(), "AES");
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        
        String jerseyData = "Jersey client response data";
        byte[] encrypted = cipher.doFinal(jerseyData.getBytes());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_11() {
    try {
        // Using Apache Commons Crypto with hardcoded IV
        // ruleid: java-crypto-insecure-iv
        byte[] iv = Hex.decodeHex("000102030405060708090a0b0c0d0e0f".toCharArray());
        
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec keySpec = new SecretKeySpec("CommonsSecretKey".getBytes(), "AES");
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        
        String commonsData = "Apache Commons encrypted data";
        byte[] encrypted = cipher.doFinal(commonsData.getBytes());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_12() {
    try {
        // Using Netty with static IV
        // ruleid: java-crypto-insecure-iv
        byte[] iv = "NettyStaticIvVec".getBytes();
        
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec keySpec = new SecretKeySpec("NettySecretKey123".getBytes(), "AES");
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        
        String nettyData = "Netty server response data";
        byte[] encrypted = cipher.doFinal(nettyData.getBytes());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_13() {
    try {
        // Using Play Framework with predictable IV
        // ruleid: java-crypto-insecure-iv
        byte[] iv = new byte[16];
        for (int i = 0; i < 16; i++) {
            iv[i] = (byte)(i * 2); // Predictable pattern
        }
        
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec keySpec = new SecretKeySpec("PlayFrameworkKey".getBytes(), "AES");
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        
        String playData = "Play Framework response data";
        byte[] encrypted = cipher.doFinal(playData.getBytes());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_14() {
    try {
        // Using Feign client with zero IV
        // ruleid: java-crypto-insecure-iv
        byte[] iv = new byte[16]; // All zeros by default
        
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec keySpec = new SecretKeySpec("FeignClientSecret".getBytes(), "AES");
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        
        String feignData = "Feign client response data";
        byte[] encrypted = cipher.doFinal(feignData.getBytes());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_15() {
    try {
        // Using Vert.x with constant IV
        // ruleid: java-crypto-insecure-iv
        byte[] iv = "VertxConstantIV!!".getBytes();
        
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec keySpec = new SecretKeySpec("VertxSecretKey123".getBytes(), "AES");
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        
        String vertxData = "Vert.x server response data";
        byte[] encrypted = cipher.doFinal(vertxData.getBytes());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1() {
    try {
        // Using javax.crypto with SecureRandom IV
        String key = "0123456789abcdef";
        SecretKeySpec keyspec = new SecretKeySpec(key.getBytes(), "AES");
        
        // ok: java-crypto-insecure-iv
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[16];
        secureRandom.nextBytes(iv);
        
        IvParameterSpec ivspec = new IvParameterSpec(iv);
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keyspec, ivspec);
        
        String plaintext = "sensitive data";
        byte[] encrypted = cipher.doFinal(plaintext.getBytes());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_2() {
    try {
        // Using BouncyCastle with secure IV
        byte[] key = new byte[16];
        SecureRandom.getInstanceStrong().nextBytes(key);
        
        // ok: java-crypto-insecure-iv
        byte[] iv = new byte[16];
        SecureRandom.getInstanceStrong().nextBytes(iv);
        
        KeyParameter keyParam = new KeyParameter(key);
        ParametersWithIV params = new ParametersWithIV(keyParam, iv);
        
        CBCBlockCipher blockCipher = new CBCBlockCipher(new AESEngine());
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(blockCipher);
        cipher.init(true, params);
        
        byte[] input = "sensitive data".getBytes();
        byte[] output = new byte[cipher.getOutputSize(input.length)];
        int len = cipher.processBytes(input, 0, input.length, output, 0);
        cipher.doFinal(output, len);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_3() {
    try {
        // Using Spring RestController with secure IV
        String encryptionKey = "ThisIsASecretKey";
        SecretKeySpec secretKeySpec = new SecretKeySpec(encryptionKey.getBytes(), "AES");
        
        // ok: java-crypto-insecure-iv
        SecureRandom random = SecureRandom.getInstanceStrong();
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        
        String plainText = "Data from Spring controller";
        byte[] encrypted = cipher.doFinal(plainText.getBytes());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_4() {
    try {
        // Using Apache HttpClient with secure IV
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpGet request = new HttpGet("https://api.example.com/data");
        
        // ok: java-crypto-insecure-iv
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[16];
        secureRandom.nextBytes(iv);
        
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec keySpec = new SecretKeySpec("secretkey1234567".getBytes(), "AES");
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        
        // Process response and encrypt
        String responseBody = "response data";
        byte[] encrypted = cipher.doFinal(responseBody.getBytes());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_5() {
    try {
        // Using OkHttp with secure IV
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
            .url("https://api.example.com/data")
            .build();
        
        // ok: java-crypto-insecure-iv
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec keySpec = new SecretKeySpec("AES-Key-12345678".getBytes(), "AES");
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        
        Response response = client.newCall(request).execute();
        String responseData = response.body().string();
        byte[] encrypted = cipher.doFinal(responseData.getBytes());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_6() {
    try {
        // Using AWS KMS with secure IV
        AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
        
        // ok: java-crypto-insecure-iv
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[16];
        secureRandom.nextBytes(iv);
        
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec keySpec = new SecretKeySpec("AWSSecretKey12345".getBytes(), "AES");
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        
        String sensitiveData = "AWS credentials and secrets";
        byte[] encrypted = cipher.doFinal(sensitiveData.getBytes());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_7() {
    try {
        // Using Google Cloud KMS with secure IV
        // ok: java-crypto-insecure-iv
        SecureRandom secureRandom = SecureRandom.getInstanceStrong();
        byte[] iv = new byte[16];
        secureRandom.nextBytes(iv);
        
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec keySpec = new SecretKeySpec("GCPSecretKey12345".getBytes(), "AES");
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        
        String cloudData = "Google Cloud sensitive data";
        byte[] encrypted = cipher.doFinal(cloudData.getBytes());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_8() {
    try {
        // Using Azure Key Vault with secure IV
        // ok: java-crypto-insecure-iv
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[16];
        secureRandom.nextBytes(iv);
        
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec keySpec = new SecretKeySpec("AzureKeyVaultKey".getBytes(), "AES");
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        
        String azureData = "Azure Key Vault secrets";
        byte[] encrypted = cipher.doFinal(azureData.getBytes());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_9() {
    try {
        // Using Retrofit HTTP client with secure IV
        // ok: java-crypto-insecure-iv
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec keySpec = new SecretKeySpec("RetrofitSecretKey".getBytes(), "AES");
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        
        String apiResponse = "Retrofit API response data";
        byte[] encrypted = cipher.doFinal(apiResponse.getBytes());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_10() {
    try {
        // Using Jersey client with secure IV
        // ok: java-crypto-insecure-iv
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[16];
        secureRandom.nextBytes(iv);
        
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec keySpec = new SecretKeySpec("JerseyClientKey12".getBytes(), "AES");
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        
        String jerseyData = "Jersey client response data";
        byte[] encrypted = cipher.doFinal(jerseyData.getBytes());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_11() {
    try {
        // Using Apache Commons Crypto with secure IV
        // ok: java-crypto-insecure-iv
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        byte[] iv = new byte[16];
        secureRandom.nextBytes(iv);
        
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec keySpec = new SecretKeySpec("CommonsSecretKey".getBytes(), "AES");
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        
        String commonsData = "Apache Commons encrypted data";
        byte[] encrypted = cipher.doFinal(commonsData.getBytes());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_12() {
    try {
        // Using Netty with secure IV
        // ok: java-crypto-insecure-iv
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec keySpec = new SecretKeySpec("NettySecretKey123".getBytes(), "AES");
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        
        String nettyData = "Netty server response data";
        byte[] encrypted = cipher.doFinal(nettyData.getBytes());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_13() {
    try {
        // Using Play Framework with secure IV
        // ok: java-crypto-insecure-iv
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[16];
        secureRandom.nextBytes(iv);
        
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec keySpec = new SecretKeySpec("PlayFrameworkKey".getBytes(), "AES");
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        
        String playData = "Play Framework response data";
        byte[] encrypted = cipher.doFinal(playData.getBytes());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_14() {
    try {
        // Using Feign client with secure IV
        // ok: java-crypto-insecure-iv
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec keySpec = new SecretKeySpec("FeignClientSecret".getBytes(), "AES");
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        
        String feignData = "Feign client response data";
        byte[] encrypted = cipher.doFinal(feignData.getBytes());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_15() {
    try {
        // Using Vert.x with secure IV
        // ok: java-crypto-insecure-iv
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[16];
        secureRandom.nextBytes(iv);
        
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec keySpec = new SecretKeySpec("VertxSecretKey123".getBytes(), "AES");
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        
        String vertxData = "Vert.x server response data";
        byte[] encrypted = cipher.doFinal(vertxData.getBytes());
    } catch (Exception e) {
        e.printStackTrace();
    }
}