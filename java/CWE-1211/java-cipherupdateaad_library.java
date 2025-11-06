import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.AEADBadTagException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Base64;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.EncryptRequest;
import com.google.cloud.kms.v1.CryptoKeyName;
import com.google.cloud.kms.v1.DecryptResponse;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpContent;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServer;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import org.apache.commons.codec.binary.Hex;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;
import java.util.HashMap;
import java.util.Map;

// Security Issue: Improper handling of authenticated encryption modes like GCM and CCM where ciphertext authenticity calculations 
// are performed before associated data authenticity calculations, potentially resulting in security vulnerabilities and data integrity issues.

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) {
    try {
        // Standard Java Crypto API with incorrect AAD update order
        String key = request.getParameter("key");
        String data = request.getParameter("data");
        String aad = request.getParameter("aad");
        
        byte[] keyBytes = Base64.getDecoder().decode(key);
        byte[] dataBytes = Base64.getDecoder().decode(data);
        byte[] aadBytes = aad.getBytes(StandardCharsets.UTF_8);
        
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
        
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        
        // First update with data (ciphertext) before AAD - INCORRECT ORDER
        // ruleid: java-cipherupdateaad
        cipher.update(dataBytes);
        cipher.updateAAD(aadBytes);
        
        byte[] cipherText = cipher.doFinal();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_2(HttpServletRequest request) {
    try {
        // BouncyCastle library with incorrect AAD processing
        String key = request.getParameter("key");
        String data = request.getParameter("data");
        String aad = request.getParameter("aad");
        
        byte[] keyBytes = Base64.getDecoder().decode(key);
        byte[] dataBytes = Base64.getDecoder().decode(data);
        byte[] aadBytes = aad.getBytes(StandardCharsets.UTF_8);
        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);
        
        GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());
        AEADParameters params = new AEADParameters(new KeyParameter(keyBytes), 128, nonce);
        
        cipher.init(true, params);
        
        // Process data before AAD - INCORRECT ORDER
        byte[] output = new byte[cipher.getOutputSize(dataBytes.length)];
        int offset = cipher.processBytes(dataBytes, 0, dataBytes.length, output, 0);
        
        // ruleid: java-cipherupdateaad
        cipher.processAADBytes(aadBytes, 0, aadBytes.length);
        
        cipher.doFinal(output, offset);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

@RestController
public void bad_case_3(HttpServletRequest request, HttpServletResponse response) {
    try {
        // Spring Web MVC with incorrect AAD handling
        String key = request.getHeader("X-Encryption-Key");
        String data = request.getParameter("data");
        String aad = request.getParameter("metadata");
        
        byte[] keyBytes = Base64.getDecoder().decode(key);
        byte[] dataBytes = Base64.getDecoder().decode(data);
        byte[] aadBytes = aad.getBytes(StandardCharsets.UTF_8);
        
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
        
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        
        // Process part of data before AAD - INCORRECT ORDER
        // ruleid: java-cipherupdateaad
        cipher.update(dataBytes, 0, dataBytes.length / 2);
        cipher.updateAAD(aadBytes);
        cipher.update(dataBytes, dataBytes.length / 2, dataBytes.length - dataBytes.length / 2);
        
        byte[] cipherText = cipher.doFinal();
        response.getOutputStream().write(cipherText);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_4() {
    try {
        // AWS KMS with incorrect AAD handling
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpPost httpPost = new HttpPost("https://api.example.com/data");
        HttpEntity entity = httpPost.getEntity();
        String responseString = EntityUtils.toString(entity);
        
        // Parse the response to get encryption parameters
        JsonObject jsonResponse = new Gson().fromJson(responseString, JsonObject.class);
        String keyId = jsonResponse.get("keyId").getAsString();
        String data = jsonResponse.get("data").getAsString();
        String aad = jsonResponse.get("aad").getAsString();
        
        byte[] dataBytes = Base64.getDecoder().decode(data);
        byte[] aadBytes = aad.getBytes(StandardCharsets.UTF_8);
        
        // Custom implementation using AWS KMS for key but local GCM for encryption
        AWSKMS kmsClient = AWSKMSClientBuilder.defaultClient();
        ByteBuffer keyBytes = kmsClient.generateDataKey(keyId, 32).getPlaintext();
        
        SecretKey secretKey = new SecretKeySpec(keyBytes.array(), "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
        
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        
        // First update with data before AAD - INCORRECT ORDER
        // ruleid: java-cipherupdateaad
        cipher.update(dataBytes);
        cipher.updateAAD(aadBytes);
        
        byte[] cipherText = cipher.doFinal();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_5() {
    try {
        // Google Cloud KMS with incorrect AAD handling
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
            .url("https://api.example.com/secure-data")
            .build();
        
        Response response = client.newCall(request).execute();
        String responseBody = response.body().string();
        
        // Parse the response to get encryption parameters
        JsonObject jsonResponse = new Gson().fromJson(responseBody, JsonObject.class);
        String keyName = jsonResponse.get("keyName").getAsString();
        String data = jsonResponse.get("data").getAsString();
        String aad = jsonResponse.get("aad").getAsString();
        
        byte[] dataBytes = Base64.getDecoder().decode(data);
        byte[] aadBytes = aad.getBytes(StandardCharsets.UTF_8);
        
        // Using Google Cloud KMS for key but local GCM for encryption
        KeyManagementServiceClient kmsClient = KeyManagementServiceClient.create();
        CryptoKeyName cryptoKeyName = CryptoKeyName.parse(keyName);
        
        // Get encryption key from Google Cloud KMS
        byte[] keyBytes = kmsClient.decrypt(cryptoKeyName.toString(), ByteBuffer.wrap(dataBytes)).getPlaintext().toByteArray();
        
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
        
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        
        // First update with data before AAD - INCORRECT ORDER
        // ruleid: java-cipherupdateaad
        cipher.update(dataBytes);
        cipher.updateAAD(aadBytes);
        
        byte[] cipherText = cipher.doFinal();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_6() {
    try {
        // Retrofit HTTP client with incorrect AAD handling
        Retrofit retrofit = new Retrofit.Builder()
            .baseUrl("https://api.example.com/")
            .addConverterFactory(GsonConverterFactory.create())
            .build();
        
        // Assume we have an API interface and get encryption parameters
        Map<String, String> requestBody = new HashMap<>();
        requestBody.put("operation", "encrypt");
        
        retrofit2.Call<Map<String, String>> call = retrofit.create(ApiService.class).getEncryptionParams(requestBody);
        retrofit2.Response<Map<String, String>> response = call.execute();
        
        Map<String, String> encryptionParams = response.body();
        String key = encryptionParams.get("key");
        String data = encryptionParams.get("data");
        String aad = encryptionParams.get("aad");
        
        byte[] keyBytes = Base64.getDecoder().decode(key);
        byte[] dataBytes = Base64.getDecoder().decode(data);
        byte[] aadBytes = aad.getBytes(StandardCharsets.UTF_8);
        
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
        
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        
        // First update with data before AAD - INCORRECT ORDER
        // ruleid: java-cipherupdateaad
        cipher.update(dataBytes);
        cipher.updateAAD(aadBytes);
        
        byte[] cipherText = cipher.doFinal();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_7(RoutingContext routingContext) {
    try {
        // Vert.x web framework with incorrect AAD handling
        String key = routingContext.request().getHeader("X-Encryption-Key");
        String data = routingContext.request().getParam("data");
        String aad = routingContext.request().getParam("aad");
        
        byte[] keyBytes = Base64.getDecoder().decode(key);
        byte[] dataBytes = Base64.getDecoder().decode(data);
        byte[] aadBytes = aad.getBytes(StandardCharsets.UTF_8);
        
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
        
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        
        // First update with data before AAD - INCORRECT ORDER
        // ruleid: java-cipherupdateaad
        cipher.update(dataBytes);
        cipher.updateAAD(aadBytes);
        
        byte[] cipherText = cipher.doFinal();
        routingContext.response().end(Base64.getEncoder().encodeToString(cipherText));
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_8(HttpServletRequest request) {
    try {
        // Spring RestTemplate with incorrect AAD handling
        RestTemplate restTemplate = new RestTemplate();
        String url = "https://api.example.com/encryption-params";
        
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", request.getHeader("Authorization"));
        
        ResponseEntity<Map> response = restTemplate.getForEntity(url, Map.class);
        Map<String, String> encryptionParams = response.getBody();
        
        String key = encryptionParams.get("key");
        String data = encryptionParams.get("data");
        String aad = encryptionParams.get("aad");
        
        byte[] keyBytes = Base64.getDecoder().decode(key);
        byte[] dataBytes = Base64.getDecoder().decode(data);
        byte[] aadBytes = aad.getBytes(StandardCharsets.UTF_8);
        
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding"); // Using CCM mode
        
        byte[] nonce = new byte[7]; // CCM typically uses 7-13 bytes
        new SecureRandom().nextBytes(nonce);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, nonce);
        
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        
        // First update with data before AAD - INCORRECT ORDER
        // ruleid: java-cipherupdateaad
        cipher.update(dataBytes);
        cipher.updateAAD(aadBytes);
        
        byte[] cipherText = cipher.doFinal();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

@PostMapping("/encrypt")
public void bad_case_9(@RequestBody Map<String, String> requestBody) {
    try {
        // Spring Boot REST API with incorrect AAD handling
        String key = requestBody.get("key");
        String data = requestBody.get("data");
        String aad = requestBody.get("aad");
        
        byte[] keyBytes = Base64.getDecoder().decode(key);
        byte[] dataBytes = Base64.getDecoder().decode(data);
        byte[] aadBytes = aad.getBytes(StandardCharsets.UTF_8);
        
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
        
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        
        // First update with data before AAD - INCORRECT ORDER
        // ruleid: java-cipherupdateaad
        cipher.update(dataBytes);
        cipher.updateAAD(aadBytes);
        
        byte[] cipherText = cipher.doFinal();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_10(HttpServletRequest request) {
    try {
        // Netty HTTP framework with incorrect AAD handling
        String key = request.getHeader("X-Encryption-Key");
        String data = request.getParameter("data");
        String aad = request.getParameter("aad");
        
        byte[] keyBytes = Hex.decodeHex(key.toCharArray());
        byte[] dataBytes = Base64.getDecoder().decode(data);
        byte[] aadBytes = aad.getBytes(StandardCharsets.UTF_8);
        
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
        
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        
        // Multiple updates with data before AAD - INCORRECT ORDER
        // ruleid: java-cipherupdateaad
        cipher.update(dataBytes, 0, dataBytes.length / 3);
        cipher.update(dataBytes, dataBytes.length / 3, dataBytes.length / 3);
        cipher.updateAAD(aadBytes);
        cipher.update(dataBytes, 2 * dataBytes.length / 3, dataBytes.length - 2 * dataBytes.length / 3);
        
        byte[] cipherText = cipher.doFinal();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_11(HttpServletRequest request) {
    try {
        // Apache HttpClient with incorrect AAD handling in decryption
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpPost httpPost = new HttpPost("https://api.example.com/decrypt");
        
        String encryptedData = request.getParameter("encryptedData");
        String iv = request.getParameter("iv");
        String key = request.getParameter("key");
        String aad = request.getParameter("aad");
        
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedData);
        byte[] ivBytes = Base64.getDecoder().decode(iv);
        byte[] keyBytes = Base64.getDecoder().decode(key);
        byte[] aadBytes = aad.getBytes(StandardCharsets.UTF_8);
        
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, ivBytes);
        
        cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);
        
        // First update with encrypted data before AAD - INCORRECT ORDER for decryption
        // ruleid: java-cipherupdateaad
        cipher.update(encryptedBytes);
        cipher.updateAAD(aadBytes);
        
        byte[] decryptedData = cipher.doFinal();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_12(HttpServletRequest request) {
    try {
        // Custom HTTP client with incorrect AAD handling
        String url = "https://api.example.com/secure-data";
        java.net.URL apiUrl = new java.net.URL(url);
        java.net.HttpURLConnection connection = (java.net.HttpURLConnection) apiUrl.openConnection();
        connection.setRequestMethod("GET");
        connection.setRequestProperty("Authorization", request.getHeader("Authorization"));
        
        int responseCode = connection.getResponseCode();
        if (responseCode == 200) {
            java.io.BufferedReader in = new java.io.BufferedReader(
                new java.io.InputStreamReader(connection.getInputStream()));
            String inputLine;
            StringBuilder response = new StringBuilder();
            
            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            in.close();
            
            JsonObject jsonResponse = new Gson().fromJson(response.toString(), JsonObject.class);
            String key = jsonResponse.get("key").getAsString();
            String data = jsonResponse.get("data").getAsString();
            String aad = jsonResponse.get("aad").getAsString();
            
            byte[] keyBytes = Base64.getDecoder().decode(key);
            byte[] dataBytes = Base64.getDecoder().decode(data);
            byte[] aadBytes = aad.getBytes(StandardCharsets.UTF_8);
            
            SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            
            byte[] iv = new byte[12];
            new SecureRandom().nextBytes(iv);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
            
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
            
            // First update with data before AAD - INCORRECT ORDER
            // ruleid: java-cipherupdateaad
            cipher.update(dataBytes);
            cipher.updateAAD(aadBytes);
            
            byte[] cipherText = cipher.doFinal();
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_13(HttpServletRequest request) {
    try {
        // Jersey Client with incorrect AAD handling
        javax.ws.rs.client.Client client = javax.ws.rs.client.ClientBuilder.newClient();
        String url = "https://api.example.com/encryption-params";
        
        javax.ws.rs.core.Response response = client.target(url)
            .request(javax.ws.rs.core.MediaType.APPLICATION_JSON)
            .header("Authorization", request.getHeader("Authorization"))
            .get();
        
        Map<String, String> encryptionParams = response.readEntity(Map.class);
        String key = encryptionParams.get("key");
        String data = encryptionParams.get("data");
        String aad = encryptionParams.get("aad");
        
        byte[] keyBytes = Base64.getDecoder().decode(key);
        byte[] dataBytes = Base64.getDecoder().decode(data);
        byte[] aadBytes = aad.getBytes(StandardCharsets.UTF_8);
        
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
        
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        
        // First update with data before AAD - INCORRECT ORDER
        // ruleid: java-cipherupdateaad
        cipher.update(dataBytes);
        cipher.updateAAD(aadBytes);
        
        byte[] cipherText = cipher.doFinal();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_14(HttpServletRequest request) {
    try {
        // Apache CXF with incorrect AAD handling
        org.apache.cxf.jaxrs.client.WebClient client = org.apache.cxf.jaxrs.client.WebClient.create("https://api.example.com");
        client.path("/encryption-params").header("Authorization", request.getHeader("Authorization"));
        
        Map<String, String> encryptionParams = client.get(Map.class);
        String key = encryptionParams.get("key");
        String data = encryptionParams.get("data");
        String aad = encryptionParams.get("aad");
        
        byte[] keyBytes = Base64.getDecoder().decode(key);
        byte[] dataBytes = Base64.getDecoder().decode(data);
        byte[] aadBytes = aad.getBytes(StandardCharsets.UTF_8);
        
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
        
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        
        // First update with data before AAD - INCORRECT ORDER
        // ruleid: java-cipherupdateaad
        cipher.update(dataBytes);
        cipher.updateAAD(aadBytes);
        
        byte[] cipherText = cipher.doFinal();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_15(HttpServletRequest request) {
    try {
        // Feign Client with incorrect AAD handling
        String key = request.getHeader("X-Encryption-Key");
        String data = request.getParameter("data");
        String aad = request.getParameter("aad");
        
        byte[] keyBytes = Base64.getDecoder().decode(key);
        byte[] dataBytes = Base64.getDecoder().decode(data);
        byte[] aadBytes = aad.getBytes(StandardCharsets.UTF_8);
        
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
        
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        
        // Partial update with data, then AAD, then more data - INCORRECT ORDER
        // ruleid: java-cipherupdateaad
        cipher.update(dataBytes, 0, dataBytes.length / 2);
        cipher.updateAAD(aadBytes);
        cipher.update(dataBytes, dataBytes.length / 2, dataBytes.length - dataBytes.length / 2);
        
        byte[] cipherText = cipher.doFinal();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) {
    try {
        // Standard Java Crypto API with correct AAD update order
        String key = request.getParameter("key");
        String data = request.getParameter("data");
        String aad = request.getParameter("aad");
        
        byte[] keyBytes = Base64.getDecoder().decode(key);
        byte[] dataBytes = Base64.getDecoder().decode(data);
        byte[] aadBytes = aad.getBytes(StandardCharsets.UTF_8);
        
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
        
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        
        // First update AAD before data - CORRECT ORDER
        // ok: java-cipherupdateaad
        cipher.updateAAD(aadBytes);
        cipher.update(dataBytes);
        
        byte[] cipherText = cipher.doFinal();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_2(HttpServletRequest request) {
    try {
        // BouncyCastle library with correct AAD processing
        String key = request.getParameter("key");
        String data = request.getParameter("data");
        String aad = request.getParameter("aad");
        
        byte[] keyBytes = Base64.getDecoder().decode(key);
        byte[] dataBytes = Base64.getDecoder().decode(data);
        byte[] aadBytes = aad.getBytes(StandardCharsets.UTF_8);
        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);
        
        GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());
        AEADParameters params = new AEADParameters(new KeyParameter(keyBytes), 128, nonce);
        
        cipher.init(true, params);
        
        // Process AAD before data - CORRECT ORDER
        // ok: java-cipherupdateaad
        cipher.processAADBytes(aadBytes, 0, aadBytes.length);
        
        byte[] output = new byte[cipher.getOutputSize(dataBytes.length)];
        int offset = cipher.processBytes(dataBytes, 0, dataBytes.length, output, 0);
        
        cipher.doFinal(output, offset);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

@RestController
public void good_case_3(HttpServletRequest request, HttpServletResponse response) {
    try {
        // Spring Web MVC with correct AAD handling
        String key = request.getHeader("X-Encryption-Key");
        String data = request.getParameter("data");
        String aad = request.getParameter("metadata");
        
        byte[] keyBytes = Base64.getDecoder().decode(key);
        byte[] dataBytes = Base64.getDecoder().decode(data);
        byte[] aadBytes = aad.getBytes(StandardCharsets.UTF_8);
        
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
        
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        
        // First update AAD before data - CORRECT ORDER
        // ok: java-cipherupdateaad
        cipher.updateAAD(aadBytes);
        cipher.update(dataBytes);
        
        byte[] cipherText = cipher.doFinal();
        response.getOutputStream().write(cipherText);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_4() {
    try {
        // AWS KMS with correct AAD handling
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpPost httpPost = new HttpPost("https://api.example.com/data");
        HttpEntity entity = httpPost.getEntity();
        String responseString = EntityUtils.toString(entity);
        
        // Parse the response to get encryption parameters
        JsonObject jsonResponse = new Gson().fromJson(responseString, JsonObject.class);
        String keyId = jsonResponse.get("keyId").getAsString();
        String data = jsonResponse.get("data").getAsString();
        String aad = jsonResponse.get("aad").getAsString();
        
        byte[] dataBytes = Base64.getDecoder().decode(data);
        byte[] aadBytes = aad.getBytes(StandardCharsets.UTF_8);
        
        // Custom implementation using AWS KMS for key but local GCM for encryption
        AWSKMS kmsClient = AWSKMSClientBuilder.defaultClient();
        ByteBuffer keyBytes = kmsClient.generateDataKey(keyId, 32).getPlaintext();
        
        SecretKey secretKey = new SecretKeySpec(keyBytes.array(), "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
        
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        
        // First update AAD before data - CORRECT ORDER
        // ok: java-cipherupdateaad
        cipher.updateAAD(aadBytes);
        cipher.update(dataBytes);
        
        byte[] cipherText = cipher.doFinal();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_5() {
    try {
        // Google Cloud KMS with correct AAD handling
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
            .url("https://api.example.com/secure-data")
            .build();
        
        Response response = client.newCall(request).execute();
        String responseBody = response.body().string();
        
        // Parse the response to get encryption parameters
        JsonObject jsonResponse = new Gson().fromJson(responseBody, JsonObject.class);
        String keyName = jsonResponse.get("keyName").getAsString();
        String data = jsonResponse.get("data").getAsString();
        String aad = jsonResponse.get("aad").getAsString();
        
        byte[] dataBytes = Base64.getDecoder().decode(data);
        byte[] aadBytes = aad.getBytes(StandardCharsets.UTF_8);
        
        // Using Google Cloud KMS for key but local GCM for encryption
        KeyManagementServiceClient kmsClient = KeyManagementServiceClient.create();
        CryptoKeyName cryptoKeyName = CryptoKeyName.parse(keyName);
        
        // Get encryption key from Google Cloud KMS
        byte[] keyBytes = kmsClient.decrypt(cryptoKeyName.toString(), ByteBuffer.wrap(dataBytes)).getPlaintext().toByteArray();
        
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
        
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        
        // First update AAD before data - CORRECT ORDER
        // ok: java-cipherupdateaad
        cipher.updateAAD(aadBytes);
        cipher.update(dataBytes);
        
        byte[] cipherText = cipher.doFinal();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_6() {
    try {
        // Retrofit HTTP client with correct AAD handling
        Retrofit retrofit = new Retrofit.Builder()
            .baseUrl("https://api.example.com/")
            .addConverterFactory(GsonConverterFactory.create())
            .build();
        
        // Assume we have an API interface and get encryption parameters
        Map<String, String> requestBody = new HashMap<>();
        requestBody.put("operation", "encrypt");
        
        retrofit2.Call<Map<String, String>> call = retrofit.create(ApiService.class).getEncryptionParams(requestBody);
        retrofit2.Response<Map<String, String>> response = call.execute();
        
        Map<String, String> encryptionParams = response.body();
        String key = encryptionParams.get("key");
        String data = encryptionParams.get("data");
        String aad = encryptionParams.get("aad");
        
        byte[] keyBytes = Base64.getDecoder().decode(key);
        byte[] dataBytes = Base64.getDecoder().decode(data);
        byte[] aadBytes = aad.getBytes(StandardCharsets.UTF_8);
        
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
        
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        
        // First update AAD before data - CORRECT ORDER
        // ok: java-cipherupdateaad
        cipher.updateAAD(aadBytes);
        cipher.update(dataBytes);
        
        byte[] cipherText = cipher.doFinal();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_7(RoutingContext routingContext) {
    try {
        // Vert.x web framework with correct AAD handling
        String key = routingContext.request().getHeader("X-Encryption-Key");
        String data = routingContext.request().getParam("data");
        String aad = routingContext.request().getParam("aad");
        
        byte[] keyBytes = Base64.getDecoder().decode(key);
        byte[] dataBytes = Base64.getDecoder().decode(data);
        byte[] aadBytes = aad.getBytes(StandardCharsets.UTF_8);
        
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
        
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        
        // First update AAD before data - CORRECT ORDER
        // ok: java-cipherupdateaad
        cipher.updateAAD(aadBytes);
        cipher.update(dataBytes);
        
        byte[] cipherText = cipher.doFinal();
        routingContext.response().end(Base64.getEncoder().encodeToString(cipherText));
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_8(HttpServletRequest request) {
    try {
        // Spring RestTemplate with correct AAD handling
        RestTemplate restTemplate = new RestTemplate();
        String url = "https://api.example.com/encryption-params";
        
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", request.getHeader("Authorization"));
        
        ResponseEntity<Map> response = restTemplate.getForEntity(url, Map.class);
        Map<String, String> encryptionParams = response.getBody();
        
        String key = encryptionParams.get("key");
        String data = encryptionParams.get("data");
        String aad = encryptionParams.get("aad");
        
        byte[] keyBytes = Base64.getDecoder().decode(key);
        byte[] dataBytes = Base64.getDecoder().decode(data);
        byte[] aadBytes = aad.getBytes(StandardCharsets.UTF_8);
        
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding"); // Using CCM mode
        
        byte[] nonce = new byte[7]; // CCM typically uses 7-13 bytes
        new SecureRandom().nextBytes(nonce);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, nonce);
        
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        
        // First update AAD before data - CORRECT ORDER
        // ok: java-cipherupdateaad
        cipher.updateAAD(aadBytes);
        cipher.update(dataBytes);
        
        byte[] cipherText = cipher.doFinal();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

@PostMapping("/encrypt")
public void good_case_9(@RequestBody Map<String, String> requestBody) {
    try {
        // Spring Boot REST API with correct AAD handling
        String key = requestBody.get("key");
        String data = requestBody.get("data");
        String aad = requestBody.get("aad");
        
        byte[] keyBytes = Base64.getDecoder().decode(key);
        byte[] dataBytes = Base64.getDecoder().decode(data);
        byte[] aadBytes = aad.getBytes(StandardCharsets.UTF_8);
        
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
        
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        
        // First update AAD before data - CORRECT ORDER
        // ok: java-cipherupdateaad
        cipher.updateAAD(aadBytes);
        cipher.update(dataBytes);
        
        byte[] cipherText = cipher.doFinal();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_10(HttpServletRequest request) {
    try {
        // Netty HTTP framework with correct AAD handling
        String key = request.getHeader("X-Encryption-Key");
        String data = request.getParameter("data");
        String aad = request.getParameter("aad");
        
        byte[] keyBytes = Hex.decodeHex(key.toCharArray());
        byte[] dataBytes = Base64.getDecoder().decode(data);
        byte[] aadBytes = aad.getBytes(StandardCharsets.UTF_8);
        
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
        
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        
        // First update AAD before any data - CORRECT ORDER
        // ok: java-cipherupdateaad
        cipher.updateAAD(aadBytes);
        cipher.update(dataBytes, 0, dataBytes.length / 3);
        cipher.update(dataBytes, dataBytes.length / 3, dataBytes.length / 3);
        cipher.update(dataBytes, 2 * dataBytes.length / 3, dataBytes.length - 2 * dataBytes.length / 3);
        
        byte[] cipherText = cipher.doFinal();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_11(HttpServletRequest request) {
    try {
        // Apache HttpClient with correct AAD handling in decryption
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpPost httpPost = new HttpPost("https://api.example.com/decrypt");
        
        String encryptedData = request.getParameter("encryptedData");
        String iv = request.getParameter("iv");
        String key = request.getParameter("key");
        String aad = request.getParameter("aad");
        
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedData);
        byte[] ivBytes = Base64.getDecoder().decode(iv);
        byte[] keyBytes = Base64.getDecoder().decode(key);
        byte[] aadBytes = aad.getBytes(StandardCharsets.UTF_8);
        
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, ivBytes);
        
        cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);
        
        // First update AAD before encrypted data - CORRECT ORDER for decryption
        // ok: java-cipherupdateaad
        cipher.updateAAD(aadBytes);
        cipher.update(encryptedBytes);
        
        byte[] decryptedData = cipher.doFinal();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_12(HttpServletRequest request) {
    try {
        // Custom HTTP client with correct AAD handling
        String url = "https://api.example.com/secure-data";
        java.net.URL apiUrl = new java.net.URL(url);
        java.net.HttpURLConnection connection = (java.net.HttpURLConnection) apiUrl.openConnection();
        connection.setRequestMethod("GET");
        connection.setRequestProperty("Authorization", request.getHeader("Authorization"));
        
        int responseCode = connection.getResponseCode();
        if (responseCode == 200) {
            java.io.BufferedReader in = new java.io.BufferedReader(
                new java.io.InputStreamReader(connection.getInputStream()));
            String inputLine;
            StringBuilder response = new StringBuilder();
            
            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            in.close();
            
            JsonObject jsonResponse = new Gson().fromJson(response.toString(), JsonObject.class);
            String key = jsonResponse.get("key").getAsString();
            String data = jsonResponse.get("data").getAsString();
            String aad = jsonResponse.get("aad").getAsString();
            
            byte[] keyBytes = Base64.getDecoder().decode(key);
            byte[] dataBytes = Base64.getDecoder().decode(data);
            byte[] aadBytes = aad.getBytes(StandardCharsets.UTF_8);
            
            SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            
            byte[] iv = new byte[12];
            new SecureRandom().nextBytes(iv);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
            
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
            
            // First update AAD before data - CORRECT ORDER
            // ok: java-cipherupdateaad
            cipher.updateAAD(aadBytes);
            cipher.update(dataBytes);
            
            byte[] cipherText = cipher.doFinal();
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_13(HttpServletRequest request) {
    try {
        // Jersey Client with correct AAD handling
        javax.ws.rs.client.Client client = javax.ws.rs.client.ClientBuilder.newClient();
        String url = "https://api.example.com/encryption-params";
        
        javax.ws.rs.core.Response response = client.target(url)
            .request(javax.ws.rs.core.MediaType.APPLICATION_JSON)
            .header("Authorization", request.getHeader("Authorization"))
            .get();
        
        Map<String, String> encryptionParams = response.readEntity(Map.class);
        String key = encryptionParams.get("key");
        String data = encryptionParams.get("data");
        String aad = encryptionParams.get("aad");
        
        byte[] keyBytes = Base64.getDecoder().decode(key);
        byte[] dataBytes = Base64.getDecoder().decode(data);
        byte[] aadBytes = aad.getBytes(StandardCharsets.UTF_8);
        
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
        
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        
        // First update AAD before data - CORRECT ORDER
        // ok: java-cipherupdateaad
        cipher.updateAAD(aadBytes);
        cipher.update(dataBytes);
        
        byte[] cipherText = cipher.doFinal();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_14(HttpServletRequest request) {
    try {
        // Apache CXF with correct AAD handling
        org.apache.cxf.jaxrs.client.WebClient client = org.apache.cxf.jaxrs.client.WebClient.create("https://api.example.com");
        client.path("/encryption-params").header("Authorization", request.getHeader("Authorization"));
        
        Map<String, String> encryptionParams = client.get(Map.class);
        String key = encryptionParams.get("key");
        String data = encryptionParams.get("data");
        String aad = encryptionParams.get("aad");
        
        byte[] keyBytes = Base64.getDecoder().decode(key);
        byte[] dataBytes = Base64.getDecoder().decode(data);
        byte[] aadBytes = aad.getBytes(StandardCharsets.UTF_8);
        
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
        
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        
        // First update AAD before data - CORRECT ORDER
        // ok: java-cipherupdateaad
        cipher.updateAAD(aadBytes);
        cipher.update(dataBytes);
        
        byte[] cipherText = cipher.doFinal();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_15(HttpServletRequest request) {
    try {
        // Feign Client with correct AAD handling
        String key = request.getHeader("X-Encryption-Key");
        String data = request.getParameter("data");
        String aad = request.getParameter("aad");
        
        byte[] keyBytes = Base64.getDecoder().decode(key);
        byte[] dataBytes = Base64.getDecoder().decode(data);
        byte[] aadBytes = aad.getBytes(StandardCharsets.UTF_8);
        
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
        
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        
        // First update AAD before any data - CORRECT ORDER
        // ok: java-cipherupdateaad
        cipher.updateAAD(aadBytes);
        cipher.update(dataBytes, 0, dataBytes.length / 2);
        cipher.update(dataBytes, dataBytes.length / 2, dataBytes.length - dataBytes.length / 2);
        
        byte[] cipherText = cipher.doFinal();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

// Interface needed for Retrofit example
interface ApiService {
    @retrofit2.http.POST("/encryption-params")
    retrofit2.Call<Map<String, String>> getEncryptionParams(@retrofit2.http.Body Map<String, String> request);
}