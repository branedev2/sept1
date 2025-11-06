import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.codec.binary.Hex;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.http.ResponseEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.entity.StringEntity;
import org.apache.http.util.EntityUtils;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.KeyParameter;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.GenerateRandomRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.GenericUrl;
import com.google.crypto.tink.Mac.MacFactory;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.KeyTemplates;
import io.vertx.core.Vertx;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.BodyHandler;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.QueryValue;
import io.quarkus.vertx.web.Route;
import io.quarkus.vertx.web.RouteBase;
import io.netty.handler.codec.http.HttpMethod;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.apache.commons.crypto.mac.JceMac;
import org.apache.commons.crypto.mac.MacOptions;
import org.apache.commons.crypto.utils.Utils;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MAC_REDACTED_TWILIO_ID;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.crypto.hash.format.HexFormat;
import org.apache.shiro.util.ByteSource;
import org.jasypt.util.text.BasicTextEncryptor;
import org.jasypt.util.text.StrongTextEncryptor;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.encryption.pbe.config.SimpleStringPBEConfig;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.security.crypto.keygen.KeyGenerators;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import java.util.Date;
import java.util.Base64;
import java.nio.charset.StandardCharsets;

// Security Issue: Insecure MAC_REDACTED_TWILIO_ID algorithm usage in cryptographic operations

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) throws Exception {
    String data = request.getParameter("data");
    String key = request.getParameter("key");
    
    // ruleid: java-crypto-compliance
    Mac mac = Mac.getInstance("HmacMD5"); // Insecure - MD5 is cryptographically broken
    SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "HmacMD5");
    mac.init(secretKeySpec);
    byte[] hmac = mac.doFinal(data.getBytes());
    
    System.out.println("HMAC_REDACTED_TWILIO_ID: " + Hex.encodeHexString(hmac));
}

public void bad_case_2(HttpServletRequest request) throws Exception {
    String data = request.getParameter("data");
    String key = request.getParameter("key");
    
    // ruleid: java-crypto-compliance
    Mac mac = Mac.getInstance("HmacSHA1"); // Insecure - SHA1 is no longer considered secure
    SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "HmacSHA1");
    mac.init(secretKeySpec);
    byte[] hmac = mac.doFinal(data.getBytes());
    
    System.out.println("HMAC_REDACTED_TWILIO_ID: " + Hex.encodeHexString(hmac));
}

@RestController
public class bad_case_3 {
    @RequestMapping("/sign")
    public String signData(@RequestParam String data, @RequestParam String key) throws Exception {
        // ruleid: java-crypto-compliance
        Mac mac = Mac.getInstance("PBEWithHmacSHA1"); // Insecure - SHA1-based
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "PBEWithHmacSHA1");
        mac.init(secretKeySpec);
        byte[] hmac = mac.doFinal(data.getBytes());
        
        return Base64.getEncoder().encodeToString(hmac);
    }
}

public void bad_case_4(HttpServletRequest request) throws Exception {
    String data = request.getParameter("data");
    String key = request.getParameter("key");
    
    // Using BouncyCastle with weak algorithm
    // ruleid: java-crypto-compliance
    HMac hmac = new HMac(new SHA1Digest()); // Insecure - SHA1 is no longer considered secure
    byte[] keyBytes = key.getBytes();
    hmac.init(new KeyParameter(keyBytes));
    byte[] dataBytes = data.getBytes();
    hmac.update(dataBytes, 0, dataBytes.length);
    byte[] result = new byte[hmac.getMacSize()];
    hmac.doFinal(result, 0);
    
    System.out.println("HMAC_REDACTED_TWILIO_ID: " + Hex.encodeHexString(result));
}

public void bad_case_5(HttpServletRequest request) throws Exception {
    String data = request.getParameter("data");
    String key = request.getParameter("key");
    
    // Apache Commons Crypto with weak algorithm
    // ruleid: java-crypto-compliance
    JceMac mac = new JceMac("HmacMD5"); // Insecure - MD5 is cryptographically broken
    MacOptions options = new MacOptions();
    mac.init(key.getBytes(), options);
    byte[] result = mac.doFinal(data.getBytes());
    
    System.out.println("HMAC_REDACTED_TWILIO_ID: " + Utils.toHex(result));
}

@Controller
public class bad_case_6 {
    @PostMapping("/authenticate")
    public HttpResponse<?> authenticate(@RequestBody String payload, @QueryValue String signature, @QueryValue String key) throws Exception {
        // ruleid: java-crypto-compliance
        Mac mac = Mac.getInstance("HmacMD2"); // Insecure - MD2 is cryptographically broken
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "HmacMD2");
        mac.init(secretKeySpec);
        byte[] calculatedSignature = mac.doFinal(payload.getBytes());
        
        String calculatedSignatureHex = Hex.encodeHexString(calculatedSignature);
        if (calculatedSignatureHex.equals(signature)) {
            return HttpResponse.ok("Authenticated");
        }
        return HttpResponse.unauthorized();
    }
}

@RouteBase(path = "/api")
public class bad_case_7 {
    @Route(path = "/verify", methods = HttpMethod.POST)
    public void verifySignature(RoutingContext context) throws Exception {
        String data = context.request().getParam("data");
        String key = context.request().getParam("key");
        
        // ruleid: java-crypto-compliance
        Mac mac = Mac.getInstance("HmacSHA1"); // Insecure - SHA1 is no longer considered secure
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "HmacSHA1");
        mac.init(secretKeySpec);
        byte[] hmac = mac.doFinal(data.getBytes());
        
        context.response()
            .putHeader("content-type", "text/plain")
            .end(Hex.encodeHexString(hmac));
    }
}

public void bad_case_8(HttpServletRequest request) throws Exception {
    String subject = request.getParameter("subject");
    String key = request.getParameter("key");
    
    // Nimbus JOSE+JWT with weak algorithm
    // ruleid: java-crypto-compliance
    JWSSigner signer = new MAC_REDACTED_TWILIO_ID(key.getBytes());
    JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS1) // Insecure - HS1 is based on SHA1
            .build();
    
    JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
            .subject(subject)
            .issuer("https://example.com")
            .expirationTime(new Date(new Date().getTime() + 60 * 1000))
            .build();
    
    SignedJWT signedJWT = new SignedJWT(header, claimsSet);
    signedJWT.sign(signer);
    
    String jwt = signedJWT.serialize();
    System.out.println("JWT: " + jwt);
}

public void bad_case_9(HttpServletRequest request) throws Exception {
    String data = request.getParameter("data");
    String key = request.getParameter("key");
    
    // Apache Shiro with weak algorithm
    // ruleid: java-crypto-compliance
    SimpleHash hash = new SimpleHash("MD5", data, ByteSource.Util.bytes(key), 1); // Insecure - MD5 is cryptographically broken
    String hexHash = new HexFormat().format(hash.getBytes());
    
    System.out.println("Hash: " + hexHash);
}

public void bad_case_10(HttpServletRequest request) throws Exception {
    String data = request.getParameter("data");
    String key = request.getParameter("key");
    
    // JJWT with weak algorithm
    // ruleid: java-crypto-compliance
    String jws = Jwts.builder()
        .setSubject(data)
        .signWith(SignatureAlgorithm.HS1, key.getBytes()) // Insecure - HS1 is based on SHA1
        .compact();
    
    System.out.println("JWS: " + jws);
}

public void bad_case_11(HttpServletRequest request) throws Exception {
    String data = request.getParameter("data");
    String key = request.getParameter("key");
    
    // Jasypt with weak algorithm
    StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
    SimpleStringPBEConfig config = new SimpleStringPBEConfig();
    config.setPassword(key);
    // ruleid: java-crypto-compliance
    config.setAlgorithm("PBEWithHmacSHA1"); // Insecure - SHA1-based
    encryptor.setConfig(config);
    
    String encrypted = encryptor.encrypt(data);
    System.out.println("Encrypted: " + encrypted);
}

public void bad_case_12(HttpServletRequest request) throws Exception {
    String data = request.getParameter("data");
    String key = request.getParameter("key");
    
    // Spring Security with weak algorithm
    String salt = KeyGenerators.string().generateKey();
    // ruleid: java-crypto-compliance
    TextEncryptor encryptor = Encryptors.delux(key, salt); // Uses PBKDF2WithHmacSHA1 internally
    
    String encrypted = encryptor.encrypt(data);
    System.out.println("Encrypted: " + encrypted);
}

public void bad_case_13(HttpServletRequest request) throws Exception {
    String data = request.getParameter("data");
    
    // Google Tink with weak algorithm
    try {
        MacConfig.register();
        // ruleid: java-crypto-compliance
        KeysetHandle keysetHandle = KeysetHandle.generateNew(
            KeyTemplates.get("HMAC_REDACTED_TWILIO_ID_SHA1_128BITTAG")); // Insecure - SHA1-based
        
        com.google.crypto.tink.Mac mac = MacFactory.getPrimitive(keysetHandle);
        byte[] tag = mac.computeMac(data.getBytes());
        
        System.out.println("Tag: " + Base64.getEncoder().encodeToString(tag));
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_14(HttpServletRequest request) throws Exception {
    String data = request.getParameter("data");
    String key = request.getParameter("key");
    
    // OkHttp client with weak HMAC_REDACTED_TWILIO_ID
    OkHttpClient client = new OkHttpClient();
    // ruleid: java-crypto-compliance
    Mac mac = Mac.getInstance("HmacSHA1"); // Insecure - SHA1 is no longer considered secure
    SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "HmacSHA1");
    mac.init(secretKeySpec);
    byte[] hmac = mac.doFinal(data.getBytes());
    
    String signature = Base64.getEncoder().encodeToString(hmac);
    
    Request httpRequest = new Request.Builder()
        .url("https://api.example.com/data")
        .header("Authorization", "HMAC_REDACTED_TWILIO_ID " + signature)
        .build();
    
    try (Response response = client.newCall(httpRequest).execute()) {
        System.out.println(response.body().string());
    }
}

public void bad_case_15(HttpServletRequest request) throws Exception {
    String data = request.getParameter("data");
    String key = request.getParameter("key");
    
    // Google HTTP Client with weak HMAC_REDACTED_TWILIO_ID
    HttpRequestFactory requestFactory = new NetHttpTransport().createRequestFactory();
    // ruleid: java-crypto-compliance
    Mac mac = Mac.getInstance("HmacMD5"); // Insecure - MD5 is cryptographically broken
    SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "HmacMD5");
    mac.init(secretKeySpec);
    byte[] hmac = mac.doFinal(data.getBytes());
    
    String signature = Base64.getEncoder().encodeToString(hmac);
    
    HttpRequest httpRequest = requestFactory.buildGetRequest(new GenericUrl("https://api.example.com/data"))
        .setRequestMethod("POST")
        .getHeaders().set("Authorization", "HMAC_REDACTED_TWILIO_ID " + signature);
    
    System.out.println(httpRequest.execute().parseAsString());
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) throws Exception {
    String data = request.getParameter("data");
    String key = request.getParameter("key");
    
    // ok: java-crypto-compliance
    Mac mac = Mac.getInstance("HmacSHA256"); // Secure - SHA256 is considered secure
    SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "HmacSHA256");
    mac.init(secretKeySpec);
    byte[] hmac = mac.doFinal(data.getBytes());
    
    System.out.println("HMAC_REDACTED_TWILIO_ID: " + Hex.encodeHexString(hmac));
}

public void good_case_2(HttpServletRequest request) throws Exception {
    String data = request.getParameter("data");
    String key = request.getParameter("key");
    
    // ok: java-crypto-compliance
    Mac mac = Mac.getInstance("HmacSHA512"); // Secure - SHA512 is considered secure
    SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "HmacSHA512");
    mac.init(secretKeySpec);
    byte[] hmac = mac.doFinal(data.getBytes());
    
    System.out.println("HMAC_REDACTED_TWILIO_ID: " + Hex.encodeHexString(hmac));
}

@RestController
public class good_case_3 {
    @RequestMapping("/sign")
    public String signData(@RequestParam String data, @RequestParam String key) throws Exception {
        // ok: java-crypto-compliance
        Mac mac = Mac.getInstance("HmacSHA384"); // Secure - SHA384 is considered secure
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "HmacSHA384");
        mac.init(secretKeySpec);
        byte[] hmac = mac.doFinal(data.getBytes());
        
        return Base64.getEncoder().encodeToString(hmac);
    }
}

public void good_case_4(HttpServletRequest request) throws Exception {
    String data = request.getParameter("data");
    String key = request.getParameter("key");
    
    // Using BouncyCastle with secure algorithm
    // ok: java-crypto-compliance
    HMac hmac = new HMac(new SHA256Digest()); // Secure - SHA256 is considered secure
    byte[] keyBytes = key.getBytes();
    hmac.init(new KeyParameter(keyBytes));
    byte[] dataBytes = data.getBytes();
    hmac.update(dataBytes, 0, dataBytes.length);
    byte[] result = new byte[hmac.getMacSize()];
    hmac.doFinal(result, 0);
    
    System.out.println("HMAC_REDACTED_TWILIO_ID: " + Hex.encodeHexString(result));
}

public void good_case_5(HttpServletRequest request) throws Exception {
    String data = request.getParameter("data");
    String key = request.getParameter("key");
    
    // Apache Commons Crypto with secure algorithm
    // ok: java-crypto-compliance
    JceMac mac = new JceMac("HmacSHA256"); // Secure - SHA256 is considered secure
    MacOptions options = new MacOptions();
    mac.init(key.getBytes(), options);
    byte[] result = mac.doFinal(data.getBytes());
    
    System.out.println("HMAC_REDACTED_TWILIO_ID: " + Utils.toHex(result));
}

@Controller
public class good_case_6 {
    @PostMapping("/authenticate")
    public HttpResponse<?> authenticate(@RequestBody String payload, @QueryValue String signature, @QueryValue String key) throws Exception {
        // ok: java-crypto-compliance
        Mac mac = Mac.getInstance("HmacSHA3-256"); // Secure - SHA3-256 is considered secure
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "HmacSHA3-256");
        mac.init(secretKeySpec);
        byte[] calculatedSignature = mac.doFinal(payload.getBytes());
        
        String calculatedSignatureHex = Hex.encodeHexString(calculatedSignature);
        if (calculatedSignatureHex.equals(signature)) {
            return HttpResponse.ok("Authenticated");
        }
        return HttpResponse.unauthorized();
    }
}

@RouteBase(path = "/api")
public class good_case_7 {
    @Route(path = "/verify", methods = HttpMethod.POST)
    public void verifySignature(RoutingContext context) throws Exception {
        String data = context.request().getParam("data");
        String key = context.request().getParam("key");
        
        // ok: java-crypto-compliance
        Mac mac = Mac.getInstance("HmacSHA3-512"); // Secure - SHA3-512 is considered secure
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "HmacSHA3-512");
        mac.init(secretKeySpec);
        byte[] hmac = mac.doFinal(data.getBytes());
        
        context.response()
            .putHeader("content-type", "text/plain")
            .end(Hex.encodeHexString(hmac));
    }
}

public void good_case_8(HttpServletRequest request) throws Exception {
    String subject = request.getParameter("subject");
    String key = request.getParameter("key");
    
    // Nimbus JOSE+JWT with secure algorithm
    // ok: java-crypto-compliance
    JWSSigner signer = new MAC_REDACTED_TWILIO_ID(key.getBytes());
    JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256) // Secure - HS256 is based on SHA256
            .build();
    
    JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
            .subject(subject)
            .issuer("https://example.com")
            .expirationTime(new Date(new Date().getTime() + 60 * 1000))
            .build();
    
    SignedJWT signedJWT = new SignedJWT(header, claimsSet);
    signedJWT.sign(signer);
    
    String jwt = signedJWT.serialize();
    System.out.println("JWT: " + jwt);
}

public void good_case_9(HttpServletRequest request) throws Exception {
    String data = request.getParameter("data");
    String key = request.getParameter("key");
    
    // Apache Shiro with secure algorithm
    // ok: java-crypto-compliance
    SimpleHash hash = new SimpleHash("SHA-256", data, ByteSource.Util.bytes(key), 1); // Secure - SHA256 is considered secure
    String hexHash = new HexFormat().format(hash.getBytes());
    
    System.out.println("Hash: " + hexHash);
}

public void good_case_10(HttpServletRequest request) throws Exception {
    String data = request.getParameter("data");
    
    // JJWT with secure algorithm
    // ok: java-crypto-compliance
    byte[] key = Keys.secretKeyFor(SignatureAlgorithm.HS512).getEncoded(); // Secure - HS512 is based on SHA512
    String jws = Jwts.builder()
        .setSubject(data)
        .signWith(Keys.hmacShaKeyFor(key), SignatureAlgorithm.HS512)
        .compact();
    
    System.out.println("JWS: " + jws);
}

public void good_case_11(HttpServletRequest request) throws Exception {
    String data = request.getParameter("data");
    String key = request.getParameter("key");
    
    // Jasypt with secure algorithm
    StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
    SimpleStringPBEConfig config = new SimpleStringPBEConfig();
    config.setPassword(key);
    // ok: java-crypto-compliance
    config.setAlgorithm("PBEWITHHMAC_REDACTED_TWILIO_ID_256"); // Secure - SHA256-based
    encryptor.setConfig(config);
    
    String encrypted = encryptor.encrypt(data);
    System.out.println("Encrypted: " + encrypted);
}

public void good_case_12(HttpServletRequest request) throws Exception {
    String data = request.getParameter("data");
    String key = request.getParameter("key");
    
    // Spring Security with secure algorithm
    String salt = KeyGenerators.string().generateKey();
    // ok: java-crypto-compliance
    TextEncryptor encryptor = Encryptors.stronger(key, salt); // Uses PBKDF2WithHmacSHA256 internally
    
    String encrypted = encryptor.encrypt(data);
    System.out.println("Encrypted: " + encrypted);
}

public void good_case_13(HttpServletRequest request) throws Exception {
    String data = request.getParameter("data");
    
    // Google Tink with secure algorithm
    try {
        MacConfig.register();
        // ok: java-crypto-compliance
        KeysetHandle keysetHandle = KeysetHandle.generateNew(
            KeyTemplates.get("HMAC_REDACTED_TWILIO_ID_SHA256_256BITTAG")); // Secure - SHA256-based
        
        com.google.crypto.tink.Mac mac = MacFactory.getPrimitive(keysetHandle);
        byte[] tag = mac.computeMac(data.getBytes());
        
        System.out.println("Tag: " + Base64.getEncoder().encodeToString(tag));
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_14(HttpServletRequest request) throws Exception {
    String data = request.getParameter("data");
    String key = request.getParameter("key");
    
    // OkHttp client with secure HMAC_REDACTED_TWILIO_ID
    OkHttpClient client = new OkHttpClient();
    // ok: java-crypto-compliance
    Mac mac = Mac.getInstance("HmacSHA256"); // Secure - SHA256 is considered secure
    SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "HmacSHA256");
    mac.init(secretKeySpec);
    byte[] hmac = mac.doFinal(data.getBytes());
    
    String signature = Base64.getEncoder().encodeToString(hmac);
    
    Request httpRequest = new Request.Builder()
        .url("https://api.example.com/data")
        .header("Authorization", "HMAC_REDACTED_TWILIO_ID " + signature)
        .build();
    
    try (Response response = client.newCall(httpRequest).execute()) {
        System.out.println(response.body().string());
    }
}

public void good_case_15(HttpServletRequest request) throws Exception {
    String data = request.getParameter("data");
    String key = request.getParameter("key");
    
    // Google HTTP Client with secure HMAC_REDACTED_TWILIO_ID
    HttpRequestFactory requestFactory = new NetHttpTransport().createRequestFactory();
    // ok: java-crypto-compliance
    Mac mac = Mac.getInstance("HmacSHA512"); // Secure - SHA512 is considered secure
    SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "HmacSHA512");
    mac.init(secretKeySpec);
    byte[] hmac = mac.doFinal(data.getBytes());
    
    String signature = Base64.getEncoder().encodeToString(hmac);
    
    HttpRequest httpRequest = requestFactory.buildGetRequest(new GenericUrl("https://api.example.com/data"))
        .setRequestMethod("POST")
        .getHeaders().set("Authorization", "HMAC_REDACTED_TWILIO_ID " + signature);
    
    System.out.println(httpRequest.execute().parseAsString());
}