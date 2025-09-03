import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import io.fusionauth.jwt.Signer;
import io.fusionauth.jwt.hmac.HMAC_REDACTED_TWILIO_ID;
import io.fusionauth.jwt.domain.JWT as FusionJWT;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.keys.HmacKey;
import io.vertx.ext.auth.JWTOptions;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;
import io.vertx.ext.jwt.JWTOptions as VertxJWTOptions;
import io.vertx.core.json.JsonObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MAC_REDACTED_TWILIO_ID;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import com.okta.jwt.JwtBuilder;
import com.okta.jwt.Jwt;
import io.jsonwebtoken.io.Encoders;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.UUID;
import java.util.Properties;
import java.io.FileInputStream;
import java.io.IOException;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;

// Security Issue: Hardcoded credentials in JWT implementations

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1() {
    // Using Auth0 JWT library with hardcoded secret
    // ruleid: java-jwt-exposed-credentials
    String secret = "myStaticSecretKey123456789012345678901234";
    Algorithm algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID(secret);
    String token = JWT.create()
        .withIssuer("auth0")
        .withClaim("username", "admin")
        .sign(algorithm);
    System.out.println(token);
}

public void bad_case_2() {
    // Using JJWT library with hardcoded key
    // ruleid: java-jwt-exposed-credentials
    String secretKey = "superSecretKey123456789012345678901234";
    Key key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
    String jws = Jwts.builder()
        .setSubject("user")
        .signWith(key)
        .compact();
    System.out.println(jws);
}

public void bad_case_3() {
    // Using FusionAuth JWT library with hardcoded signer
    try {
        // ruleid: java-jwt-exposed-credentials
        Signer signer = HMAC_REDACTED_TWILIO_ID.newSHA256Signer("thisIsAHardcodedSecret12345678901234");
        FusionJWT jwt = new FusionJWT().setSubject("subject");
        String encodedJWT = io.fusionauth.jwt.domain.JWT.getEncoder().encode(jwt, signer);
        System.out.println(encodedJWT);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_4() {
    // Using Jose4j library with hardcoded key
    try {
        JwtClaims claims = new JwtClaims();
        claims.setSubject("user123");
        claims.setIssuedAtToNow();
        
        // ruleid: java-jwt-exposed-credentials
        String secretKeyString = "hardcodedSecret123456789012345678901234";
        HmacKey key = new HmacKey(secretKeyString.getBytes(StandardCharsets.UTF_8));
        
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(key);
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_REDACTED_TWILIO_ID_SHA256);
        
        String jwt = jws.getCompactSerialization();
        System.out.println(jwt);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_5() {
    // Using Nimbus JOSE+JWT library with hardcoded key
    try {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
            .subject("user")
            .issuer("https://example.com")
            .expirationTime(new Date(new Date().getTime() + 60 * 1000))
            .build();
        
        // ruleid: java-jwt-exposed-credentials
        String secretKey = "hardcodedSecretKey123456789012345678901234";
        JWSSigner signer = new MAC_REDACTED_TWILIO_ID(secretKey.getBytes(StandardCharsets.UTF_8));
        
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
        signedJWT.sign(signer);
        
        String jwt = signedJWT.serialize();
        System.out.println(jwt);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_6() {
    // Using Spring Security OAuth2 JWT with hardcoded RSA key
    try {
        JwtClaimsSet claims = JwtClaimsSet.builder()
            .issuer("self")
            .subject("user")
            .build();
        
        // ruleid: java-jwt-exposed-credentials
        RSAKey rsaKey = new RSAKey.Builder(generateRSAKey())
            .privateKey((RSAPrivateKey) generateRSAKey().getPrivate())
            .keyID("static-key-id")
            .build();
        
        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(rsaKey));
        JwtEncoder encoder = new NimbusJwtEncoder(jwkSource);
        
        String jwt = encoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
        System.out.println(jwt);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_7() {
    // Using Okta JWT library with hardcoded key
    try {
        // ruleid: java-jwt-exposed-credentials
        String apiKey = "hardcodedApiKey12345678901234567890";
        JwtBuilder jwtBuilder = new JwtBuilder()
            .setIssuer("https://example.com")
            .setSubject("user")
            .setIssuedAt(new Date())
            .setExpiration(new Date(System.currentTimeMillis() + 3600000))
            .signWith(apiKey.getBytes(StandardCharsets.UTF_8));
        
        Jwt jwt = jwtBuilder.build();
        System.out.println(jwt.getTokenValue());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_8() {
    // Using Vert.x JWT with hardcoded key
    // ruleid: java-jwt-exposed-credentials
    String keyValue = "hardcodedKeyForVertx123456789012345678901234";
    JsonObject config = new JsonObject()
        .put("keyStore", new JsonObject()
            .put("type", "jceks")
            .put("password", keyValue)
            .put("path", "keystore.jceks"));
    
    JWTAuthOptions options = new JWTAuthOptions()
        .setKeyStore(config);
    
    // This is just for demonstration - actual implementation would require a Vertx instance
    System.out.println("JWT Auth configured with hardcoded password: " + options.getKeyStore().getString("password"));
}

public void bad_case_9() {
    // Using custom JWT implementation with hardcoded key
    try {
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "user123");
        claims.put("iat", System.currentTimeMillis() / 1000);
        
        // ruleid: java-jwt-exposed-credentials
        String secretKey = "myHardcodedSecretForCustomJWT12345678901234";
        
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString(
            "{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(
            claims.toString().getBytes(StandardCharsets.UTF_8));
        
        String content = header + "." + payload;
        // Signature calculation would be implemented here
        
        System.out.println("Custom JWT with hardcoded key: " + content);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_10() {
    // Using JJWT with hardcoded Base64-encoded key
    // ruleid: java-jwt-exposed-credentials
    String base64EncodedKey = "c2VjcmV0S2V5MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNA==";
    byte[] decodedKey = Base64.getDecoder().decode(base64EncodedKey);
    Key key = new SecretKeySpec(decodedKey, 0, decodedKey.length, "HmacSHA256");
    
    String jws = Jwts.builder()
        .setSubject("user")
        .signWith(key)
        .compact();
    System.out.println(jws);
}

public void bad_case_11() {
    // Using Auth0 JWT with hardcoded RSA private key content
    try {
        // ruleid: java-jwt-exposed-credentials
        String privateKeyContent = "-----BEGIN PRIVATE KEY-----\n" +
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\n" +
            "MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu\n" +
            "NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ\n" +
            "-----END PRIVATE KEY-----";
        
        RSAPrivateKey privateKey = /* code to parse the private key */;
        Algorithm algorithm = Algorithm.RSA256(null, privateKey);
        
        String token = JWT.create()
            .withIssuer("auth0")
            .sign(algorithm);
        System.out.println(token);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_12() {
    // Using Spring Security with hardcoded symmetric key in configuration
    @Configuration
    class JwtConfig {
        // ruleid: java-jwt-exposed-credentials
        private final String jwtKey = "thisIsAVerySecretKeyForJwtSigningPleaseChangeIt";
        
        @Bean
        public JwtDecoder jwtDecoder() {
            SecretKeySpec secretKey = new SecretKeySpec(
                jwtKey.getBytes(StandardCharsets.UTF_8),
                "HmacSHA256"
            );
            return NimbusJwtDecoder.withSecretKey(secretKey).build();
        }
    }
    
    System.out.println("JWT configuration with hardcoded key created");
}

public void bad_case_13() {
    // Using Nimbus JOSE+JWT with hardcoded credentials in JWK
    try {
        // ruleid: java-jwt-exposed-credentials
        String jwkJson = "{\"kty\":\"oct\",\"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\"}";
        JWK jwk = JWK.parse(jwkJson);
        
        JWSSigner signer = new MAC_REDACTED_TWILIO_ID(jwk.toOctetSequenceKey());
        
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
            .subject("user")
            .build();
        
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
        signedJWT.sign(signer);
        
        String jwt = signedJWT.serialize();
        System.out.println(jwt);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_14() {
    // Using JJWT with hardcoded key in a constant field
    class JwtUtil {
        // ruleid: java-jwt-exposed-credentials
        private static final String SECRET_KEY = "thisIsAC_REDACTED_TWILIO_ID";
        
        public String generateToken(String username) {
            return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 3600000))
                .signWith(Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8)))
                .compact();
        }
    }
    
    JwtUtil jwtUtil = new JwtUtil();
    String token = jwtUtil.generateToken("user");
    System.out.println(token);
}

public void bad_case_15() {
    // Using Auth0 JWT with hardcoded key in a method
    public String createJwtToken(String userId) {
        // ruleid: java-jwt-exposed-credentials
        String secretKey = "myVerySecretKeyForJwtGeneration12345678901234";
        Algorithm algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID(secretKey);
        
        return JWT.create()
            .withSubject(userId)
            .withExpiresAt(new Date(System.currentTimeMillis() + 3600000))
            .sign(algorithm);
    }
    
    String token = createJwtToken("user123");
    System.out.println(token);
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1() {
    // Using Auth0 JWT library with secret from environment variable
    try {
        // ok: java-jwt-exposed-credentials
        String secret = System.getenv("JWT_SECRET");
        if (secret == null || secret.isEmpty()) {
            throw new IllegalStateException("JWT secret not configured");
        }
        
        Algorithm algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID(secret);
        String token = JWT.create()
            .withIssuer("auth0")
            .withClaim("username", "admin")
            .sign(algorithm);
        System.out.println(token);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_2() {
    // Using JJWT library with key from properties file
    try {
        Properties props = new Properties();
        props.load(new FileInputStream("config.properties"));
        
        // ok: java-jwt-exposed-credentials
        String secretKey = props.getProperty("jwt.secret");
        if (secretKey == null || secretKey.isEmpty()) {
            throw new IllegalStateException("JWT secret not configured in properties");
        }
        
        Key key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
        String jws = Jwts.builder()
            .setSubject("user")
            .signWith(key)
            .compact();
        System.out.println(jws);
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_3() {
    // Using FusionAuth JWT library with secret from configuration service
    try {
        ConfigService configService = new ConfigService(); // Hypothetical service
        
        // ok: java-jwt-exposed-credentials
        String secret = configService.getSecret("jwt.signing.key");
        if (secret == null || secret.isEmpty()) {
            throw new IllegalStateException("JWT signing key not available");
        }
        
        Signer signer = HMAC_REDACTED_TWILIO_ID.newSHA256Signer(secret);
        FusionJWT jwt = new FusionJWT().setSubject("subject");
        String encodedJWT = io.fusionauth.jwt.domain.JWT.getEncoder().encode(jwt, signer);
        System.out.println(encodedJWT);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_4() {
    // Using Jose4j library with key from secure vault
    try {
        SecureVault vault = new SecureVault(); // Hypothetical secure vault
        
        // ok: java-jwt-exposed-credentials
        byte[] secretKeyBytes = vault.getSecretBytes("jwt.hmac.key");
        if (secretKeyBytes == null || secretKeyBytes.length == 0) {
            throw new IllegalStateException("JWT HMAC_REDACTED_TWILIO_ID key not available in vault");
        }
        
        HmacKey key = new HmacKey(secretKeyBytes);
        
        JwtClaims claims = new JwtClaims();
        claims.setSubject("user123");
        claims.setIssuedAtToNow();
        
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(key);
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_REDACTED_TWILIO_ID_SHA256);
        
        String jwt = jws.getCompactSerialization();
        System.out.println(jwt);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_5() {
    // Using Nimbus JOSE+JWT library with key from Spring environment
    class JwtService {
        private final String secretKey;
        
        public JwtService(@Value("${jwt.secret}") String secretKey) {
            // ok: java-jwt-exposed-credentials
            this.secretKey = secretKey;
        }
        
        public String createJwt() throws Exception {
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("user")
                .issuer("https://example.com")
                .expirationTime(new Date(new Date().getTime() + 60 * 1000))
                .build();
            
            JWSSigner signer = new MAC_REDACTED_TWILIO_ID(secretKey.getBytes(StandardCharsets.UTF_8));
            
            SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
            signedJWT.sign(signer);
            
            return signedJWT.serialize();
        }
    }
    
    // Simulating Spring environment
    JwtService service = new JwtService(System.getenv("JWT_SECRET"));
    try {
        String jwt = service.createJwt();
        System.out.println(jwt);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_6() {
    // Using Spring Security OAuth2 JWT with key from KeyStore
    class JwtConfig {
        @Bean
        public JwtEncoder jwtEncoder() throws Exception {
            // ok: java-jwt-exposed-credentials
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(new FileInputStream("keystore.p12"), System.getenv("KEYSTORE_PASSWORD").toCharArray());
            
            RSAKey rsaKey = RSAKey.load(keyStore, "jwt-signing-key", System.getenv("KEY_PASSWORD").toCharArray());
            
            JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(rsaKey));
            return new NimbusJwtEncoder(jwkSource);
        }
    }
    
    System.out.println("JWT configuration with KeyStore created");
}

public void good_case_7() {
    // Using Okta JWT library with key from secure configuration
    class SecureConfigProvider {
        public byte[] getJwtSigningKey() {
            // ok: java-jwt-exposed-credentials
            String encodedKey = System.getenv("OKTA_JWT_KEY");
            if (encodedKey == null || encodedKey.isEmpty()) {
                throw new IllegalStateException("Okta JWT signing key not configured");
            }
            return Base64.getDecoder().decode(encodedKey);
        }
    }
    
    try {
        SecureConfigProvider config = new SecureConfigProvider();
        JwtBuilder jwtBuilder = new JwtBuilder()
            .setIssuer("https://example.com")
            .setSubject("user")
            .setIssuedAt(new Date())
            .setExpiration(new Date(System.currentTimeMillis() + 3600000))
            .signWith(config.getJwtSigningKey());
        
        Jwt jwt = jwtBuilder.build();
        System.out.println(jwt.getTokenValue());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_8() {
    // Using Vert.x JWT with key from configuration file
    class VertxJwtProvider {
        public JWTAuthOptions createJwtAuthOptions() {
            // ok: java-jwt-exposed-credentials
            String keystorePassword = System.getenv("VERTX_KEYSTORE_PASSWORD");
            if (keystorePassword == null || keystorePassword.isEmpty()) {
                throw new IllegalStateException("Keystore password not configured");
            }
            
            JsonObject config = new JsonObject()
                .put("keyStore", new JsonObject()
                    .put("type", "jceks")
                    .put("password", keystorePassword)
                    .put("path", "keystore.jceks"));
            
            return new JWTAuthOptions().setKeyStore(config);
        }
    }
    
    VertxJwtProvider provider = new VertxJwtProvider();
    JWTAuthOptions options = provider.createJwtAuthOptions();
    System.out.println("JWT Auth configured with secure password");
}

public void good_case_9() {
    // Using custom JWT implementation with key from secure storage
    class SecureKeyManager {
        public byte[] getSigningKey(String keyId) {
            // ok: java-jwt-exposed-credentials
            // Retrieve from a secure key management service
            KeyManagementService keyService = new KeyManagementService(); // Hypothetical service
            return keyService.retrieveKey(keyId);
        }
    }
    
    try {
        SecureKeyManager keyManager = new SecureKeyManager();
        byte[] signingKey = keyManager.getSigningKey("jwt-signing-key");
        
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "user123");
        claims.put("iat", System.currentTimeMillis() / 1000);
        
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString(
            "{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(
            claims.toString().getBytes(StandardCharsets.UTF_8));
        
        String content = header + "." + payload;
        // Signature calculation would be implemented here using the secure key
        
        System.out.println("Custom JWT with secure key: " + content);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_10() {
    // Using JJWT with dynamically generated key
    try {
        // ok: java-jwt-exposed-credentials
        Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256); // Generates a secure random key
        
        String jws = Jwts.builder()
            .setSubject("user")
            .signWith(key)
            .compact();
        System.out.println(jws);
        
        // Store the key securely for verification
        String encodedKey = Encoders.BASE64.encode(key.getEncoded());
        // Save encodedKey to secure storage
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_11() {
    // Using Auth0 JWT with key from database
    class KeyRepository {
        public String getJwtSecret(String keyId) {
            // ok: java-jwt-exposed-credentials
            // Simulating database access
            DatabaseService db = new DatabaseService(); // Hypothetical service
            return db.queryForString("SELECT secret_key FROM jwt_keys WHERE key_id = ?", keyId);
        }
    }
    
    try {
        KeyRepository keyRepo = new KeyRepository();
        String secret = keyRepo.getJwtSecret("auth0-jwt-key");
        
        Algorithm algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID(secret);
        String token = JWT.create()
            .withIssuer("auth0")
            .sign(algorithm);
        System.out.println(token);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_12() {
    // Using Spring Security with key from environment in configuration
    @Configuration
    class JwtConfig {
        @Bean
        public JwtDecoder jwtDecoder() {
            // ok: java-jwt-exposed-credentials
            String jwtKey = System.getenv("SPRING_JWT_KEY");
            if (jwtKey == null || jwtKey.isEmpty()) {
                throw new IllegalStateException("JWT key not configured in environment");
            }
            
            SecretKeySpec secretKey = new SecretKeySpec(
                jwtKey.getBytes(StandardCharsets.UTF_8),
                "HmacSHA256"
            );
            return NimbusJwtDecoder.withSecretKey(secretKey).build();
        }
    }
    
    System.out.println("JWT configuration with environment key created");
}

public void good_case_13() {
    // Using Nimbus JOSE+JWT with key from AWS Secrets Manager
    class AwsSecretsProvider {
        public String getJwtSecret() {
            // ok: java-jwt-exposed-credentials
            // Simulating AWS Secrets Manager access
            AwsSecretsManager secretsManager = new AwsSecretsManager(); // Hypothetical service
            return secretsManager.getSecretValue("jwt/signing-key").getSecretString();
        }
    }
    
    try {
        AwsSecretsProvider secretsProvider = new AwsSecretsProvider();
        String secretKey = secretsProvider.getJwtSecret();
        
        JWSSigner signer = new MAC_REDACTED_TWILIO_ID(secretKey.getBytes(StandardCharsets.UTF_8));
        
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
            .subject("user")
            .build();
        
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
        signedJWT.sign(signer);
        
        String jwt = signedJWT.serialize();
        System.out.println(jwt);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_14() {
    // Using JJWT with key rotation strategy
    class KeyRotationService {
        public Key getCurrentSigningKey() {
            // ok: java-jwt-exposed-credentials
            // Get current key from secure storage based on rotation schedule
            String currentKeyId = "key-" + (System.currentTimeMillis() / (24 * 60 * 60 * 1000));
            SecureStorage storage = new SecureStorage(); // Hypothetical service
            byte[] keyBytes = storage.getBytes(currentKeyId);
            return new SecretKeySpec(keyBytes, "HmacSHA256");
        }
    }
    
    try {
        KeyRotationService keyService = new KeyRotationService();
        Key signingKey = keyService.getCurrentSigningKey();
        
        String jws = Jwts.builder()
            .setSubject("user")
            .setHeaderParam("kid", "current")
            .signWith(signingKey)
            .compact();
        System.out.println(jws);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_15() {
    // Using Auth0 JWT with asymmetric keys from KeyPair generator
    try {
        // ok: java-jwt-exposed-credentials
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        
        // Store keys securely for future use
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, "password".toCharArray());
        keyStore.setKeyEntry("jwt-key-pair", privateKey, "keyPassword".toCharArray(), 
                            new java.security.cert.Certificate[]{generateSelfSignedCertificate(keyPair)});
        
        Algorithm algorithm = Algorithm.RSA256(publicKey, privateKey);
        String token = JWT.create()
            .withIssuer("auth0")
            .sign(algorithm);
        System.out.println(token);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

// Helper classes for examples (would be implemented in a real application)
class ConfigService {
    public String getSecret(String key) {
        return System.getenv(key.toUpperCase().replace('.', '_'));
    }
}

class SecureVault {
    public byte[] getSecretBytes(String key) {
        String envKey = key.toUpperCase().replace('.', '_');
        String value = System.getenv(envKey);
        return value != null ? value.getBytes(StandardCharsets.UTF_8) : null;
    }
}

class DatabaseService {
    public String queryForString(String sql, String param) {
        // Simulated database access
        return System.getenv("DB_" + param.toUpperCase());
    }
}

class KeyManagementService {
    public byte[] retrieveKey(String keyId) {
        // Simulated key management service
        String envKey = "KEY_" + keyId.toUpperCase().replace('-', '_');
        String value = System.getenv(envKey);
        return value != null ? value.getBytes(StandardCharsets.UTF_8) : null;
    }
}

class AwsSecretsManager {
    public SecretValue getSecretValue(String secretId) {
        // Simulated AWS Secrets Manager
        String envKey = secretId.toUpperCase().replace('/', '_').replace('-', '_');
        return new SecretValue(System.getenv(envKey));
    }
    
    class SecretValue {
        private final String value;
        
        public SecretValue(String value) {
            this.value = value;
        }
        
        public String getSecretString() {
            return value;
        }
    }
}

class SecureStorage {
    public byte[] getBytes(String key) {
        // Simulated secure storage
        String envKey = "STORAGE_" + key.toUpperCase().replace('-', '_');
        String value = System.getenv(envKey);
        return value != null ? value.getBytes(StandardCharsets.UTF_8) : null;
    }
}

// Helper method for RSA example
private static java.security.cert.Certificate generateSelfSignedCertificate(KeyPair keyPair) {
    // This would be implemented in a real application
    return null;
}