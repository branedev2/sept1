import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtParser;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.Base64;
import java.util.Map;
import java.util.HashMap;
import java.nio.charset.StandardCharsets;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;
import org.springframework.core.env.Environment;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import java.security.KeyStore;
import java.security.cert.Certificate;

public class JwtSecurityExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=hardcoded-credentials@v1.0 defects=1}
    public String bad_case_1() {
        // Hardcoded secret key for JWT signing
        // ruleid: java-jwt-exposed-credentials
        String secretKey = "my_super_secret_key_for_jwt_dont_share";
        
        String token = Jwts.builder()
                .setSubject("user123")
                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes()))
                .compact();
        
        return token;
    }
    
    public void bad_case_2() {
        // Hardcoded secret key for JWT verification
        // ruleid: java-jwt-exposed-credentials
        String jwtSecret = "hardcoded_jwt_verification_key_12345";
        
        Claims claims = Jwts.parser()
                .setSigningKey(jwtSecret.getBytes())
                .parseClaimsJws("received.jwt.token")
                .getBody();
                
        System.out.println("Subject: " + claims.getSubject());
    }
    
    public String bad_case_3() {
        // Hardcoded secret key with Auth0 JWT library
        // ruleid: java-jwt-exposed-credentials
        Algorithm algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID("my_auth0_jwt_secret_key_123");
        
        String token = JWT.create()
                .withSubject("user@example.com")
                .withIssuer("https://api.example.com/")
                .sign(algorithm);
                
        return token;
    }
    
    public DecodedJWT bad_case_4() {
        // Hardcoded secret for JWT verification with Auth0
        // ruleid: java-jwt-exposed-credentials
        String secret = "auth0_verification_secret_key_456";
        Algorithm algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID(secret);
        
        JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer("https://api.example.com/")
                .build();
                
        return verifier.verify("received.jwt.token");
    }
    
    public String bad_case_5() {
        // Hardcoded Base64 encoded secret
        // ruleid: java-jwt-exposed-credentials
        String base64EncodedSecret = "c2VjcmV0X2tleV9mb3Jfand0X3NpZ25pbmc="; // base64 encoded secret
        byte[] decodedKey = Base64.getDecoder().decode(base64EncodedSecret);
        
        Key key = new SecretKeySpec(decodedKey, 0, decodedKey.length, "HmacSHA256");
        
        return Jwts.builder()
                .setSubject("user")
                .signWith(key)
                .compact();
    }
    
    public String bad_case_6() {
        // Hardcoded RSA private key content (simplified for example)
        // ruleid: java-jwt-exposed-credentials
        String privateKeyPEM = "-----BEGIN PRIVATE KEY-----\n" +
                "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\n" +
                "MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu\n" +
                "NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ\n" +
                "-----END PRIVATE KEY-----";
        
        // Simplified for example - in real code would parse the PEM
        byte[] keyBytes = privateKeyPEM.getBytes();
        Key signingKey = new SecretKeySpec(keyBytes, "RSA");
        
        return Jwts.builder()
                .setSubject("admin")
                .signWith(signingKey)
                .compact();
    }
    
    public JwtDecoder bad_case_7() {
        // Hardcoded JWT secret for Spring Security OAuth2
        // ruleid: java-jwt-exposed-credentials
        String jwkSetUri = "https://example.com/.well-known/jwks.json";
        String clientSecret = "spring_oauth2_client_secret_789";
        
        return NimbusJwtDecoder.withJwkSetUri(jwkSetUri)
                .jwsAlgorithm(SignatureAlgorithm.HS256)
                .macKey(clientSecret.getBytes())
                .build();
    }
    
    public String bad_case_8() {
        // Hardcoded secret key with expiration time
        // ruleid: java-jwt-exposed-credentials
        String secretKey = "expiring_jwt_secret_key_987654321";
        
        return Jwts.builder()
                .setSubject("user456")
                .setExpiration(new Date(System.currentTimeMillis() + 3600000)) // 1 hour
                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes()))
                .compact();
    }
    
    public String bad_case_9() {
        // Hardcoded secret with claims
        // ruleid: java-jwt-exposed-credentials
        String secret = "jwt_with_claims_secret_key_abcdef";
        
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", "admin");
        claims.put("permissions", "read,write,delete");
        
        return Jwts.builder()
                .setClaims(claims)
                .signWith(Keys.hmacShaKeyFor(secret.getBytes()))
                .compact();
    }
    
    public JWTVerifier bad_case_10() {
        // Hardcoded secret with multiple verification parameters
        // ruleid: java-jwt-exposed-credentials
        String secret = "multi_verification_secret_key_123456";
        Algorithm algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID(secret);
        
        return JWT.require(algorithm)
                .withIssuer("auth.example.com")
                .withAudience("client.example.com")
                .withClaimPresence("user_id")
                .build();
    }
    
    public String bad_case_11() {
        // Hardcoded secret in a more complex JWT with header claims
        // ruleid: java-jwt-exposed-credentials
        String secretKey = "complex_jwt_secret_key_with_headers_xyz";
        
        Map<String, Object> headers = new HashMap<>();
        headers.put("kid", "key-id-12345");
        headers.put("typ", "JWT");
        
        return Jwts.builder()
                .setHeader(headers)
                .setSubject("user789")
                .setIssuer("api.example.org")
                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes()))
                .compact();
    }
    
    public String bad_case_12() {
        // Hardcoded secret with SecretKeySpec
        // ruleid: java-jwt-exposed-credentials
        String secret = "secret_key_spec_for_jwt_signing_123";
        SecretKey key = new SecretKeySpec(secret.getBytes(), "HmacSHA256");
        
        return Jwts.builder()
                .setSubject("user@domain.com")
                .signWith(key)
                .compact();
    }
    
    public Algorithm bad_case_13() {
        // Hardcoded secret for HMAC_REDACTED_TWILIO_ID
        // ruleid: java-jwt-exposed-credentials
        String secret = "hmac384_secret_key_for_stronger_jwt_signing";
        return Algorithm.HMAC_REDACTED_TWILIO_ID(secret);
    }
    
    public String bad_case_14() {
        try {
            // Hardcoded password for keystore
            // ruleid: java-jwt-exposed-credentials
            String keystorePassword = "keystore_password_123";
            KeyStore keystore = KeyStore.getInstance("PKCS12");
            keystore.load(new FileInputStream("keystore.p12"), keystorePassword.toCharArray());
            
            Certificate cert = keystore.getCertificate("jwt-key");
            Key key = keystore.getKey("jwt-key", keystorePassword.toCharArray());
            
            return Jwts.builder()
                    .setSubject("user")
                    .signWith((Key) key)
                    .compact();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
    
    public String bad_case_15() {
        // Multiple hardcoded secrets in different variables
        // ruleid: java-jwt-exposed-credentials
        String signingSecret = "signing_jwt_secret_abc";
        String encryptionSecret = "encryption_jwt_secret_xyz";
        
        // Using one of the secrets for signing
        return Jwts.builder()
                .setSubject("user123")
                .claim("encrypted", "data")
                .signWith(Keys.hmacShaKeyFor(signingSecret.getBytes()))
                .compact();
    }
    
    // True Negative Examples (Secure Code)
    
    @Autowired
    private Environment env;
    
    public String good_case_1() {
        // Using environment variable for JWT secret
        // ok: java-jwt-exposed-credentials
        String secretKey = System.getenv("JWT_SECRET_KEY");
        
        return Jwts.builder()
                .setSubject("user123")
                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes()))
                .compact();
    }
    
    public void good_case_2() {
        try {
            // Loading secret from properties file
            Properties props = new Properties();
            props.load(new FileInputStream("config.properties"));
            
            // ok: java-jwt-exposed-credentials
            String jwtSecret = props.getProperty("jwt.secret");
            
            Claims claims = Jwts.parser()
                    .setSigningKey(jwtSecret.getBytes())
                    .parseClaimsJws("received.jwt.token")
                    .getBody();
                    
            System.out.println("Subject: " + claims.getSubject());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    @Value("${jwt.secret}")
    private String jwtSecret;
    
    public String good_case_3() {
        // Using Spring's @Value annotation to inject secret from configuration
        // ok: java-jwt-exposed-credentials
        Algorithm algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID(jwtSecret);
        
        return JWT.create()
                .withSubject("user@example.com")
                .withIssuer("https://api.example.com/")
                .sign(algorithm);
    }
    
    public DecodedJWT good_case_4() {
        // Using environment variable for verification
        // ok: java-jwt-exposed-credentials
        String secret = env.getProperty("jwt.verification.secret");
        Algorithm algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID(secret);
        
        JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer("https://api.example.com/")
                .build();
                
        return verifier.verify("received.jwt.token");
    }
    
    public String good_case_5() {
        try {
            // Generate a secure random key instead of hardcoding
            // ok: java-jwt-exposed-credentials
            SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
            
            return Jwts.builder()
                    .setSubject("user")
                    .signWith(key)
                    .compact();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
    
    public String good_case_6() {
        try {
            // Loading private key from keystore instead of hardcoding
            KeyStore keystore = KeyStore.getInstance("PKCS12");
            
            // ok: java-jwt-exposed-credentials
            String keystorePassword = System.getenv("KEYSTORE_PASSWORD");
            keystore.load(new FileInputStream("keystore.p12"), keystorePassword.toCharArray());
            
            Key privateKey = keystore.getKey("jwt-key", keystorePassword.toCharArray());
            
            return Jwts.builder()
                    .setSubject("admin")
                    .signWith(privateKey)
                    .compact();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
    
    public JwtDecoder good_case_7() {
        // Using Spring's environment for OAuth2 client secret
        // ok: java-jwt-exposed-credentials
        String jwkSetUri = "https://example.com/.well-known/jwks.json";
        String clientSecret = env.getProperty("oauth2.client.secret");
        
        return NimbusJwtDecoder.withJwkSetUri(jwkSetUri)
                .jwsAlgorithm(SignatureAlgorithm.HS256)
                .macKey(clientSecret.getBytes())
                .build();
    }
    
    public String good_case_8() {
        // Using a secret from a secure vault service
        // ok: java-jwt-exposed-credentials
        String secretKey = getSecretFromVault("jwt-signing-key");
        
        return Jwts.builder()
                .setSubject("user456")
                .setExpiration(new Date(System.currentTimeMillis() + 3600000)) // 1 hour
                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes()))
                .compact();
    }
    
    private String getSecretFromVault(String secretId) {
        // This would be implemented to retrieve secrets from a secure vault
        // For example, AWS Secrets Manager, HashiCorp Vault, etc.
        return "securely-retrieved-secret";
    }
    
    public String good_case_9() {
        // Using asymmetric keys generated at runtime
        try {
            // ok: java-jwt-exposed-credentials
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.generateKeyPair();
            
            Map<String, Object> claims = new HashMap<>();
            claims.put("role", "admin");
            claims.put("permissions", "read,write,delete");
            
            return Jwts.builder()
                    .setClaims(claims)
                    .signWith(keyPair.getPrivate())
                    .compact();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
    
    public JWTVerifier good_case_10() {
        // Using a configuration service for secret retrieval
        // ok: java-jwt-exposed-credentials
        String secret = getConfigurationValue("jwt.verification.secret");
        Algorithm algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID(secret);
        
        return JWT.require(algorithm)
                .withIssuer("auth.example.com")
                .withAudience("client.example.com")
                .withClaimPresence("user_id")
                .build();
    }
    
    private String getConfigurationValue(String key) {
        // This would be implemented to retrieve configuration values securely
        return "securely-retrieved-configuration";
    }
    
    public String good_case_11() {
        // Using RSA key pair from environment
        try {
            // ok: java-jwt-exposed-credentials
            RSAPublicKey publicKey = (RSAPublicKey) getPublicKeyFromEnvironment();
            RSAPrivateKey privateKey = (RSAPrivateKey) getPrivateKeyFromEnvironment();
            
            Algorithm algorithm = Algorithm.RSA256(publicKey, privateKey);
            
            return JWT.create()
                    .withSubject("user789")
                    .withIssuer("api.example.org")
                    .sign(algorithm);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
    
    private Key getPublicKeyFromEnvironment() {
        // Implementation to retrieve public key from environment
        return null; // Placeholder
    }
    
    private Key getPrivateKeyFromEnvironment() {
        // Implementation to retrieve private key from environment
        return null; // Placeholder
    }
    
    public String good_case_12() {
        // Using a secret manager service
        // ok: java-jwt-exposed-credentials
        String secret = SecretManagerService.getSecret("JWT_SIGNING_SECRET");
        SecretKey key = new SecretKeySpec(secret.getBytes(), "HmacSHA256");
        
        return Jwts.builder()
                .setSubject("user@domain.com")
                .signWith(key)
                .compact();
    }
    
    // Mock secret manager service
    static class SecretManagerService {
        public static String getSecret(String secretId) {
            // This would be implemented to retrieve secrets from a secret manager
            return "securely-retrieved-secret";
        }
    }
    
    public Algorithm good_case_13() {
        // Using a database to store and retrieve the secret
        // ok: java-jwt-exposed-credentials
        String secret = DatabaseSecretProvider.getJwtSecret();
        return Algorithm.HMAC_REDACTED_TWILIO_ID(secret);
    }
    
    // Mock database secret provider
    static class DatabaseSecretProvider {
        public static String getJwtSecret() {
            // This would be implemented to retrieve secrets from a database
            return "securely-retrieved-secret";
        }
    }
    
    public String good_case_14() {
        try {
            // Using a secure configuration provider for keystore password
            // ok: java-jwt-exposed-credentials
            String keystorePassword = SecureConfigProvider.getKeystorePassword();
            KeyStore keystore = KeyStore.getInstance("PKCS12");
            keystore.load(new FileInputStream("keystore.p12"), keystorePassword.toCharArray());
            
            Certificate cert = keystore.getCertificate("jwt-key");
            Key key = keystore.getKey("jwt-key", keystorePassword.toCharArray());
            
            return Jwts.builder()
                    .setSubject("user")
                    .signWith((Key) key)
                    .compact();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
    
    // Mock secure configuration provider
    static class SecureConfigProvider {
        public static String getKeystorePassword() {
            // This would be implemented to retrieve configuration securely
            return "securely-retrieved-password";
        }
    }
    
    public String good_case_15() {
        // Using different environment variables for different secrets
        // ok: java-jwt-exposed-credentials
        String signingSecret = System.getenv("JWT_SIGNING_SECRET");
        String encryptionSecret = System.getenv("JWT_ENCRYPTION_SECRET");
        
        // Using one of the secrets for signing
        return Jwts.builder()
                .setSubject("user123")
                .claim("encrypted", "data")
                .signWith(Keys.hmacShaKeyFor(signingSecret.getBytes()))
                .compact();
    }
}
// {/fact}