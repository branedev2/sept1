import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.interfaces.DecodedJWT;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Date;
import java.util.Map;
import java.util.HashMap;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

public class JwtSecurityExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=hardcoded-credentials@v1.0 defects=1}
    public void bad_case_1() {
        // ruleid: java-jwt-algo-hardcoded-secret
        Algorithm algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID("my-secret-key-1234");
        String token = JWT.create()
                .withIssuer("auth0")
                .sign(algorithm);
        System.out.println("Generated token: " + token);
    }

    public void bad_case_2() {
        String issuer = "example-issuer";
        // ruleid: java-jwt-algo-hardcoded-secret
        Algorithm algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID("super-secret-password-do-not-share");
        JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer(issuer)
                .build();
        // Verify a token
        DecodedJWT jwt = verifier.verify("token-to-verify");
    }

    public void bad_case_3() {
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", "admin");
        
        // ruleid: java-jwt-algo-hardcoded-secret
        String jwtToken = Jwts.builder()
                .setClaims(claims)
                .setSubject("user123")
                .setIssuedAt(new Date())
                .signWith(SignatureAlgorithm.HS256, "hardcoded-jwt-secret-key")
                .compact();
    }

    public void bad_case_4() {
        // ruleid: java-jwt-algo-hardcoded-secret
        byte[] keyBytes = "ThisIsAVeryLongSecretKeyForHS512Algorithm".getBytes(StandardCharsets.UTF_8);
        SecretKey key = new SecretKeySpec(keyBytes, "HmacSHA512");
        
        String token = Jwts.builder()
                .setSubject("user")
                .signWith(key)
                .compact();
    }

    public void bad_case_5() {
        // ruleid: java-jwt-algo-hardcoded-secret
        Algorithm algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID("production-api-secret-key-123456789");
        String token = JWT.create()
                .withClaim("user_id", 123)
                .withExpiresAt(new Date(System.currentTimeMillis() + 3600000))
                .sign(algorithm);
    }

    public void bad_case_6() {
        try {
            // ruleid: java-jwt-algo-hardcoded-secret
            SecretKey key = Keys.hmacShaKeyFor("my-static-secret-key-for-jwt-signing".getBytes(StandardCharsets.UTF_8));
            String jws = Jwts.builder()
                    .setSubject("user")
                    .signWith(key)
                    .compact();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_7() {
        // ruleid: java-jwt-algo-hardcoded-secret
        String base64EncodedKey = Base64.getEncoder().encodeToString("hardcoded-secret-key".getBytes());
        Algorithm algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID(base64EncodedKey);
        
        String token = JWT.create()
                .withIssuer("api")
                .sign(algorithm);
    }

    public void bad_case_8() {
        // ruleid: java-jwt-algo-hardcoded-secret
        final String SECRET = "jwt-secret-should-not-be-hardcoded";
        Algorithm algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID(SECRET);
        
        String token = JWT.create()
                .withSubject("1234567890")
                .withIssuer("auth0")
                .sign(algorithm);
    }

    public void bad_case_9() {
        Map<String, Object> claims = new HashMap<>();
        claims.put("name", "John Doe");
        
        // ruleid: java-jwt-algo-hardcoded-secret
        String jwtToken = Jwts.builder()
                .setClaims(claims)
                .setExpiration(new Date(System.currentTimeMillis() + 864000000))
                .signWith(SignatureAlgorithm.HS256, "my-static-signing-key")
                .compact();
    }

    public void bad_case_10() {
        // ruleid: java-jwt-algo-hardcoded-secret
        byte[] secretBytes = "ThisIsASecretKeyForJWT".getBytes();
        SecretKey secretKey = new SecretKeySpec(secretBytes, SignatureAlgorithm.HS256.getJcaName());
        
        String jwt = Jwts.builder()
                .setSubject("user")
                .signWith(secretKey)
                .compact();
    }

    public void bad_case_11() {
        // ruleid: java-jwt-algo-hardcoded-secret
        String secret = "hardcoded" + "-" + "secret" + "-" + "key";
        Algorithm algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID(secret);
        
        String token = JWT.create()
                .withClaim("admin", true)
                .sign(algorithm);
    }

    public void bad_case_12() {
        if (true) {
            // ruleid: java-jwt-algo-hardcoded-secret
            Algorithm algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID("secret-key-for-dev-environment");
            String token = JWT.create()
                    .withIssuer("example.com")
                    .sign(algorithm);
        } else {
            // This branch is never executed
            Algorithm algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID(System.getenv("JWT_SECRET"));
            String token = JWT.create()
                    .withIssuer("example.com")
                    .sign(algorithm);
        }
    }

    public void bad_case_13() {
        String userId = "12345";
        // ruleid: java-jwt-algo-hardcoded-secret
        String secretKey = "jwt-signing-key-production-environment";
        
        String token = Jwts.builder()
                .setId(userId)
                .setIssuedAt(new Date())
                .signWith(SignatureAlgorithm.HS512, secretKey.getBytes())
                .compact();
    }

    public void bad_case_14() {
        // ruleid: java-jwt-algo-hardcoded-secret
        final String[] SECRETS = {"key1", "key2", "key3"};
        Algorithm algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID(SECRETS[0]);
        
        String token = JWT.create()
                .withSubject("user@example.com")
                .sign(algorithm);
    }

    public void bad_case_15() {
        // ruleid: java-jwt-algo-hardcoded-secret
        StringBuilder secretBuilder = new StringBuilder();
        secretBuilder.append("hard").append("coded").append("secret");
        String secret = secretBuilder.toString();
        
        Algorithm algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID(secret);
        String token = JWT.create()
                .withExpiresAt(new Date(System.currentTimeMillis() + 3600000))
                .sign(algorithm);
    }

    // True Negative Examples (Secure Code)

    public void good_case_1(Environment env) {
        // ok: java-jwt-algo-hardcoded-secret
        String secret = env.getProperty("jwt.secret");
        Algorithm algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID(secret);
        
        String token = JWT.create()
                .withIssuer("auth0")
                .sign(algorithm);
    }

    public void good_case_2() {
        // ok: java-jwt-algo-hardcoded-secret
        String secret = System.getenv("JWT_SECRET_KEY");
        Algorithm algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID(secret);
        
        JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer("example-issuer")
                .build();
        DecodedJWT jwt = verifier.verify("token-to-verify");
    }

    public void good_case_3() {
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", "admin");
        
        // ok: java-jwt-algo-hardcoded-secret
        String jwtSecret = System.getProperty("jwt.signing.key");
        String jwtToken = Jwts.builder()
                .setClaims(claims)
                .setSubject("user123")
                .setIssuedAt(new Date())
                .signWith(SignatureAlgorithm.HS256, jwtSecret)
                .compact();
    }

    private String getSecretFromVault() {
        // This would retrieve the secret from a secure vault
        return "secret-from-vault";
    }

    public void good_case_4() {
        // ok: java-jwt-algo-hardcoded-secret
        String secretFromVault = getSecretFromVault();
        byte[] keyBytes = secretFromVault.getBytes(StandardCharsets.UTF_8);
        SecretKey key = new SecretKeySpec(keyBytes, "HmacSHA512");
        
        String token = Jwts.builder()
                .setSubject("user")
                .signWith(key)
                .compact();
    }

    public void good_case_5(@Value("${jwt.secret}") String jwtSecret) {
        // ok: java-jwt-algo-hardcoded-secret
        Algorithm algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID(jwtSecret);
        String token = JWT.create()
                .withClaim("user_id", 123)
                .withExpiresAt(new Date(System.currentTimeMillis() + 3600000))
                .sign(algorithm);
    }

    public void good_case_6() {
        try {
            // ok: java-jwt-algo-hardcoded-secret
            String secretKey = System.getenv("JWT_SECRET_KEY");
            if (secretKey == null || secretKey.isEmpty()) {
                throw new IllegalStateException("JWT secret key not configured");
            }
            
            SecretKey key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
            String jws = Jwts.builder()
                    .setSubject("user")
                    .signWith(key)
                    .compact();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_7() throws IOException {
        Properties properties = new Properties();
        properties.load(new FileInputStream("config.properties"));
        
        // ok: java-jwt-algo-hardcoded-secret
        String secretKey = properties.getProperty("jwt.secret");
        Algorithm algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID(secretKey);
        
        String token = JWT.create()
                .withIssuer("api")
                .sign(algorithm);
    }

    public void good_case_8(SecretKey secretKeyFromKeyStore) {
        // ok: java-jwt-algo-hardcoded-secret
        String jwt = Jwts.builder()
                .setSubject("1234567890")
                .setIssuer("auth0")
                .signWith(secretKeyFromKeyStore)
                .compact();
    }

    public void good_case_9(Environment env) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("name", "John Doe");
        
        // ok: java-jwt-algo-hardcoded-secret
        String secret = env.getProperty("jwt.signing.key");
        String jwtToken = Jwts.builder()
                .setClaims(claims)
                .setExpiration(new Date(System.currentTimeMillis() + 864000000))
                .signWith(SignatureAlgorithm.HS256, secret)
                .compact();
    }

    public void good_case_10() {
        // ok: java-jwt-algo-hardcoded-secret
        String secretFromConfig = loadSecretFromSecureConfig();
        byte[] secretBytes = secretFromConfig.getBytes();
        SecretKey secretKey = new SecretKeySpec(secretBytes, SignatureAlgorithm.HS256.getJcaName());
        
        String jwt = Jwts.builder()
                .setSubject("user")
                .signWith(secretKey)
                .compact();
    }

    private String loadSecretFromSecureConfig() {
        // Implementation to load secret from a secure configuration source
        return "secure-secret";
    }

    public void good_case_11() {
        // ok: java-jwt-algo-hardcoded-secret
        String secret = fetchSecretFromKeyManagementService();
        Algorithm algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID(secret);
        
        String token = JWT.create()
                .withClaim("admin", true)
                .sign(algorithm);
    }

    private String fetchSecretFromKeyManagementService() {
        // Implementation to fetch secret from a key management service
        return "secret-from-kms";
    }

    public void good_case_12(Environment env) {
        boolean isDev = "dev".equals(env.getProperty("app.environment"));
        
        // ok: java-jwt-algo-hardcoded-secret
        String secret = isDev ? env.getProperty("jwt.dev.secret") : env.getProperty("jwt.prod.secret");
        Algorithm algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID(secret);
        String token = JWT.create()
                .withIssuer("example.com")
                .sign(algorithm);
    }

    public void good_case_13() {
        String userId = "12345";
        
        // ok: java-jwt-algo-hardcoded-secret
        String secretKey = System.getenv("JWT_SIGNING_KEY");
        if (secretKey == null) {
            throw new IllegalStateException("JWT signing key not configured");
        }
        
        String token = Jwts.builder()
                .setId(userId)
                .setIssuedAt(new Date())
                .signWith(SignatureAlgorithm.HS512, secretKey.getBytes())
                .compact();
    }

    public void good_case_14() throws IOException {
        Properties appProps = new Properties();
        appProps.load(new FileInputStream("application.properties"));
        
        // ok: java-jwt-algo-hardcoded-secret
        String[] secrets = appProps.getProperty("jwt.secrets").split(",");
        Algorithm algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID(secrets[0]);
        
        String token = JWT.create()
                .withSubject("user@example.com")
                .sign(algorithm);
    }

    public void good_case_15(Environment env) {
        // ok: java-jwt-algo-hardcoded-secret
        String prefix = env.getProperty("jwt.secret.prefix");
        String suffix = env.getProperty("jwt.secret.suffix");
        String secret = prefix + suffix;
        
        Algorithm algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID(secret);
        String token = JWT.create()
                .withExpiresAt(new Date(System.currentTimeMillis() + 3600000))
                .sign(algorithm);
    }
}
// {/fact}