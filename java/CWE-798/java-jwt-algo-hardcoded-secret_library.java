import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.keys.HmacKey;
import io.vertx.ext.auth.JWTOptions;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;
import io.vertx.ext.jwt.JWK;
import io.vertx.ext.jwt.JWTOptions;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MAC_REDACTED_TWILIO_ID;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import io.fusionauth.jwt.Signer;
import io.fusionauth.jwt.hmac.HMAC_REDACTED_TWILIO_ID;
import io.fusionauth.jwt.domain.JWT;
import com.okta.jwt.JwtBuilder;
import com.okta.jwt.Jwt;
import io.jsonwebtoken.io.Decoders;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.servlet.http.HttpServletRequest;
import org.apache.http.HttpRequest;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import java.util.Properties;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

// Security Issue: Hardcoded JWT secrets in Java applications

// True Positive Examples (Vulnerable/Insecure Code)
public class JwtSecurityExamples {

// {fact rule=hardcoded-credentials@v1.0 defects=1}
    public static void bad_case_1(HttpServletRequest request) {
        String userId = request.getParameter("userId");
        
        // ruleid: java-jwt-algo-hardcoded-secret
        Algorithm algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID("my-super-secret-key-that-should-not-be-hardcoded");
        
        String token = JWT.create()
                .withSubject(userId)
                .withExpiresAt(new Date(System.currentTimeMillis() + 3600000))
                .sign(algorithm);
    }

    public static void bad_case_2(HttpServletRequest request) {
        String username = request.getParameter("username");
        
        // ruleid: java-jwt-algo-hardcoded-secret
        String jwtToken = Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 900000))
                .signWith(SignatureAlgorithm.HS512, "hardcoded-secret-key-for-jwt-signing")
                .compact();
    }

    public static void bad_case_3(HttpServletRequest request) throws Exception {
        String userId = request.getParameter("userId");
        
        JwtClaims claims = new JwtClaims();
        claims.setSubject(userId);
        claims.setIssuedAtToNow();
        claims.setExpirationTimeMinutesInTheFuture(30);
        
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_REDACTED_TWILIO_ID_SHA256);
        
        // ruleid: java-jwt-algo-hardcoded-secret
        byte[] secretBytes = "jose4j-hardcoded-secret-key".getBytes("UTF-8");
        HmacKey key = new HmacKey(secretBytes);
        jws.setKey(key);
        
        String jwt = jws.getCompactSerialization();
    }

    public static void bad_case_4(HttpServletRequest request) throws Exception {
        String userId = request.getParameter("userId");
        
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(userId)
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 3600000))
                .build();
        
        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        
        // ruleid: java-jwt-algo-hardcoded-secret
        JWSSigner signer = new MAC_REDACTED_TWILIO_ID("nimbus-jose-jwt-hardcoded-secret");
        signedJWT.sign(signer);
        
        String jwt = signedJWT.serialize();
    }

    public static void bad_case_5(HttpServletRequest request) throws Exception {
        String userId = request.getParameter("userId");
        
        // ruleid: java-jwt-algo-hardcoded-secret
        Signer signer = HMAC_REDACTED_TWILIO_ID.newSHA256Signer("fusionauth-jwt-hardcoded-secret");
        
        JWT jwt = new JWT()
                .setSubject(userId)
                .setIssuedAt(ZonedDateTime.now(ZoneOffset.UTC))
                .setExpiration(ZonedDateTime.now(ZoneOffset.UTC).plusMinutes(60));
        
        String encodedJWT = JWT.getEncoder().encode(jwt, signer);
    }

    public static void bad_case_6(HttpServletRequest request) {
        String userId = request.getParameter("userId");
        
        JWTAuthOptions config = new JWTAuthOptions()
                .addPubSecKey(new JWK()
                        .setAlgorithm("HS256")
                        // ruleid: java-jwt-algo-hardcoded-secret
                        .setSecret("vertx-jwt-hardcoded-secret"));
        
        JWTAuth provider = JWTAuth.create(vertx, config);
        
        String token = provider.generateToken(
                new JsonObject().put("sub", userId),
                new JWTOptions().setExpiresInMinutes(60));
    }

    public static void bad_case_7(HttpServletRequest request) {
        String userId = request.getParameter("userId");
        
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .subject(userId)
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();
        
        // ruleid: java-jwt-algo-hardcoded-secret
        SecretKey key = Keys.hmacShaKeyFor("spring-security-oauth2-hardcoded-secret".getBytes());
        JwtEncoder encoder = new NimbusJwtEncoder(new ImmutableSecret<>(key));
        
        String jwt = encoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    public static void bad_case_8(HttpServletRequest request) throws Exception {
        String userId = request.getParameter("userId");
        
        // ruleid: java-jwt-algo-hardcoded-secret
        JwtBuilder jwtBuilder = Jwt.claims()
                .setSubject(userId)
                .setIssuedAt(new Date())
                .setExpiresAt(new Date(System.currentTimeMillis() + 3600000))
                .signWith(Keys.hmacShaKeyFor("okta-jwt-sdk-hardcoded-secret".getBytes()));
        
        String jwt = jwtBuilder.compact();
    }

    public static void bad_case_9(HttpServletRequest request) {
        String userId = request.getParameter("userId");
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", userId);
        
        // ruleid: java-jwt-algo-hardcoded-secret
        String jwt = Jwts.builder()
                .setClaims(claims)
                .setExpiration(new Date(System.currentTimeMillis() + 3600000))
                .signWith(Keys.hmacShaKeyFor("jjwt-api-hardcoded-secret".getBytes()))
                .compact();
    }

    public static void bad_case_10(HttpServletRequest request) throws Exception {
        String userId = request.getParameter("userId");
        
        // ruleid: java-jwt-algo-hardcoded-secret
        Algorithm algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID("auth0-jwt-hardcoded-secret-with-hmac384");
        
        String token = JWT.create()
                .withSubject(userId)
                .withExpiresAt(new Date(System.currentTimeMillis() + 3600000))
                .sign(algorithm);
    }

    public static void bad_case_11(HttpServletRequest request) throws Exception {
        String userId = request.getParameter("userId");
        
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(userId)
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 3600000))
                .build();
        
        JWSHeader header = new JWSHeader(JWSAlgorithm.HS512);
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        
        // ruleid: java-jwt-algo-hardcoded-secret
        JWSSigner signer = new MAC_REDACTED_TWILIO_ID("nimbus-jose-jwt-hardcoded-secret-with-hs512");
        signedJWT.sign(signer);
        
        String jwt = signedJWT.serialize();
    }

    public static void bad_case_12(HttpServletRequest request) {
        String userId = request.getParameter("userId");
        
        // ruleid: java-jwt-algo-hardcoded-secret
        String key = "another-hardcoded-secret-key-for-jwt";
        Algorithm algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID(key);
        
        String token = JWT.create()
                .withSubject(userId)
                .withExpiresAt(new Date(System.currentTimeMillis() + 3600000))
                .sign(algorithm);
    }

    public static void bad_case_13(HttpServletRequest request) throws Exception {
        String userId = request.getParameter("userId");
        
        // ruleid: java-jwt-algo-hardcoded-secret
        final String SECRET = "constant-hardcoded-jwt-secret";
        
        String jwtToken = Jwts.builder()
                .setSubject(userId)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 900000))
                .signWith(SignatureAlgorithm.HS256, SECRET)
                .compact();
    }

    public static void bad_case_14(HttpServletRequest request) throws Exception {
        String userId = request.getParameter("userId");
        
        // ruleid: java-jwt-algo-hardcoded-secret
        byte[] keyBytes = "base64-encoded-secret".getBytes();
        SecretKey key = Keys.hmacShaKeyFor(keyBytes);
        
        String jwt = Jwts.builder()
                .setSubject(userId)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 3600000))
                .signWith(key)
                .compact();
    }

    public static void bad_case_15(HttpServletRequest request) throws Exception {
        String userId = request.getParameter("userId");
        
        JwtClaims claims = new JwtClaims();
        claims.setSubject(userId);
        claims.setIssuedAtToNow();
        claims.setExpirationTimeMinutesInTheFuture(30);
        
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_REDACTED_TWILIO_ID_SHA512);
        
        // ruleid: java-jwt-algo-hardcoded-secret
        String secretString = "jose4j-hardcoded-secret-key-with-sha512";
        HmacKey key = new HmacKey(secretString.getBytes("UTF-8"));
        jws.setKey(key);
        
        String jwt = jws.getCompactSerialization();
    }

    // True Negative Examples (Safe/Secure Code)
    public static void good_case_1(HttpServletRequest request) {
        String userId = request.getParameter("userId");
        
        // ok: java-jwt-algo-hardcoded-secret
        String secretKey = System.getenv("JWT_SECRET_KEY");
        Algorithm algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID(secretKey);
        
        String token = JWT.create()
                .withSubject(userId)
                .withExpiresAt(new Date(System.currentTimeMillis() + 3600000))
                .sign(algorithm);
    }

    public static void good_case_2(HttpServletRequest request) {
        String username = request.getParameter("username");
        
        // ok: java-jwt-algo-hardcoded-secret
        String secretKey = loadSecretFromSecureStorage();
        String jwtToken = Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 900000))
                .signWith(SignatureAlgorithm.HS512, secretKey)
                .compact();
    }

    private static String loadSecretFromSecureStorage() {
        // Implementation to load secret from secure storage
        return System.getProperty("jwt.secret");
    }

    public static void good_case_3(HttpServletRequest request) throws Exception {
        String userId = request.getParameter("userId");
        
        JwtClaims claims = new JwtClaims();
        claims.setSubject(userId);
        claims.setIssuedAtToNow();
        claims.setExpirationTimeMinutesInTheFuture(30);
        
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_REDACTED_TWILIO_ID_SHA256);
        
        // ok: java-jwt-algo-hardcoded-secret
        Properties props = new Properties();
        try (InputStream input = new FileInputStream("config.properties")) {
            props.load(input);
        }
        String secretKey = props.getProperty("jwt.secret");
        HmacKey key = new HmacKey(secretKey.getBytes("UTF-8"));
        jws.setKey(key);
        
        String jwt = jws.getCompactSerialization();
    }

    @Value("${jwt.secret}")
    private String jwtSecret;
    
    public void good_case_4(HttpServletRequest request) throws Exception {
        String userId = request.getParameter("userId");
        
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(userId)
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 3600000))
                .build();
        
        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        
        // ok: java-jwt-algo-hardcoded-secret
        JWSSigner signer = new MAC_REDACTED_TWILIO_ID(jwtSecret);
        signedJWT.sign(signer);
        
        String jwt = signedJWT.serialize();
    }

    public static void good_case_5(HttpServletRequest request) throws Exception {
        String userId = request.getParameter("userId");
        
        // ok: java-jwt-algo-hardcoded-secret
        String secretKey = new String(Files.readAllBytes(Paths.get("/secure/path/jwt_secret.key")));
        Signer signer = HMAC_REDACTED_TWILIO_ID.newSHA256Signer(secretKey);
        
        JWT jwt = new JWT()
                .setSubject(userId)
                .setIssuedAt(ZonedDateTime.now(ZoneOffset.UTC))
                .setExpiration(ZonedDateTime.now(ZoneOffset.UTC).plusMinutes(60));
        
        String encodedJWT = JWT.getEncoder().encode(jwt, signer);
    }

    public static void good_case_6(HttpServletRequest request) {
        String userId = request.getParameter("userId");
        
        // ok: java-jwt-algo-hardcoded-secret
        String secretKey = System.getenv("VERTX_JWT_SECRET");
        JWTAuthOptions config = new JWTAuthOptions()
                .addPubSecKey(new JWK()
                        .setAlgorithm("HS256")
                        .setSecret(secretKey));
        
        JWTAuth provider = JWTAuth.create(vertx, config);
        
        String token = provider.generateToken(
                new JsonObject().put("sub", userId),
                new JWTOptions().setExpiresInMinutes(60));
    }

    @Configuration
    public class JwtConfig {
        @Value("${jwt.secret}")
        private String secret;
        
        @Bean
        public JwtEncoder jwtEncoder() {
            // ok: java-jwt-algo-hardcoded-secret
            SecretKey key = Keys.hmacShaKeyFor(secret.getBytes());
            return new NimbusJwtEncoder(new ImmutableSecret<>(key));
        }
    }

    public static void good_case_7(HttpServletRequest request) {
        String userId = request.getParameter("userId");
        
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .subject(userId)
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();
        
        // ok: java-jwt-algo-hardcoded-secret
        KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();
        JwtEncoder encoder = new NimbusJwtEncoder(new ImmutableSecret<>(key));
        
        String jwt = encoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    public static void good_case_8(HttpServletRequest request) throws Exception {
        String userId = request.getParameter("userId");
        
        // ok: java-jwt-algo-hardcoded-secret
        String secretKey = getSecretFromVault("jwt");
        JwtBuilder jwtBuilder = Jwt.claims()
                .setSubject(userId)
                .setIssuedAt(new Date())
                .setExpiresAt(new Date(System.currentTimeMillis() + 3600000))
                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes()));
        
        String jwt = jwtBuilder.compact();
    }
    
    private static String getSecretFromVault(String key) {
        // Implementation to retrieve secret from a secure vault
        return System.getProperty("vault." + key);
    }

    public static void good_case_9(HttpServletRequest request) {
        String userId = request.getParameter("userId");
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", userId);
        
        // ok: java-jwt-algo-hardcoded-secret
        SecretKey key = generateSecretKey();
        String jwt = Jwts.builder()
                .setClaims(claims)
                .setExpiration(new Date(System.currentTimeMillis() + 3600000))
                .signWith(key)
                .compact();
    }
    
    private static SecretKey generateSecretKey() {
        KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
        SecureRandom secureRandom = new SecureRandom();
        keyGen.init(256, secureRandom);
        return keyGen.generateKey();
    }

    public static void good_case_10(HttpServletRequest request) throws Exception {
        String userId = request.getParameter("userId");
        
        // ok: java-jwt-algo-hardcoded-secret
        String secretKeyBase64 = System.getenv("JWT_SECRET_BASE64");
        byte[] secretKeyBytes = Base64.getDecoder().decode(secretKeyBase64);
        Algorithm algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID(secretKeyBytes);
        
        String token = JWT.create()
                .withSubject(userId)
                .withExpiresAt(new Date(System.currentTimeMillis() + 3600000))
                .sign(algorithm);
    }

    public static void good_case_11(HttpServletRequest request) throws Exception {
        String userId = request.getParameter("userId");
        
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(userId)
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 3600000))
                .build();
        
        JWSHeader header = new JWSHeader(JWSAlgorithm.HS512);
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        
        // ok: java-jwt-algo-hardcoded-secret
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        JWSSigner signer = new RSASSASigner(keyPair.getPrivate());
        signedJWT.sign(signer);
        
        String jwt = signedJWT.serialize();
    }

    @RestController
    public class JwtController {
        @Value("${jwt.secret}")
        private String jwtSecret;
        
        @RequestMapping("/generate-token")
        public String good_case_12(HttpServletRequest request) {
            String userId = request.getParameter("userId");
            
            // ok: java-jwt-algo-hardcoded-secret
            Algorithm algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID(jwtSecret);
            
            String token = JWT.create()
                    .withSubject(userId)
                    .withExpiresAt(new Date(System.currentTimeMillis() + 3600000))
                    .sign(algorithm);
                    
            return token;
        }
    }

    public static void good_case_13(HttpServletRequest request) throws Exception {
        String userId = request.getParameter("userId");
        
        // ok: java-jwt-algo-hardcoded-secret
        String secretKey = retrieveSecretFromDatabase();
        
        String jwtToken = Jwts.builder()
                .setSubject(userId)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 900000))
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();
    }
    
    private static String retrieveSecretFromDatabase() {
        // Implementation to retrieve secret from database
        return "dynamic-secret-from-database";
    }

    public static void good_case_14(HttpServletRequest request) throws Exception {
        String userId = request.getParameter("userId");
        
        // ok: java-jwt-algo-hardcoded-secret
        byte[] keyBytes = Decoders.BASE64.decode(System.getenv("JWT_SECRET_BASE64"));
        SecretKey key = Keys.hmacShaKeyFor(keyBytes);
        
        String jwt = Jwts.builder()
                .setSubject(userId)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 3600000))
                .signWith(key)
                .compact();
    }

    public static void good_case_15(HttpServletRequest request) throws Exception {
        String userId = request.getParameter("userId");
        
        JwtClaims claims = new JwtClaims();
        claims.setSubject(userId);
        claims.setIssuedAtToNow();
        claims.setExpirationTimeMinutesInTheFuture(30);
        
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_REDACTED_TWILIO_ID_SHA512);
        
        // ok: java-jwt-algo-hardcoded-secret
        SecureRandom secureRandom = new SecureRandom();
        byte[] secretBytes = new byte[64];
        secureRandom.nextBytes(secretBytes);
        HmacKey key = new HmacKey(secretBytes);
        jws.setKey(key);
        
        String jwt = jws.getCompactSerialization();
    }
}
// {/fact}