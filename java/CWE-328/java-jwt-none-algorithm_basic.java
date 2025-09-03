import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Date;
import java.util.List;

public class JwtNoneAlgorithmExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=clear-text-credentials@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) {
        String token = request.getHeader("Authorization");
        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7);
            try {
                // ruleid: java-jwt-none-algorithm
                JWT.require(Algorithm.none())
                   .withIssuer("auth0")
                   .build()
                   .verify(token);
                response.getWriter().write("Token verified");
            } catch (Exception e) {
                response.getWriter().write("Invalid token");
            }
        }
    }

    public void bad_case_2(HttpServletRequest request) throws Exception {
        String token = request.getParameter("token");
        String secretKey = "mySecretKey";
        
        // ruleid: java-jwt-none-algorithm
        Algorithm algorithm = Algorithm.none();
        JWTVerifier verifier = JWT.require(algorithm)
                                  .withIssuer("auth0")
                                  .build();
        DecodedJWT jwt = verifier.verify(token);
        String userId = jwt.getSubject();
    }

    public void bad_case_3() {
        String secretKey = "mySecretKey";
        
        // ruleid: java-jwt-none-algorithm
        String token = JWT.create()
                         .withSubject("1234567890")
                         .withIssuer("auth0")
                         .sign(Algorithm.none());
        System.out.println("Generated token: " + token);
    }

    public void bad_case_4(HttpServletRequest request) {
        String token = request.getHeader("X-Auth-Token");
        
        try {
            // ruleid: java-jwt-none-algorithm
            DecodedJWT jwt = JWT.require(Algorithm.none())
                               .build()
                               .verify(token);
            String username = jwt.getClaim("username").asString();
            System.out.println("Authenticated user: " + username);
        } catch (JWTVerificationException e) {
            System.out.println("Authentication failed: " + e.getMessage());
        }
    }

    public void bad_case_5(HttpServletRequest request) {
        String token = request.getParameter("access_token");
        String userId = null;
        
        try {
            // ruleid: java-jwt-none-algorithm
            JWTVerifier verifier = JWT.require(Algorithm.none())
                                     .withAudience("api-audience")
                                     .withIssuer("auth-service")
                                     .build();
            DecodedJWT jwt = verifier.verify(token);
            userId = jwt.getSubject();
        } catch (Exception e) {
            System.out.println("Token verification failed");
        }
    }

    public void bad_case_6() {
        // ruleid: java-jwt-none-algorithm
        Algorithm algorithm = Algorithm.none();
        String token = JWT.create()
                         .withSubject("user123")
                         .withExpiresAt(new Date(System.currentTimeMillis() + 3600000))
                         .sign(algorithm);
        System.out.println("Token: " + token);
    }

    public void bad_case_7(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            try {
                // ruleid: java-jwt-none-algorithm
                DecodedJWT jwt = JWT.require(Algorithm.none())
                                   .withClaimPresence("permissions")
                                   .build()
                                   .verify(token);
                List<String> permissions = jwt.getClaim("permissions").asList(String.class);
            } catch (Exception e) {
                System.out.println("Invalid token");
            }
        }
    }

    public void bad_case_8(HttpServletRequest request) {
        String token = request.getParameter("id_token");
        
        try {
            // ruleid: java-jwt-none-algorithm
            Algorithm alg = Algorithm.none();
            JWTVerifier verifier = JWT.require(alg)
                                     .withIssuer("https://my-domain.auth0.com/")
                                     .build();
            DecodedJWT jwt = verifier.verify(token);
        } catch (Exception e) {
            System.out.println("Token validation failed: " + e.getMessage());
        }
    }

    public void bad_case_9() {
        // ruleid: java-jwt-none-algorithm
        String token = JWT.create()
                         .withClaim("admin", true)
                         .withSubject("admin_user")
                         .sign(Algorithm.none());
        System.out.println("Admin token: " + token);
    }

    public void bad_case_10(HttpServletRequest request) {
        String token = request.getHeader("X-API-Token");
        
        try {
            // ruleid: java-jwt-none-algorithm
            JWTVerifier verifier = JWT.require(Algorithm.none())
                                     .acceptLeeway(1)
                                     .build();
            DecodedJWT jwt = verifier.verify(token);
            String userId = jwt.getSubject();
        } catch (Exception e) {
            System.out.println("Invalid token");
        }
    }

    public void bad_case_11(HttpServletRequest request) {
        String token = request.getParameter("token");
        String userId = null;
        
        try {
            // ruleid: java-jwt-none-algorithm
            Algorithm algorithm = null;
            String alg = request.getParameter("alg");
            if ("none".equals(alg)) {
                algorithm = Algorithm.none();
            } else {
                algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID("secret");
            }
            
            JWTVerifier verifier = JWT.require(algorithm).build();
            DecodedJWT jwt = verifier.verify(token);
            userId = jwt.getSubject();
        } catch (Exception e) {
            System.out.println("Token verification failed");
        }
    }

    public void bad_case_12() {
        String[] algorithms = {"HMAC_REDACTED_TWILIO_ID", "HMAC_REDACTED_TWILIO_ID", "none"};
        for (String alg : algorithms) {
            try {
                Algorithm algorithm;
                if (alg.equals("none")) {
                    // ruleid: java-jwt-none-algorithm
                    algorithm = Algorithm.none();
                } else if (alg.equals("HMAC_REDACTED_TWILIO_ID")) {
                    algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID("secret");
                } else {
                    algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID("secret");
                }
                
                String token = JWT.create()
                                 .withSubject("1234567890")
                                 .sign(algorithm);
                System.out.println("Token with " + alg + ": " + token);
            } catch (Exception e) {
                System.out.println("Error creating token with " + alg);
            }
        }
    }

    public void bad_case_13(HttpServletRequest request) {
        String token = request.getHeader("Authorization").substring(7);
        String algorithmName = request.getParameter("algorithm");
        
        try {
            Algorithm algorithm;
            if ("none".equalsIgnoreCase(algorithmName)) {
                // ruleid: java-jwt-none-algorithm
                algorithm = Algorithm.none();
            } else {
                algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID("secret");
            }
            
            JWTVerifier verifier = JWT.require(algorithm).build();
            DecodedJWT jwt = verifier.verify(token);
        } catch (Exception e) {
            System.out.println("Token verification failed");
        }
    }

    public void bad_case_14() {
        boolean useSecureAlgorithm = false;
        Algorithm algorithm;
        
        if (useSecureAlgorithm) {
            algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID("secret");
        } else {
            // ruleid: java-jwt-none-algorithm
            algorithm = Algorithm.none();
        }
        
        String token = JWT.create()
                         .withSubject("user")
                         .sign(algorithm);
        System.out.println("Generated token: " + token);
    }

    public void bad_case_15(HttpServletRequest request) {
        String token = request.getParameter("token");
        String mode = request.getParameter("mode");
        
        try {
            Algorithm algorithm;
            if ("testing".equals(mode)) {
                // ruleid: java-jwt-none-algorithm
                algorithm = Algorithm.none();
            } else {
                algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID("production-secret");
            }
            
            JWTVerifier verifier = JWT.require(algorithm).build();
            DecodedJWT jwt = verifier.verify(token);
        } catch (Exception e) {
            System.out.println("Token verification failed");
        }
    }

    // True Negative Examples (Secure Code)

    public void good_case_1(HttpServletRequest request, HttpServletResponse response) {
        String token = request.getHeader("Authorization");
        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7);
            try {
                // ok: java-jwt-none-algorithm
                JWT.require(Algorithm.HMAC_REDACTED_TWILIO_ID("secret"))
                   .withIssuer("auth0")
                   .build()
                   .verify(token);
                response.getWriter().write("Token verified");
            } catch (Exception e) {
                response.getWriter().write("Invalid token");
            }
        }
    }

    public void good_case_2(HttpServletRequest request) throws Exception {
        String token = request.getParameter("token");
        String secretKey = "mySecretKey";
        
        // ok: java-jwt-none-algorithm
        Algorithm algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID(secretKey);
        JWTVerifier verifier = JWT.require(algorithm)
                                  .withIssuer("auth0")
                                  .build();
        DecodedJWT jwt = verifier.verify(token);
        String userId = jwt.getSubject();
    }

    public void good_case_3() throws Exception {
        String secretKey = "mySecretKey";
        
        // ok: java-jwt-none-algorithm
        String token = JWT.create()
                         .withSubject("1234567890")
                         .withIssuer("auth0")
                         .sign(Algorithm.HMAC_REDACTED_TWILIO_ID(secretKey));
        System.out.println("Generated token: " + token);
    }

    public void good_case_4(HttpServletRequest request) throws Exception {
        String token = request.getHeader("X-Auth-Token");
        
        try {
            // ok: java-jwt-none-algorithm
            DecodedJWT jwt = JWT.require(Algorithm.HMAC_REDACTED_TWILIO_ID("secret"))
                               .build()
                               .verify(token);
            String username = jwt.getClaim("username").asString();
            System.out.println("Authenticated user: " + username);
        } catch (JWTVerificationException e) {
            System.out.println("Authentication failed: " + e.getMessage());
        }
    }

    public void good_case_5(HttpServletRequest request) throws Exception {
        String token = request.getParameter("access_token");
        String userId = null;
        
        try {
            // ok: java-jwt-none-algorithm
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.generateKeyPair();
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
            
            JWTVerifier verifier = JWT.require(Algorithm.RSA256(publicKey, privateKey))
                                     .withAudience("api-audience")
                                     .withIssuer("auth-service")
                                     .build();
            DecodedJWT jwt = verifier.verify(token);
            userId = jwt.getSubject();
        } catch (Exception e) {
            System.out.println("Token verification failed");
        }
    }

    public void good_case_6() throws Exception {
        // ok: java-jwt-none-algorithm
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        
        Algorithm algorithm = Algorithm.RSA512(publicKey, privateKey);
        String token = JWT.create()
                         .withSubject("user123")
                         .withExpiresAt(new Date(System.currentTimeMillis() + 3600000))
                         .sign(algorithm);
        System.out.println("Token: " + token);
    }

    public void good_case_7(HttpServletRequest request) throws Exception {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            try {
                // ok: java-jwt-none-algorithm
                DecodedJWT jwt = JWT.require(Algorithm.HMAC_REDACTED_TWILIO_ID("secret"))
                                   .withClaimPresence("permissions")
                                   .build()
                                   .verify(token);
                List<String> permissions = jwt.getClaim("permissions").asList(String.class);
            } catch (Exception e) {
                System.out.println("Invalid token");
            }
        }
    }

    public void good_case_8(HttpServletRequest request) throws Exception {
        String token = request.getParameter("id_token");
        
        try {
            // ok: java-jwt-none-algorithm
            byte[] keyBytes = Base64.getDecoder().decode("your-base64-encoded-secret");
            Algorithm alg = Algorithm.HMAC_REDACTED_TWILIO_ID(keyBytes);
            JWTVerifier verifier = JWT.require(alg)
                                     .withIssuer("https://my-domain.auth0.com/")
                                     .build();
            DecodedJWT jwt = verifier.verify(token);
        } catch (Exception e) {
            System.out.println("Token validation failed: " + e.getMessage());
        }
    }

    public void good_case_9() throws Exception {
        // ok: java-jwt-none-algorithm
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        
        String token = JWT.create()
                         .withClaim("admin", true)
                         .withSubject("admin_user")
                         .sign(Algorithm.RSA256(publicKey, privateKey));
        System.out.println("Admin token: " + token);
    }

    public void good_case_10(HttpServletRequest request) throws Exception {
        String token = request.getHeader("X-API-Token");
        
        try {
            // ok: java-jwt-none-algorithm
            JWTVerifier verifier = JWT.require(Algorithm.HMAC_REDACTED_TWILIO_ID("secret"))
                                     .acceptLeeway(1)
                                     .build();
            DecodedJWT jwt = verifier.verify(token);
            String userId = jwt.getSubject();
        } catch (Exception e) {
            System.out.println("Invalid token");
        }
    }

    public void good_case_11(HttpServletRequest request) throws Exception {
        String token = request.getParameter("token");
        String userId = null;
        
        try {
            // ok: java-jwt-none-algorithm
            Algorithm algorithm;
            String alg = request.getParameter("alg");
            if ("HS256".equals(alg)) {
                algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID("secret");
            } else {
                algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID("secret");
            }
            
            JWTVerifier verifier = JWT.require(algorithm).build();
            DecodedJWT jwt = verifier.verify(token);
            userId = jwt.getSubject();
        } catch (Exception e) {
            System.out.println("Token verification failed");
        }
    }

    public void good_case_12() throws Exception {
        String[] algorithms = {"HMAC_REDACTED_TWILIO_ID", "HMAC_REDACTED_TWILIO_ID"};
        for (String alg : algorithms) {
            try {
                Algorithm algorithm;
                if (alg.equals("HMAC_REDACTED_TWILIO_ID")) {
                    // ok: java-jwt-none-algorithm
                    algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID("secret");
                } else {
                    algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID("secret");
                }
                
                String token = JWT.create()
                                 .withSubject("1234567890")
                                 .sign(algorithm);
                System.out.println("Token with " + alg + ": " + token);
            } catch (Exception e) {
                System.out.println("Error creating token with " + alg);
            }
        }
    }

    public void good_case_13() throws Exception {
        // ok: java-jwt-none-algorithm
        Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        String jws = Jwts.builder()
                        .setSubject("Joe")
                        .signWith(key)
                        .compact();
        System.out.println("Generated token: " + jws);
    }

    public void good_case_14(HttpServletRequest request) throws Exception {
        String token = request.getHeader("Authorization").substring(7);
        String algorithmName = request.getParameter("algorithm");
        
        try {
            Algorithm algorithm;
            // ok: java-jwt-none-algorithm
            if ("HS256".equalsIgnoreCase(algorithmName)) {
                algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID("secret");
            } else if ("HS512".equalsIgnoreCase(algorithmName)) {
                algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID("secret");
            } else {
                algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID("secret");
            }
            
            JWTVerifier verifier = JWT.require(algorithm).build();
            DecodedJWT jwt = verifier.verify(token);
        } catch (Exception e) {
            System.out.println("Token verification failed");
        }
    }

    public void good_case_15() throws Exception {
        boolean useSecureAlgorithm = true;
        Algorithm algorithm;
        
        if (useSecureAlgorithm) {
            // ok: java-jwt-none-algorithm
            algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID("secret");
        } else {
            algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID("secret");
        }
        
        String token = JWT.create()
                         .withSubject("user")
                         .sign(algorithm);
        System.out.println("Generated token: " + token);
    }
}
// {/fact}