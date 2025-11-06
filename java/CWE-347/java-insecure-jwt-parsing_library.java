import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.HmacKey;
import org.jose4j.lang.JoseException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MAC_REDACTED_TWILIO_ID;
import com.nimbusds.jose.crypto.MAC_REDACTED_TWILIO_ID;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.JWTParser;
import fusionauth.jwt.Signer;
import fusionauth.jwt.Verifier;
import fusionauth.jwt.domain.JWT;
import fusionauth.jwt.hmac.HMAC_REDACTED_TWILIO_ID;
import fusionauth.jwt.hmac.HMAC_REDACTED_TWILIO_ID;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.JWTOptions;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;
import io.vertx.ext.web.handler.JWTAuthHandler;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import javax.servlet.http.HttpServletRequest;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.apache.commons.codec.binary.Base64;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.AccessToken;
import com.okta.jwt.AccessTokenVerifier;
import com.okta.jwt.JwtVerifiers;
import com.okta.jwt.Jwt;
import org.pac4j.jwt.config.signature.SecretSignatureConfiguration;
import org.pac4j.jwt.profile.JwtGenerator;
import org.pac4j.jwt.credentials.authenticator.JwtAuthenticator;
import org.pac4j.core.profile.CommonProfile;
import io.jsonwebtoken.jackson.io.JacksonDeserializer;
import io.jsonwebtoken.jackson.io.JacksonSerializer;
import io.jsonwebtoken.io.Deserializer;
import io.jsonwebtoken.io.Serializer;
import com.google.api.client.json.webtoken.JsonWebToken;
import com.google.api.client.json.webtoken.JsonWebSignature;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import org.apache.cxf.rs.security.jose.jws.JwsJwtCompactConsumer;
import org.apache.cxf.rs.security.jose.jws.JwsSignatureVerifier;
import org.apache.cxf.rs.security.jose.jws.HmacJwsSignatureVerifier;
import org.apache.cxf.rs.security.jose.jwa.SignatureAlgorithm;
import org.apache.cxf.rs.security.jose.jwk.JsonWebKey;

// Security Issue: Insecure JWT parsing that doesn't validate signatures, allowing attackers to forge tokens

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) {
    // JJWT library - Parsing JWT without signature verification
    String token = request.getHeader("Authorization").replace("Bearer ", "");
    
    try {
        // ruleid: java-insecure-jwt-parsing
        Claims claims = Jwts.parser()
            .parse(token)
            .getBody();
        
        String username = claims.getSubject();
        System.out.println("Authenticated user: " + username);
    } catch (Exception e) {
        System.out.println("Invalid token");
    }
}

public void bad_case_2(HttpServletRequest request) {
    // Nimbus JOSE+JWT library - Parsing JWT without signature verification
    String token = request.getHeader("Authorization").replace("Bearer ", "");
    
    try {
        // ruleid: java-insecure-jwt-parsing
        com.nimbusds.jwt.JWT jwt = JWTParser.parse(token);
        JWTClaimsSet claimsSet = jwt.getJWTClaimsSet();
        
        String username = claimsSet.getSubject();
        System.out.println("Authenticated user: " + username);
    } catch (Exception e) {
        System.out.println("Invalid token");
    }
}

public void bad_case_3(HttpServletRequest request) {
    // Auth0 JWT library - Parsing JWT without signature verification
    String token = request.getHeader("Authorization").replace("Bearer ", "");
    
    try {
        // ruleid: java-insecure-jwt-parsing
        com.auth0.jwt.interfaces.DecodedJWT jwt = JWT.decode(token);
        
        String username = jwt.getSubject();
        System.out.println("Authenticated user: " + username);
    } catch (Exception e) {
        System.out.println("Invalid token");
    }
}

public void bad_case_4(HttpServletRequest request) {
    // Apache CXF RS Security - Parsing JWT without signature verification
    String token = request.getHeader("Authorization").replace("Bearer ", "");
    
    try {
        // ruleid: java-insecure-jwt-parsing
        JwsJwtCompactConsumer consumer = new JwsJwtCompactConsumer(token);
        org.apache.cxf.rs.security.jose.jwt.JwtToken jwt = consumer.getJwtToken();
        
        String username = jwt.getClaim("sub").toString();
        System.out.println("Authenticated user: " + username);
    } catch (Exception e) {
        System.out.println("Invalid token");
    }
}

public void bad_case_5(HttpServletRequest request) {
    // FusionAuth JWT library - Parsing JWT without signature verification
    String token = request.getHeader("Authorization").replace("Bearer ", "");
    
    try {
        // ruleid: java-insecure-jwt-parsing
        JWT jwt = JWT.getDecoder().decode(token, false);
        
        String username = jwt.subject;
        System.out.println("Authenticated user: " + username);
    } catch (Exception e) {
        System.out.println("Invalid token");
    }
}

public void bad_case_6(HttpServletRequest request) {
    // JOSE4J library - Parsing JWT without signature verification
    String token = request.getHeader("Authorization").replace("Bearer ", "");
    
    try {
        // ruleid: java-insecure-jwt-parsing
        org.jose4j.jwt.consumer.JwtConsumer jwtConsumer = new org.jose4j.jwt.consumer.JwtConsumerBuilder()
            .setSkipSignatureVerification()
            .build();
        
        org.jose4j.jwt.JwtClaims jwtClaims = jwtConsumer.processToClaims(token);
        String username = jwtClaims.getSubject();
        System.out.println("Authenticated user: " + username);
    } catch (Exception e) {
        System.out.println("Invalid token");
    }
}

public void bad_case_7(HttpServletRequest request) {
    // Pac4j JWT library - Parsing JWT without signature verification
    String token = request.getHeader("Authorization").replace("Bearer ", "");
    
    try {
        // ruleid: java-insecure-jwt-parsing
        JwtAuthenticator jwtAuthenticator = new JwtAuthenticator();
        jwtAuthenticator.setSignatureConfiguration(null); // No signature verification
        
        CommonProfile profile = jwtAuthenticator.validateToken(token);
        String username = profile.getId();
        System.out.println("Authenticated user: " + username);
    } catch (Exception e) {
        System.out.println("Invalid token");
    }
}

public void bad_case_8(HttpServletRequest request) {
    // Google API Client - JWT parsing without signature verification
    String token = request.getHeader("Authorization").replace("Bearer ", "");
    
    try {
        JsonFactory jsonFactory = new GsonFactory();
        HttpTransport transport = new NetHttpTransport();
        
        // ruleid: java-insecure-jwt-parsing
        com.google.api.client.json.webtoken.JsonWebSignature jws = 
            com.google.api.client.json.webtoken.JsonWebSignature.parse(jsonFactory, token);
        
        // No verification is performed
        String username = (String) jws.getPayload().get("sub");
        System.out.println("Authenticated user: " + username);
    } catch (Exception e) {
        System.out.println("Invalid token");
    }
}

public void bad_case_9(HttpServletRequest request) {
    // JJWT library with custom deserializer - Parsing JWT without signature verification
    String token = request.getHeader("Authorization").replace("Bearer ", "");
    
    try {
        Deserializer<Map<String, ?>> deserializer = new JacksonDeserializer<>();
        
        // ruleid: java-insecure-jwt-parsing
        Claims claims = Jwts.parserBuilder()
            .deserializeJsonWith(deserializer)
            .build()
            .parse(token)
            .getBody();
        
        String username = claims.getSubject();
        System.out.println("Authenticated user: " + username);
    } catch (Exception e) {
        System.out.println("Invalid token");
    }
}

public void bad_case_10(@RequestParam String token) {
    // Nimbus JOSE+JWT library with PlainJWT - Parsing JWT without signature verification
    try {
        // ruleid: java-insecure-jwt-parsing
        PlainJWT jwt = PlainJWT.parse(token);
        JWTClaimsSet claimsSet = jwt.getJWTClaimsSet();
        
        String username = claimsSet.getSubject();
        System.out.println("Authenticated user: " + username);
    } catch (Exception e) {
        System.out.println("Invalid token");
    }
}

public void bad_case_11(@RequestHeader("Authorization") String authHeader) {
    // JJWT library with relaxed parsing - Parsing JWT without signature verification
    String token = authHeader.replace("Bearer ", "");
    
    try {
        // ruleid: java-insecure-jwt-parsing
        Claims claims = Jwts.parserBuilder()
            .setAllowedClockSkewSeconds(300)
            .build()
            .parse(token)
            .getBody();
        
        String username = claims.getSubject();
        System.out.println("Authenticated user: " + username);
    } catch (Exception e) {
        System.out.println("Invalid token");
    }
}

public void bad_case_12(@RequestBody Map<String, String> payload) {
    // Auth0 JWT library with custom parsing - Parsing JWT without signature verification
    String token = payload.get("token");
    
    try {
        // ruleid: java-insecure-jwt-parsing
        com.auth0.jwt.interfaces.DecodedJWT jwt = JWT.decode(token);
        Map<String, com.auth0.jwt.interfaces.Claim> claims = jwt.getClaims();
        
        String username = claims.get("sub").asString();
        System.out.println("Authenticated user: " + username);
    } catch (Exception e) {
        System.out.println("Invalid token");
    }
}

public void bad_case_13(HttpServletRequest request) {
    // Keycloak TokenVerifier - Parsing JWT without signature verification
    String token = request.getHeader("Authorization").replace("Bearer ", "");
    
    try {
        // ruleid: java-insecure-jwt-parsing
        TokenVerifier<AccessToken> verifier = TokenVerifier.create(token, AccessToken.class)
            .withChecks()
            .checkActive()
            .checkRealmUrl("https://example.org/auth/realms/master")
            .checkTokenType("access");
        // Note: No signature verification configured
        
        AccessToken accessToken = verifier.getToken();
        String username = accessToken.getPreferredUsername();
        System.out.println("Authenticated user: " + username);
    } catch (VerificationException e) {
        System.out.println("Invalid token");
    }
}

public void bad_case_14(HttpServletRequest request) {
    // Vert.x JWT - Parsing JWT without signature verification
    String token = request.getHeader("Authorization").replace("Bearer ", "");
    
    try {
        // ruleid: java-insecure-jwt-parsing
        io.vertx.core.json.JsonObject tokenJson = new io.vertx.core.json.JsonObject()
            .put("token", token);
        
        // No verification is performed
        String[] parts = token.split("\\.");
        String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
        JsonObject claims = new JsonObject(payload);
        
        String username = claims.getString("sub");
        System.out.println("Authenticated user: " + username);
    } catch (Exception e) {
        System.out.println("Invalid token");
    }
}

public void bad_case_15(HttpServletRequest request) {
    // Manual JWT parsing without signature verification
    String token = request.getHeader("Authorization").replace("Bearer ", "");
    
    try {
        // ruleid: java-insecure-jwt-parsing
        String[] parts = token.split("\\.");
        if (parts.length < 2) {
            throw new IllegalArgumentException("Invalid token format");
        }
        
        String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));
        // No signature verification performed
        
        // Using a JSON library to parse the payload
        org.json.JSONObject claims = new org.json.JSONObject(payload);
        String username = claims.getString("sub");
        System.out.println("Authenticated user: " + username);
    } catch (Exception e) {
        System.out.println("Invalid token");
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) {
    // JJWT library - Secure JWT parsing with signature verification
    String token = request.getHeader("Authorization").replace("Bearer ", "");
    String secret = "mySecretKey123456789012345678901234";
    
    try {
        // ok: java-insecure-jwt-parsing
        Claims claims = Jwts.parserBuilder()
            .setSigningKey(Keys.hmacShaKeyFor(secret.getBytes()))
            .build()
            .parseClaimsJws(token)
            .getBody();
        
        String username = claims.getSubject();
        System.out.println("Authenticated user: " + username);
    } catch (Exception e) {
        System.out.println("Invalid token");
    }
}

public void good_case_2(HttpServletRequest request) {
    // Nimbus JOSE+JWT library - Secure JWT parsing with signature verification
    String token = request.getHeader("Authorization").replace("Bearer ", "");
    String secret = "mySecretKey123456789012345678901234";
    
    try {
        SignedJWT signedJWT = SignedJWT.parse(token);
        JWSVerifier verifier = new MAC_REDACTED_TWILIO_ID(secret);
        
        // ok: java-insecure-jwt-parsing
        boolean verified = signedJWT.verify(verifier);
        if (verified) {
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            String username = claimsSet.getSubject();
            System.out.println("Authenticated user: " + username);
        } else {
            System.out.println("Token signature verification failed");
        }
    } catch (Exception e) {
        System.out.println("Invalid token");
    }
}

public void good_case_3(HttpServletRequest request) {
    // Auth0 JWT library - Secure JWT parsing with signature verification
    String token = request.getHeader("Authorization").replace("Bearer ", "");
    String secret = "mySecretKey123456789012345678901234";
    
    try {
        Algorithm algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID(secret);
        JWTVerifier verifier = JWT.require(algorithm)
            .withIssuer("auth0")
            .build();
        
        // ok: java-insecure-jwt-parsing
        DecodedJWT jwt = verifier.verify(token);
        
        String username = jwt.getSubject();
        System.out.println("Authenticated user: " + username);
    } catch (Exception e) {
        System.out.println("Invalid token");
    }
}

public void good_case_4(HttpServletRequest request) {
    // Apache CXF RS Security - Secure JWT parsing with signature verification
    String token = request.getHeader("Authorization").replace("Bearer ", "");
    String secret = "mySecretKey123456789012345678901234";
    
    try {
        JwsJwtCompactConsumer consumer = new JwsJwtCompactConsumer(token);
        JwsSignatureVerifier signatureVerifier = new HmacJwsSignatureVerifier(
            secret.getBytes(), SignatureAlgorithm.HS256);
        
        // ok: java-insecure-jwt-parsing
        boolean isValid = consumer.verifySignatureWith(signatureVerifier);
        
        if (isValid) {
            org.apache.cxf.rs.security.jose.jwt.JwtToken jwt = consumer.getJwtToken();
            String username = jwt.getClaim("sub").toString();
            System.out.println("Authenticated user: " + username);
        } else {
            System.out.println("Token signature verification failed");
        }
    } catch (Exception e) {
        System.out.println("Invalid token");
    }
}

public void good_case_5(HttpServletRequest request) {
    // FusionAuth JWT library - Secure JWT parsing with signature verification
    String token = request.getHeader("Authorization").replace("Bearer ", "");
    String secret = "mySecretKey123456789012345678901234";
    
    try {
        Verifier verifier = HMAC_REDACTED_TWILIO_ID.newVerifier(secret);
        
        // ok: java-insecure-jwt-parsing
        JWT jwt = JWT.getDecoder().decode(token, verifier);
        
        String username = jwt.subject;
        System.out.println("Authenticated user: " + username);
    } catch (Exception e) {
        System.out.println("Invalid token");
    }
}

public void good_case_6(HttpServletRequest request) {
    // JOSE4J library - Secure JWT parsing with signature verification
    String token = request.getHeader("Authorization").replace("Bearer ", "");
    String secret = "mySecretKey123456789012345678901234";
    
    try {
        // ok: java-insecure-jwt-parsing
        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
            .setRequireExpirationTime()
            .setAllowedClockSkewInSeconds(30)
            .setRequireSubject()
            .setVerificationKey(new HmacKey(secret.getBytes()))
            .build();
        
        JwtClaims jwtClaims = jwtConsumer.processToClaims(token);
        String username = jwtClaims.getSubject();
        System.out.println("Authenticated user: " + username);
    } catch (Exception e) {
        System.out.println("Invalid token");
    }
}

public void good_case_7(HttpServletRequest request) {
    // Pac4j JWT library - Secure JWT parsing with signature verification
    String token = request.getHeader("Authorization").replace("Bearer ", "");
    String secret = "mySecretKey123456789012345678901234";
    
    try {
        SecretSignatureConfiguration signatureConfiguration = 
            new SecretSignatureConfiguration(secret);
        
        JwtAuthenticator jwtAuthenticator = new JwtAuthenticator();
        // ok: java-insecure-jwt-parsing
        jwtAuthenticator.setSignatureConfiguration(signatureConfiguration);
        
        CommonProfile profile = jwtAuthenticator.validateToken(token);
        String username = profile.getId();
        System.out.println("Authenticated user: " + username);
    } catch (Exception e) {
        System.out.println("Invalid token");
    }
}

public void good_case_8(HttpServletRequest request) {
    // Google API Client - Secure JWT parsing with signature verification
    String token = request.getHeader("Authorization").replace("Bearer ", "");
    String secret = "mySecretKey123456789012345678901234";
    
    try {
        JsonFactory jsonFactory = new GsonFactory();
        
        // ok: java-insecure-jwt-parsing
        com.google.api.client.json.webtoken.JsonWebSignature jws = 
            com.google.api.client.json.webtoken.JsonWebSignature.parse(jsonFactory, token);
        
        // Verify the signature
        byte[] keyBytes = secret.getBytes();
        if (!jws.verifySignature(keyBytes)) {
            throw new SecurityException("Invalid token signature");
        }
        
        String username = (String) jws.getPayload().get("sub");
        System.out.println("Authenticated user: " + username);
    } catch (Exception e) {
        System.out.println("Invalid token");
    }
}

public void good_case_9(HttpServletRequest request) {
    // JJWT library with custom deserializer - Secure JWT parsing with signature verification
    String token = request.getHeader("Authorization").replace("Bearer ", "");
    String secret = "mySecretKey123456789012345678901234";
    
    try {
        Deserializer<Map<String, ?>> deserializer = new JacksonDeserializer<>();
        
        // ok: java-insecure-jwt-parsing
        Claims claims = Jwts.parserBuilder()
            .deserializeJsonWith(deserializer)
            .setSigningKey(Keys.hmacShaKeyFor(secret.getBytes()))
            .build()
            .parseClaimsJws(token)
            .getBody();
        
        String username = claims.getSubject();
        System.out.println("Authenticated user: " + username);
    } catch (Exception e) {
        System.out.println("Invalid token");
    }
}

public void good_case_10(@RequestParam String token) {
    // Spring Security OAuth2 - Secure JWT parsing with signature verification
    String issuerUri = "https://example.com";
    
    try {
        // ok: java-insecure-jwt-parsing
        JwtDecoder jwtDecoder = JwtDecoders.fromIssuerLocation(issuerUri);
        Jwt jwt = jwtDecoder.decode(token);
        
        String username = jwt.getSubject();
        System.out.println("Authenticated user: " + username);
    } catch (Exception e) {
        System.out.println("Invalid token");
    }
}

public void good_case_11(@RequestHeader("Authorization") String authHeader) {
    // JJWT library with full verification - Secure JWT parsing with signature verification
    String token = authHeader.replace("Bearer ", "");
    String secret = "mySecretKey123456789012345678901234";
    
    try {
        // ok: java-insecure-jwt-parsing
        Claims claims = Jwts.parserBuilder()
            .setSigningKey(Keys.hmacShaKeyFor(secret.getBytes()))
            .setAllowedClockSkewSeconds(300)
            .requireIssuer("auth-service")
            .build()
            .parseClaimsJws(token)
            .getBody();
        
        String username = claims.getSubject();
        System.out.println("Authenticated user: " + username);
    } catch (Exception e) {
        System.out.println("Invalid token");
    }
}

public void good_case_12(@RequestBody Map<String, String> payload) {
    // Okta JWT - Secure JWT parsing with signature verification
    String token = payload.get("token");
    
    try {
        AccessTokenVerifier accessTokenVerifier = JwtVerifiers.accessTokenVerifierBuilder()
            .setIssuer("https://example.okta.com/oauth2/default")
            .build();
        
        // ok: java-insecure-jwt-parsing
        Jwt jwt = accessTokenVerifier.decode(token);
        
        String username = jwt.getClaims().get("sub").toString();
        System.out.println("Authenticated user: " + username);
    } catch (Exception e) {
        System.out.println("Invalid token");
    }
}

public void good_case_13(HttpServletRequest request) {
    // Keycloak TokenVerifier - Secure JWT parsing with signature verification
    String token = request.getHeader("Authorization").replace("Bearer ", "");
    String publicKeyString = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlivFI8qB4D0y2jy0CfEqFyy46R0o7S8TKpsx5xbHKoU1VWg6QkQm+ntyIv1p4kE1sPEQO73+HY8+Bzs75XwRTYL1BmR1w8J5hmjVWjc6R2BTBGAYRPFRhor3kpM6ni2SPmNNhurEAHw7TaqszP5eUF/F9+KEBWkwVta+PZ37bwqSE4sCb1soZFrVz/UT/LF4tYpuVYt3YbqToZ3pZOZ9AX2o1GCG3xwOjkc4x0W7ezbQZdC9iftPxVHR8irOijJRRjcPDtA6vPKpzLl6CyYnsIYPd99ltwxTHjr3npfv/3Lw50bAkbT4HeLFxTx4flEoZLKO/g0bAoV2uqBhkA9xnQIDAQAB";
    
    try {
        // Convert the public key string to a PublicKey object
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyString);
        java.security.spec.X509EncodedKeySpec keySpec = new java.security.spec.X509EncodedKeySpec(publicKeyBytes);
        java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
        java.security.PublicKey publicKey = keyFactory.generatePublic(keySpec);
        
        // ok: java-insecure-jwt-parsing
        TokenVerifier<AccessToken> verifier = TokenVerifier.create(token, AccessToken.class)
            .withChecks()
            .checkActive()
            .checkRealmUrl("https://example.org/auth/realms/master")
            .checkTokenType("access")
            .publicKey(publicKey);
        
        verifier.verify();
        AccessToken accessToken = verifier.getToken();
        String username = accessToken.getPreferredUsername();
        System.out.println("Authenticated user: " + username);
    } catch (VerificationException e) {
        System.out.println("Invalid token");
    } catch (Exception e) {
        System.out.println("Error verifying token");
    }
}

public void good_case_14(HttpServletRequest request) {
    // Vert.x JWT - Secure JWT parsing with signature verification
    String token = request.getHeader("Authorization").replace("Bearer ", "");
    
    try {
        // Create JWT auth provider
        JWTAuthOptions config = new JWTAuthOptions()
            .addPubSecKey(new io.vertx.core.json.JsonObject()
                .put("algorithm", "HS256")
                .put("symmetric", true)
                .put("secret", "mySecretKey123456789012345678901234"));
        
        JWTAuth provider = JWTAuth.create(null, config);
        
        // ok: java-insecure-jwt-parsing
        provider.authenticate(new io.vertx.core.json.JsonObject()
            .put("token", token), result -> {
                if (result.succeeded()) {
                    io.vertx.ext.auth.User user = result.result();
                    String username = user.principal().getString("sub");
                    System.out.println("Authenticated user: " + username);
                } else {
                    System.out.println("Invalid token");
                }
            });
    } catch (Exception e) {
        System.out.println("Error verifying token");
    }
}

public void good_case_15(HttpServletRequest request) {
    // Manual JWT parsing with signature verification
    String token = request.getHeader("Authorization").replace("Bearer ", "");
    String secret = "mySecretKey123456789012345678901234";
    
    try {
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Invalid token format");
        }
        
        // Get the signature from the token
        String tokenSignature = parts[2];
        
        // Create a new signature based on the header and payload
        String headerAndPayload = parts[0] + "." + parts[1];
        
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] signatureBytes = mac.doFinal(headerAndPayload.getBytes());
        String calculatedSignature = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(signatureBytes);
        
        // ok: java-insecure-jwt-parsing
        if (!calculatedSignature.equals(tokenSignature)) {
            throw new SecurityException("Invalid token signature");
        }
        
        // If signature is valid, decode the payload
        String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));
        org.json.JSONObject claims = new org.json.JSONObject(payload);
        String username = claims.getString("sub");
        System.out.println("Authenticated user: " + username);
    } catch (Exception e) {
        System.out.println("Invalid token");
    }
}