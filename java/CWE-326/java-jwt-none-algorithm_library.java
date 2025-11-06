import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.interfaces.DecodedJWT;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import io.fusionauth.jwt.Signer;
import io.fusionauth.jwt.Verifier;
import io.fusionauth.jwt.domain.JWT as FusionJWT;
import io.fusionauth.jwt.hmac.HMAC_REDACTED_TWILIO_ID;
import io.fusionauth.jwt.hmac.HMAC_REDACTED_TWILIO_ID;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.HmacKey;
import java.security.Key;
import java.util.Date;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.http.ResponseEntity;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.JWTAuthHandler;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;
import io.vertx.core.json.JsonObject;
import spark.Request;
import spark.Response;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MAC_REDACTED_TWILIO_ID;
import com.nimbusds.jose.crypto.MAC_REDACTED_TWILIO_ID;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import java.util.Collections;
import org.pac4j.jwt.config.signature.SecretSignatureConfiguration;
import org.pac4j.jwt.profile.JwtGenerator;
import org.pac4j.core.profile.CommonProfile;
import org.pac4j.jwt.credentials.authenticator.JwtAuthenticator;
import pasetolib.Paseto;
import pasetolib.Version;
import pasetolib.Purpose;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.AccessToken;
import io.smallrye.jwt.build.Jwt;
import io.smallrye.jwt.auth.principal.JWTParser;
import io.smallrye.jwt.auth.principal.ParseException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.JwtParserBuilder;
import com.okta.jwt.JwtVerifier;
import com.okta.jwt.JwtVerifiers;
import org.springframework.security.jwt.Jwt as SpringJwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.MacSigner;
import org.springframework.security.jwt.crypto.sign.NoneSignerVerifier;

// Security Issue: Using the "none" algorithm in JWT libraries allows attackers to bypass signature verification

// True Positive Examples (Vulnerable/Insecure Code)
public void bad_case_1(HttpServletRequest request) {
    // Auth0 JWT library - accepting none algorithm
    String token = request.getHeader("Authorization").replace("Bearer ", "");
    try {
        // ruleid: java-jwt-none-algorithm
        Algorithm algorithm = Algorithm.NONE;
        JWTVerifier verifier = JWT.require(algorithm).build();
        DecodedJWT jwt = verifier.verify(token);
        System.out.println("Valid token: " + jwt.getSubject());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_2(HttpServletRequest request) {
    // JJWT library - using none algorithm for signing
    String userId = request.getParameter("userId");
    
    // ruleid: java-jwt-none-algorithm
    String token = Jwts.builder()
        .setSubject(userId)
        .setIssuedAt(new Date())
        .setExpiration(new Date(System.currentTimeMillis() + 3600000))
        .signWith(SignatureAlgorithm.NONE)
        .compact();
    
    System.out.println("Generated token: " + token);
}

public void bad_case_3(HttpServletRequest request) {
    // Jose4j library - using none algorithm
    String userId = request.getParameter("userId");
    
    try {
        JwtClaims claims = new JwtClaims();
        claims.setSubject(userId);
        claims.setIssuedAtToNow();
        claims.setExpirationTimeMinutesInTheFuture(60);
        
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        
        // ruleid: java-jwt-none-algorithm
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.NONE);
        
        String jwt = jws.getCompactSerialization();
        System.out.println("Generated token: " + jwt);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_4(HttpServletRequest request) {
    // Nimbus JOSE+JWT library - using none algorithm
    String userId = request.getParameter("userId");
    
    try {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
            .subject(userId)
            .issueTime(new Date())
            .expirationTime(new Date(System.currentTimeMillis() + 3600000))
            .build();
        
        // ruleid: java-jwt-none-algorithm
        JWSHeader header = new JWSHeader(JWSAlgorithm.NONE);
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        
        // No actual signing needed with NONE algorithm
        String jwt = signedJWT.serialize();
        System.out.println("Generated token: " + jwt);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_5(HttpServletRequest request) {
    // Spring Security JWT - using none algorithm
    String userId = request.getParameter("userId");
    String claims = "{\"sub\":\"" + userId + "\",\"exp\":" + (System.currentTimeMillis() + 3600000) / 1000 + "}";
    
    // ruleid: java-jwt-none-algorithm
    SpringJwt jwt = JwtHelper.encode(claims, new NoneSignerVerifier());
    
    String token = jwt.getEncoded();
    System.out.println("Generated token: " + token);
}

public void bad_case_6(HttpServletRequest request) {
    // Vert.x JWT Auth - configuring to accept none algorithm
    String secretKey = "your-secret-key";
    
    JsonObject config = new JsonObject()
        .put("keyStore", new JsonObject()
            .put("type", "jceks")
            .put("path", "keystore.jceks")
            .put("password", secretKey));
    
    // ruleid: java-jwt-none-algorithm
    config.put("acceptableAlgorithms", new JsonObject().put("none", true));
    
    JWTAuth provider = JWTAuth.create(null, new JWTAuthOptions(config));
    // This would allow tokens with "none" algorithm to be accepted
}

public void bad_case_7(HttpServletRequest request) {
    // Pac4j JWT - accepting none algorithm
    String token = request.getHeader("Authorization").replace("Bearer ", "");
    String secretKey = "your-secret-key";
    
    // ruleid: java-jwt-none-algorithm
    JwtAuthenticator authenticator = new JwtAuthenticator();
    authenticator.addSignatureConfiguration(new SecretSignatureConfiguration(secretKey));
    authenticator.setAllowUnsignedToken(true); // Allows "none" algorithm
    
    authenticator.validate(token);
}

public void bad_case_8(HttpServletRequest request) {
    // Keycloak token verification - accepting none algorithm
    String token = request.getHeader("Authorization").replace("Bearer ", "");
    
    try {
        // ruleid: java-jwt-none-algorithm
        TokenVerifier<AccessToken> verifier = TokenVerifier.create(token, AccessToken.class)
            .withChecks()
            .acceptsAnyAlgorithm(); // This accepts the "none" algorithm
        
        AccessToken accessToken = verifier.verify().getToken();
        System.out.println("Valid token for: " + accessToken.getSubject());
    } catch (VerificationException e) {
        e.printStackTrace();
    }
}

public void bad_case_9(HttpServletRequest request) {
    // SmallRye JWT - accepting none algorithm
    String token = request.getHeader("Authorization").replace("Bearer ", "");
    
    try {
        // ruleid: java-jwt-none-algorithm
        JWTParser parser = JWTParser.builder().allowNoSignature(true).build();
        
        io.smallrye.jwt.auth.principal.JWTCallerPrincipal principal = parser.parse(token);
        System.out.println("Valid token for: " + principal.getName());
    } catch (ParseException e) {
        e.printStackTrace();
    }
}

public void bad_case_10(HttpServletRequest request) {
    // JJWT library - parser accepting none algorithm
    String token = request.getHeader("Authorization").replace("Bearer ", "");
    
    // ruleid: java-jwt-none-algorithm
    JwtParser parser = Jwts.parserBuilder()
        .setAllowedClockSkewSeconds(60)
        .setSigningKey(new byte[0]) // Empty key for none algorithm
        .build();
    
    parser.parseClaimsJws(token);
}

public void bad_case_11(HttpServletRequest request) {
    // Okta JWT - accepting none algorithm
    String token = request.getHeader("Authorization").replace("Bearer ", "");
    
    try {
        // ruleid: java-jwt-none-algorithm
        com.okta.jwt.JwtVerifier verifier = JwtVerifiers.accessTokenVerifierBuilder()
            .setIssuer("https://example.okta.com/oauth2/default")
            .setAudience("api://default")
            .setConnectionTimeout(1000)
            .setReadTimeout(1000)
            .setSkipSignatureVerification(true) // Effectively accepts "none" algorithm
            .build();
        
        verifier.decode(token);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_12(HttpServletRequest request) {
    // FusionAuth JWT - accepting none algorithm
    String token = request.getHeader("Authorization").replace("Bearer ", "");
    
    try {
        // ruleid: java-jwt-none-algorithm
        Verifier verifier = null; // No verifier means no signature check
        FusionJWT jwt = FusionJWT.getDecoder().decode(token, verifier);
        
        System.out.println("Valid token for: " + jwt.subject);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_13(HttpServletRequest request) {
    // Spring Security OAuth2 - accepting none algorithm
    String issuerUri = "https://example.com";
    
    // ruleid: java-jwt-none-algorithm
    JwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(issuerUri)
        .jwtProcessorCustomizer(customizer -> {
            customizer.setJWSTypeVerifier(null); // Disables algorithm verification
        })
        .build();
    
    // This decoder would accept tokens with "none" algorithm
}

public void bad_case_14(HttpServletRequest request) {
    // Auth0 JWT library - accepting any algorithm including none
    String token = request.getHeader("Authorization").replace("Bearer ", "");
    String secretKey = "your-secret-key";
    
    try {
        // ruleid: java-jwt-none-algorithm
        DecodedJWT jwt = JWT.decode(token); // No verification, accepts any algorithm including none
        
        System.out.println("Token subject: " + jwt.getSubject());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_15(HttpServletRequest request) {
    // Jose4j library - accepting none algorithm in consumer
    String token = request.getHeader("Authorization").replace("Bearer ", "");
    
    try {
        // ruleid: java-jwt-none-algorithm
        JwtConsumer consumer = new JwtConsumerBuilder()
            .setSkipSignatureVerification() // Accepts "none" algorithm
            .setRequireExpirationTime()
            .setAllowedClockSkewInSeconds(30)
            .build();
        
        JwtClaims claims = consumer.processToClaims(token);
        System.out.println("Valid token for: " + claims.getSubject());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

// True Negative Examples (Safe/Secure Code)
public void good_case_1(HttpServletRequest request) {
    // Auth0 JWT library - proper algorithm usage
    String token = request.getHeader("Authorization").replace("Bearer ", "");
    String secretKey = "your-secret-key";
    
    try {
        // ok: java-jwt-none-algorithm
        Algorithm algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID(secretKey);
        JWTVerifier verifier = JWT.require(algorithm)
            .withIssuer("auth0")
            .build();
        DecodedJWT jwt = verifier.verify(token);
        System.out.println("Valid token: " + jwt.getSubject());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_2(HttpServletRequest request) {
    // JJWT library - proper algorithm usage
    String userId = request.getParameter("userId");
    String secretKey = "your-secret-key";
    
    // ok: java-jwt-none-algorithm
    String token = Jwts.builder()
        .setSubject(userId)
        .setIssuedAt(new Date())
        .setExpiration(new Date(System.currentTimeMillis() + 3600000))
        .signWith(Keys.hmacShaKeyFor(secretKey.getBytes()), SignatureAlgorithm.HS256)
        .compact();
    
    System.out.println("Generated token: " + token);
}

public void good_case_3(HttpServletRequest request) {
    // Jose4j library - proper algorithm usage
    String userId = request.getParameter("userId");
    String secretKey = "your-secret-key";
    
    try {
        JwtClaims claims = new JwtClaims();
        claims.setSubject(userId);
        claims.setIssuedAtToNow();
        claims.setExpirationTimeMinutesInTheFuture(60);
        
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        
        // ok: java-jwt-none-algorithm
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_REDACTED_TWILIO_ID_SHA256);
        jws.setKey(new HmacKey(secretKey.getBytes()));
        
        String jwt = jws.getCompactSerialization();
        System.out.println("Generated token: " + jwt);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_4(HttpServletRequest request) {
    // Nimbus JOSE+JWT library - proper algorithm usage
    String userId = request.getParameter("userId");
    String secretKey = "your-secret-key";
    
    try {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
            .subject(userId)
            .issueTime(new Date())
            .expirationTime(new Date(System.currentTimeMillis() + 3600000))
            .build();
        
        // ok: java-jwt-none-algorithm
        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        
        JWSSigner signer = new MAC_REDACTED_TWILIO_ID(secretKey.getBytes());
        signedJWT.sign(signer);
        
        String jwt = signedJWT.serialize();
        System.out.println("Generated token: " + jwt);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_5(HttpServletRequest request) {
    // Spring Security JWT - proper algorithm usage
    String userId = request.getParameter("userId");
    String secretKey = "your-secret-key";
    String claims = "{\"sub\":\"" + userId + "\",\"exp\":" + (System.currentTimeMillis() + 3600000) / 1000 + "}";
    
    // ok: java-jwt-none-algorithm
    SpringJwt jwt = JwtHelper.encode(claims, new MacSigner(secretKey));
    
    String token = jwt.getEncoded();
    System.out.println("Generated token: " + token);
}

public void good_case_6(HttpServletRequest request) {
    // Vert.x JWT Auth - proper configuration
    String secretKey = "your-secret-key";
    
    JsonObject config = new JsonObject()
        .put("keyStore", new JsonObject()
            .put("type", "jceks")
            .put("path", "keystore.jceks")
            .put("password", secretKey));
    
    // ok: java-jwt-none-algorithm
    config.put("acceptableAlgorithms", new JsonObject().put("HS256", true));
    
    JWTAuth provider = JWTAuth.create(null, new JWTAuthOptions(config));
    // This only allows tokens with HS256 algorithm
}

public void good_case_7(HttpServletRequest request) {
    // Pac4j JWT - proper algorithm usage
    String token = request.getHeader("Authorization").replace("Bearer ", "");
    String secretKey = "your-secret-key";
    
    // ok: java-jwt-none-algorithm
    JwtAuthenticator authenticator = new JwtAuthenticator();
    authenticator.addSignatureConfiguration(new SecretSignatureConfiguration(secretKey));
    authenticator.setAllowUnsignedToken(false); // Disallows "none" algorithm
    
    authenticator.validate(token);
}

public void good_case_8(HttpServletRequest request) {
    // Keycloak token verification - proper algorithm usage
    String token = request.getHeader("Authorization").replace("Bearer ", "");
    String secretKey = "your-secret-key";
    
    try {
        // ok: java-jwt-none-algorithm
        TokenVerifier<AccessToken> verifier = TokenVerifier.create(token, AccessToken.class)
            .withChecks()
            .publicKey(null) // Would be a proper key in real implementation
            .realmUrl("https://example.com/auth/realms/master");
        
        AccessToken accessToken = verifier.verify().getToken();
        System.out.println("Valid token for: " + accessToken.getSubject());
    } catch (VerificationException e) {
        e.printStackTrace();
    }
}

public void good_case_9(HttpServletRequest request) {
    // SmallRye JWT - proper algorithm usage
    String token = request.getHeader("Authorization").replace("Bearer ", "");
    
    try {
        // ok: java-jwt-none-algorithm
        JWTParser parser = JWTParser.builder().allowNoSignature(false).build();
        
        io.smallrye.jwt.auth.principal.JWTCallerPrincipal principal = parser.parse(token);
        System.out.println("Valid token for: " + principal.getName());
    } catch (ParseException e) {
        e.printStackTrace();
    }
}

public void good_case_10(HttpServletRequest request) {
    // JJWT library - parser with proper algorithm
    String token = request.getHeader("Authorization").replace("Bearer ", "");
    String secretKey = "your-secret-key";
    
    // ok: java-jwt-none-algorithm
    JwtParser parser = Jwts.parserBuilder()
        .setAllowedClockSkewSeconds(60)
        .setSigningKey(Keys.hmacShaKeyFor(secretKey.getBytes()))
        .build();
    
    parser.parseClaimsJws(token);
}

public void good_case_11(HttpServletRequest request) {
    // Okta JWT - proper algorithm usage
    String token = request.getHeader("Authorization").replace("Bearer ", "");
    
    try {
        // ok: java-jwt-none-algorithm
        com.okta.jwt.JwtVerifier verifier = JwtVerifiers.accessTokenVerifierBuilder()
            .setIssuer("https://example.okta.com/oauth2/default")
            .setAudience("api://default")
            .setConnectionTimeout(1000)
            .setReadTimeout(1000)
            .setSkipSignatureVerification(false) // Enforces signature verification
            .build();
        
        verifier.decode(token);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_12(HttpServletRequest request) {
    // FusionAuth JWT - proper algorithm usage
    String token = request.getHeader("Authorization").replace("Bearer ", "");
    String secretKey = "your-secret-key";
    
    try {
        // ok: java-jwt-none-algorithm
        Verifier verifier = HMAC_REDACTED_TWILIO_ID.newVerifier(secretKey);
        FusionJWT jwt = FusionJWT.getDecoder().decode(token, verifier);
        
        System.out.println("Valid token for: " + jwt.subject);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_13(HttpServletRequest request) {
    // Spring Security OAuth2 - proper algorithm usage
    String issuerUri = "https://example.com";
    
    // ok: java-jwt-none-algorithm
    JwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(issuerUri)
        .jwtProcessorCustomizer(customizer -> {
            customizer.setJWTClaimsSetVerifier(JwtValidators.createDefaultWithIssuer(issuerUri));
        })
        .build();
    
    // This decoder enforces proper algorithm verification
}

public void good_case_14(HttpServletRequest request) {
    // Auth0 JWT library - proper verification
    String token = request.getHeader("Authorization").replace("Bearer ", "");
    String secretKey = "your-secret-key";
    
    try {
        // ok: java-jwt-none-algorithm
        Algorithm algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID(secretKey);
        JWTVerifier verifier = JWT.require(algorithm).build();
        DecodedJWT jwt = verifier.verify(token); // Proper verification
        
        System.out.println("Token subject: " + jwt.getSubject());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_15(HttpServletRequest request) {
    // Jose4j library - proper algorithm usage in consumer
    String token = request.getHeader("Authorization").replace("Bearer ", "");
    String secretKey = "your-secret-key";
    
    try {
        // ok: java-jwt-none-algorithm
        JwtConsumer consumer = new JwtConsumerBuilder()
            .setRequireExpirationTime()
            .setAllowedClockSkewInSeconds(30)
            .setVerificationKey(new HmacKey(secretKey.getBytes()))
            .build();
        
        JwtClaims claims = consumer.processToClaims(token);
        System.out.println("Valid token for: " + claims.getSubject());
    } catch (Exception e) {
        e.printStackTrace();
    }
}