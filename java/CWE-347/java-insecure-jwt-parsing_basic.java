import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.JwtParserBuilder;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.SignatureException;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.WeakKeyException;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Base64;

public class JwtSecurityExamples {

    private static final String SECRET_KEY = "thisIsAVeryLongSecretKeyUsedForSigningJwtTokens123456789012345678901234";
    
    // True Positive Examples (Vulnerable Code)
    
// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
    public void bad_case_1() {
        String jwtToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        
        // ruleid: java-insecure-jwt-parsing
        Claims claims = Jwts.parser().parse(jwtToken).getBody();
        
        String username = claims.get("name", String.class);
        System.out.println("Username: " + username);
    }
    
    public void bad_case_2() {
        String jwtToken = getTokenFromRequest();
        
        // ruleid: java-insecure-jwt-parsing
        Claims claims = Jwts.parser()
                .setAllowedClockSkewSeconds(60)
                .parse(jwtToken)
                .getBody();
        
        processUserData(claims);
    }
    
    public void bad_case_3() {
        String authHeader = getAuthorizationHeader();
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String jwtToken = authHeader.substring(7);
            
            try {
                // ruleid: java-insecure-jwt-parsing
                Object parsedJwt = Jwts.parser().parse(jwtToken);
                Claims claims = ((io.jsonwebtoken.Jwt) parsedJwt).getBody();
                authenticateUser(claims);
            } catch (Exception e) {
                System.out.println("Invalid token");
            }
        }
    }
    
    public void bad_case_4() {
        JwtParser parser = Jwts.parser();
        String token = getCookieValue("auth_token");
        
        try {
            // ruleid: java-insecure-jwt-parsing
            io.jsonwebtoken.Jwt jwt = parser.parse(token);
            Claims claims = (Claims) jwt.getBody();
            grantAccess(claims.getSubject());
        } catch (Exception e) {
            handleError(e);
        }
    }
    
    public void bad_case_5() {
        Map<String, Object> userInfo = new HashMap<>();
        String token = getQueryParam("token");
        
        // ruleid: java-insecure-jwt-parsing
        io.jsonwebtoken.Jwt parsedToken = Jwts.parser()
                .parse(token);
        
        userInfo.put("user", parsedToken.getBody());
        processUserInfo(userInfo);
    }
    
    public void bad_case_6() {
        String[] tokens = getAllTokensFromSession();
        
        for (String token : tokens) {
            try {
                // ruleid: java-insecure-jwt-parsing
                Claims claims = (Claims) Jwts.parser().parse(token).getBody();
                if (isAdmin(claims)) {
                    grantAdminAccess();
                    break;
                }
            } catch (Exception e) {
                continue;
            }
        }
    }
    
    public void bad_case_7() {
        String refreshToken = getRefreshToken();
        JwtParser jwtParser = Jwts.parser();
        
        try {
            // ruleid: java-insecure-jwt-parsing
            io.jsonwebtoken.Jwt jwt = jwtParser.parse(refreshToken);
            Claims claims = (Claims) jwt.getBody();
            String newToken = generateNewToken(claims.getSubject());
            sendResponse(newToken);
        } catch (Exception e) {
            denyRefresh();
        }
    }
    
    public void bad_case_8() {
        JwtParserBuilder builder = Jwts.parserBuilder();
        String token = getHeaderValue("X-Auth-Token");
        
        // ruleid: java-insecure-jwt-parsing
        io.jsonwebtoken.Jwt jwt = builder.build().parse(token);
        
        Claims claims = (Claims) jwt.getBody();
        validateUserPermissions(claims);
    }
    
    public void bad_case_9() {
        String impersonationToken = getImpersonationToken();
        
        try {
            // ruleid: java-insecure-jwt-parsing
            Claims claims = Jwts.parser()
                    .parse(impersonationToken)
                    .getBody();
            
            String originalUser = claims.getSubject();
            String impersonatedUser = claims.get("impersonate", String.class);
            switchUserContext(originalUser, impersonatedUser);
        } catch (Exception e) {
            rejectImpersonation();
        }
    }
    
    public void bad_case_10() {
        String ssoToken = getSsoToken();
        JwtParser parser = Jwts.parser();
        
        try {
            // ruleid: java-insecure-jwt-parsing
            Object parsed = parser.parse(ssoToken);
            Claims body = ((io.jsonwebtoken.Jwt) parsed).getBody();
            createLocalSession(body);
        } catch (Exception e) {
            redirectToLogin();
        }
    }
    
    public void bad_case_11() {
        String token = getApiKey();
        
        // ruleid: java-insecure-jwt-parsing
        io.jsonwebtoken.Jwt jwt = Jwts.parserBuilder()
                .build()
                .parse(token);
        
        Claims claims = (Claims) jwt.getBody();
        String clientId = claims.get("client_id", String.class);
        rateLimit(clientId);
    }
    
    public void bad_case_12() {
        String federatedToken = getFederatedToken();
        
        try {
            // ruleid: java-insecure-jwt-parsing
            Claims claims = (Claims) Jwts.parser()
                    .parse(federatedToken)
                    .getBody();
            
            String issuer = claims.getIssuer();
            if (trustedIssuers.contains(issuer)) {
                authenticateFederatedUser(claims);
            }
        } catch (Exception e) {
            denyFederatedAccess();
        }
    }
    
    public void bad_case_13() {
        String encryptedPayload = getEncryptedData();
        String jwtKey = getJwtKeyFromHeader();
        
        // First decrypt the JWT key
        String decryptedKey = decryptKey(jwtKey);
        
        // ruleid: java-insecure-jwt-parsing
        Claims claims = Jwts.parser()
                .parse(decryptedKey)
                .getBody();
        
        // Use claims to decrypt the payload
        String decryptedPayload = decryptPayload(encryptedPayload, claims.get("key", String.class));
        processDecryptedData(decryptedPayload);
    }
    
    public void bad_case_14() {
        String serviceToken = getServiceToken();
        JwtParserBuilder builder = Jwts.parserBuilder();
        
        try {
            // ruleid: java-insecure-jwt-parsing
            io.jsonwebtoken.Jwt jwt = builder
                    .setAllowedClockSkewSeconds(300)
                    .build()
                    .parse(serviceToken);
            
            Claims claims = (Claims) jwt.getBody();
            authorizeServiceAccess(claims.get("service_name", String.class));
        } catch (Exception e) {
            denyServiceAccess();
        }
    }
    
    public void bad_case_15() {
        String temporaryToken = getTemporaryAccessToken();
        
        try {
            // ruleid: java-insecure-jwt-parsing
            Object parsed = Jwts.parser().parse(temporaryToken);
            Claims claims = ((io.jsonwebtoken.Jwt) parsed).getBody();
            
            long expirationTime = claims.getExpiration().getTime();
            if (System.currentTimeMillis() < expirationTime) {
                grantTemporaryAccess(claims.getSubject());
            }
        } catch (Exception e) {
            denyTemporaryAccess();
        }
    }
    
    // True Negative Examples (Secure Code)
    
    public void good_case_1() {
        String jwtToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(SECRET_KEY));
        
        try {
            // ok: java-insecure-jwt-parsing
            Jws<Claims> claims = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(jwtToken);
            
            String username = claims.getBody().get("name", String.class);
            System.out.println("Username: " + username);
        } catch (SignatureException e) {
            System.out.println("Invalid signature");
        }
    }
    
    public void good_case_2() {
        String jwtToken = getTokenFromRequest();
        SecretKey key = getSecretKey();
        
        try {
            // ok: java-insecure-jwt-parsing
            Jws<Claims> claims = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .setAllowedClockSkewSeconds(60)
                    .build()
                    .parseClaimsJws(jwtToken);
            
            processUserData(claims.getBody());
        } catch (Exception e) {
            handleJwtException(e);
        }
    }
    
    public void good_case_3() {
        String authHeader = getAuthorizationHeader();
        Key signingKey = getSigningKey();
        
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String jwtToken = authHeader.substring(7);
            
            try {
                // ok: java-insecure-jwt-parsing
                Jws<Claims> claims = Jwts.parserBuilder()
                        .setSigningKey(signingKey)
                        .build()
                        .parseClaimsJws(jwtToken);
                
                authenticateUser(claims.getBody());
            } catch (Exception e) {
                System.out.println("Invalid token: " + e.getMessage());
            }
        }
    }
    
    public void good_case_4() {
        JwtParserBuilder parserBuilder = Jwts.parserBuilder();
        String token = getCookieValue("auth_token");
        SecretKey key = Keys.hmacShaKeyFor(SECRET_KEY.getBytes());
        
        try {
            // ok: java-insecure-jwt-parsing
            Jws<Claims> jws = parserBuilder
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);
            
            grantAccess(jws.getBody().getSubject());
        } catch (ExpiredJwtException e) {
            handleExpiredToken();
        } catch (Exception e) {
            handleError(e);
        }
    }
    
    public void good_case_5() {
        Map<String, Object> userInfo = new HashMap<>();
        String token = getQueryParam("token");
        Key key = getPublicKey();
        
        try {
            // ok: java-insecure-jwt-parsing
            Jws<Claims> parsedToken = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);
            
            userInfo.put("user", parsedToken.getBody());
            processUserInfo(userInfo);
        } catch (Exception e) {
            rejectRequest(e);
        }
    }
    
    public void good_case_6() {
        String[] tokens = getAllTokensFromSession();
        Key signingKey = getSigningKey();
        
        for (String token : tokens) {
            try {
                // ok: java-insecure-jwt-parsing
                Jws<Claims> jws = Jwts.parserBuilder()
                        .setSigningKey(signingKey)
                        .build()
                        .parseClaimsJws(token);
                
                if (isAdmin(jws.getBody())) {
                    grantAdminAccess();
                    break;
                }
            } catch (Exception e) {
                continue;
            }
        }
    }
    
    public void good_case_7() {
        String refreshToken = getRefreshToken();
        SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(SECRET_KEY));
        
        try {
            // ok: java-insecure-jwt-parsing
            Jws<Claims> jws = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .requireIssuer("auth-service")
                    .build()
                    .parseClaimsJws(refreshToken);
            
            String newToken = generateNewToken(jws.getBody().getSubject());
            sendResponse(newToken);
        } catch (Exception e) {
            denyRefresh();
        }
    }
    
    public void good_case_8() {
        JwtParserBuilder builder = Jwts.parserBuilder();
        String token = getHeaderValue("X-Auth-Token");
        Key key = getSigningKeyFromKeyStore();
        
        try {
            // ok: java-insecure-jwt-parsing
            Jws<Claims> jws = builder
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);
            
            validateUserPermissions(jws.getBody());
        } catch (MalformedJwtException e) {
            rejectMalformedToken();
        } catch (SignatureException e) {
            rejectInvalidSignature();
        } catch (ExpiredJwtException e) {
            rejectExpiredToken();
        }
    }
    
    public void good_case_9() {
        String impersonationToken = getImpersonationToken();
        SecretKey key = getImpersonationKey();
        
        try {
            // ok: java-insecure-jwt-parsing
            Jws<Claims> jws = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .requireAudience("impersonation-service")
                    .build()
                    .parseClaimsJws(impersonationToken);
            
            Claims claims = jws.getBody();
            String originalUser = claims.getSubject();
            String impersonatedUser = claims.get("impersonate", String.class);
            switchUserContext(originalUser, impersonatedUser);
        } catch (Exception e) {
            rejectImpersonation();
        }
    }
    
    public void good_case_10() {
        String ssoToken = getSsoToken();
        Key publicKey = getSsoPublicKey();
        
        try {
            // ok: java-insecure-jwt-parsing
            Jws<Claims> jws = Jwts.parserBuilder()
                    .setSigningKey(publicKey)
                    .requireIssuer("sso-provider")
                    .build()
                    .parseClaimsJws(ssoToken);
            
            createLocalSession(jws.getBody());
        } catch (UnsupportedJwtException | MalformedJwtException e) {
            logMalformedToken(e);
            redirectToLogin();
        } catch (SignatureException e) {
            logInvalidSignature(e);
            redirectToLogin();
        } catch (ExpiredJwtException e) {
            requestTokenRefresh();
        }
    }
    
    public void good_case_11() {
        String token = getApiKey();
        SecretKey apiSecret = getApiSecret();
        
        try {
            // ok: java-insecure-jwt-parsing
            Jws<Claims> jws = Jwts.parserBuilder()
                    .setSigningKey(apiSecret)
                    .build()
                    .parseClaimsJws(token);
            
            String clientId = jws.getBody().get("client_id", String.class);
            rateLimit(clientId);
        } catch (WeakKeyException e) {
            rejectWeakKey();
        } catch (SignatureException e) {
            rejectInvalidSignature();
        }
    }
    
    public void good_case_12() {
        String federatedToken = getFederatedToken();
        Map<String, Key> trustedKeys = getTrustedIssuerKeys();
        
        try {
            // First extract issuer without verification to get the right key
            String issuer = Jwts.parserBuilder()
                    .build()
                    .parseClaimsJwt(federatedToken.substring(0, federatedToken.lastIndexOf('.')))
                    .getBody()
                    .getIssuer();
            
            Key issuerKey = trustedKeys.get(issuer);
            if (issuerKey == null) {
                denyFederatedAccess();
                return;
            }
            
            // ok: java-insecure-jwt-parsing
            Jws<Claims> jws = Jwts.parserBuilder()
                    .setSigningKey(issuerKey)
                    .build()
                    .parseClaimsJws(federatedToken);
            
            authenticateFederatedUser(jws.getBody());
        } catch (Exception e) {
            denyFederatedAccess();
        }
    }
    
    public void good_case_13() {
        String encryptedPayload = getEncryptedData();
        String jwtKey = getJwtKeyFromHeader();
        SecretKey masterKey = getMasterKey();
        
        try {
            // ok: java-insecure-jwt-parsing
            Jws<Claims> jws = Jwts.parserBuilder()
                    .setSigningKey(masterKey)
                    .build()
                    .parseClaimsJws(jwtKey);
            
            // Use verified claims to decrypt the payload
            String decryptedPayload = decryptPayload(encryptedPayload, jws.getBody().get("key", String.class));
            processDecryptedData(decryptedPayload);
        } catch (Exception e) {
            handleDecryptionFailure(e);
        }
    }
    
    public void good_case_14() {
        String serviceToken = getServiceToken();
        Key serviceKey = getServicePublicKey();
        
        try {
            // ok: java-insecure-jwt-parsing
            Jws<Claims> jws = Jwts.parserBuilder()
                    .setSigningKey(serviceKey)
                    .setAllowedClockSkewSeconds(300)
                    .requireIssuer("service-registry")
                    .build()
                    .parseClaimsJws(serviceToken);
            
            authorizeServiceAccess(jws.getBody().get("service_name", String.class));
        } catch (Exception e) {
            denyServiceAccess();
            logServiceAccessAttempt(e);
        }
    }
    
    public void good_case_15() {
        String temporaryToken = getTemporaryAccessToken();
        SecretKey tempKey = getTemporaryAccessKey();
        
        try {
            // ok: java-insecure-jwt-parsing
            Jws<Claims> jws = Jwts.parserBuilder()
                    .setSigningKey(tempKey)
                    .requireExpiration()
                    .build()
                    .parseClaimsJws(temporaryToken);
            
            Claims claims = jws.getBody();
            grantTemporaryAccess(claims.getSubject());
        } catch (ExpiredJwtException e) {
            notifyTokenExpired();
            denyTemporaryAccess();
        } catch (Exception e) {
            logInvalidTemporaryToken(e);
            denyTemporaryAccess();
        }
    }
    
    // Helper methods (to avoid compilation errors)
    private String getTokenFromRequest() { return "sample-token"; }
    private String getAuthorizationHeader() { return "Bearer sample-token"; }
    private void processUserData(Claims claims) { }
    private void authenticateUser(Claims claims) { }
    private String getCookieValue(String name) { return "sample-cookie"; }
    private void grantAccess(String subject) { }
    private void handleError(Exception e) { }
    private String getQueryParam(String name) { return "sample-param"; }
    private void processUserInfo(Map<String, Object> info) { }
    private String[] getAllTokensFromSession() { return new String[]{"token1", "token2"}; }
    private boolean isAdmin(Claims claims) { return true; }
    private void grantAdminAccess() { }
    private String getRefreshToken() { return "refresh-token"; }
    private void sendResponse(String token) { }
    private void denyRefresh() { }
    private String getHeaderValue(String header) { return "header-value"; }
    private void validateUserPermissions(Claims claims) { }
    private String getImpersonationToken() { return "impersonation-token"; }
    private void switchUserContext(String original, String impersonated) { }
    private void rejectImpersonation() { }
    private String getSsoToken() { return "sso-token"; }
    private void createLocalSession(Claims claims) { }
    private void redirectToLogin() { }
    private String getApiKey() { return "api-key"; }
    private void rateLimit(String clientId) { }
    private String getFederatedToken() { return "federated-token"; }
    private void authenticateFederatedUser(Claims claims) { }
    private void denyFederatedAccess() { }
    private String getEncryptedData() { return "encrypted-data"; }
    private String getJwtKeyFromHeader() { return "jwt-key"; }
    private String decryptKey(String key) { return "decrypted-key"; }
    private String decryptPayload(String payload, String key) { return "decrypted-payload"; }
    private void processDecryptedData(String data) { }
    private String getServiceToken() { return "service-token"; }
    private void authorizeServiceAccess(String serviceName) { }
    private void denyServiceAccess() { }
    private String getTemporaryAccessToken() { return "temp-token"; }
    private void grantTemporaryAccess(String subject) { }
    private void denyTemporaryAccess() { }
    private SecretKey getSecretKey() { return Keys.secretKeyFor(SignatureAlgorithm.HS256); }
    private Key getSigningKey() { return Keys.secretKeyFor(SignatureAlgorithm.HS256); }
    private void handleJwtException(Exception e) { }
    private void handleExpiredToken() { }
    private Key getPublicKey() { return Keys.secretKeyFor(SignatureAlgorithm.HS256); }
    private void rejectRequest(Exception e) { }
    private Key getSigningKeyFromKeyStore() { return Keys.secretKeyFor(SignatureAlgorithm.HS256); }
    private void rejectMalformedToken() { }
    private void rejectInvalidSignature() { }
    private void rejectExpiredToken() { }
    private SecretKey getImpersonationKey() { return Keys.secretKeyFor(SignatureAlgorithm.HS256); }
    private Key getSsoPublicKey() { return Keys.secretKeyFor(SignatureAlgorithm.HS256); }
    private void logMalformedToken(Exception e) { }
    private void logInvalidSignature(Exception e) { }
    private void requestTokenRefresh() { }
    private SecretKey getApiSecret() { return Keys.secretKeyFor(SignatureAlgorithm.HS256); }
    private void rejectWeakKey() { }
    private Map<String, Key> getTrustedIssuerKeys() { return new HashMap<>(); }
    private SecretKey getMasterKey() { return Keys.secretKeyFor(SignatureAlgorithm.HS256); }
    private void handleDecryptionFailure(Exception e) { }
    private Key getServicePublicKey() { return Keys.secretKeyFor(SignatureAlgorithm.HS256); }
    private void logServiceAccessAttempt(Exception e) { }
    private SecretKey getTemporaryAccessKey() { return Keys.secretKeyFor(SignatureAlgorithm.HS256); }
    private void notifyTokenExpired() { }
    private void logInvalidTemporaryToken(Exception e) { }
    private java.util.Set<String> trustedIssuers = new java.util.HashSet<>();
}
// {/fact}