import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletException;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Controller;
import org.springframework.http.ResponseEntity;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.struts2.dispatcher.SessionMap;
import org.apache.struts2.interceptor.SessionAware;
import com.opensymphony.xwork2.ActionSupport;
import play.mvc.Security;
import play.mvc.Result;
import play.mvc.Http;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageOptions;
import com.google.cloud.storage.BlobId;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import io.javalin.Javalin;
import io.javalin.http.Context;
import io.javalin.http.Handler;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;
import spark.Request;
import spark.Response;
import ratpack.handling.Context;
import ratpack.handling.Handler;
import ratpack.server.RatpackServer;
import ratpack.server.ServerConfig;
import org.pac4j.core.config.Config;
import org.pac4j.core.profile.CommonProfile;
import org.pac4j.core.profile.ProfileManager;
import org.pac4j.sparkjava.SparkWebContext;
import org.pac4j.sparkjava.SecurityFilter;
import com.azure.storage.blob.BlobClient;
import com.azure.storage.blob.BlobContainerClient;
import com.azure.storage.blob.BlobServiceClient;
import com.azure.storage.blob.BlobServiceClientBuilder;
import com.okta.jwt.AccessTokenVerifier;
import com.okta.jwt.JwtVerifiers;
import com.okta.jwt.Jwt;
import com.okta.spring.boot.oauth.Okta;
import org.keycloak.adapters.KeycloakConfigResolver;
import org.keycloak.adapters.springsecurity.KeycloakSecurityComponents;
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

// Security Issue: Bypassing Authorization Configuration

// True Positive Examples (Vulnerable/Insecure Code)

public class BadAuthorizationExamples {
    
    // Spring Security - Missing authorization checks
    public class bad_case_1 {
        @RestController
        public class UserController {
            @GetMapping("/api/users/{id}")
            public ResponseEntity<String> getUserDetails(@PathVariable String id, HttpServletRequest request) {
                // ruleid: java-bypassauthorizationconfigurationrule
                return ResponseEntity.ok("User details for ID: " + id);
                // No authorization check before returning sensitive user data
            }
        }
    }

    // Apache Shiro - Missing permission check
    public class bad_case_2 {
        public class AdminController {
            public String getAdminData(HttpServletRequest request) {
                Subject currentUser = SecurityUtils.getSubject();
                
                // ruleid: java-bypassauthorizationconfigurationrule
                return "Sensitive admin data: XYZ";
                // Missing permission check before returning admin data
            }
        }
    }

    // AWS S3 - No authorization check before accessing bucket
    public class bad_case_3 {
        public String getS3Object(HttpServletRequest request) {
            String bucketName = request.getParameter("bucket");
            String key = request.getParameter("key");
            
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            
            // ruleid: java-bypassauthorizationconfigurationrule
            return s3Client.getObject(bucketName, key).toString();
            // No authorization check before accessing S3 object
        }
    }

    // Google Cloud Storage - Missing access control
    public class bad_case_4 {
        public String getGCSObject(HttpServletRequest request) {
            String bucketName = request.getParameter("bucket");
            String blobName = request.getParameter("blob");
            
            Storage storage = StorageOptions.getDefaultInstance().getService();
            
            // ruleid: java-bypassauthorizationconfigurationrule
            return storage.get(BlobId.of(bucketName, blobName)).toString();
            // No authorization check before accessing GCS object
        }
    }

    // Play Framework - Missing authorization
    public class bad_case_5 {
        public class AdminController extends play.mvc.Controller {
            public Result getAdminDashboard(Http.Request request) {
                // ruleid: java-bypassauthorizationconfigurationrule
                return ok("Admin dashboard data");
                // No authorization check before accessing admin dashboard
            }
        }
    }

    // Javalin - Missing authorization check
    public class bad_case_6 {
        public void configureRoutes() {
            Javalin app = Javalin.create().start(7000);
            
            app.get("/admin/users", ctx -> {
                // ruleid: java-bypassauthorizationconfigurationrule
                ctx.json(Collections.singletonMap("users", Arrays.asList("user1", "user2")));
                // No authorization check before returning user list
            });
        }
    }

    // Micronaut - Missing secured annotation
    public class bad_case_7 {
        @Controller("/api/admin")
        public class AdminController {
            @Get("/users")
            public HttpResponse<?> getUsers(HttpRequest<?> request) {
                // ruleid: java-bypassauthorizationconfigurationrule
                return HttpResponse.ok(Collections.singletonMap("users", Arrays.asList("user1", "user2")));
                // No authorization check before returning user data
            }
        }
    }

    // Spark Framework - Missing authorization check
    public class bad_case_8 {
        public void setupRoutes() {
            spark.Spark.get("/api/confidential", (Request request, Response response) -> {
                // ruleid: java-bypassauthorizationconfigurationrule
                return "Confidential data: XYZ";
                // No authorization check before returning confidential data
            });
        }
    }

    // Ratpack - Missing authorization
    public class bad_case_9 {
        public void setupServer() throws Exception {
            RatpackServer.start(server -> server
                .handlers(chain -> chain
                    .get("api/admin/reports", ctx -> {
                        // ruleid: java-bypassauthorizationconfigurationrule
                        ctx.render("Admin reports data");
                        // No authorization check before rendering admin reports
                    })
                )
            );
        }
    }

    // Azure Blob Storage - Missing access control
    public class bad_case_10 {
        public String getAzureBlobContent(HttpServletRequest request) {
            String containerName = request.getParameter("container");
            String blobName = request.getParameter("blob");
            
            BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
                .connectionString("connection-string")
                .buildClient();
            BlobContainerClient containerClient = blobServiceClient.getBlobContainerClient(containerName);
            BlobClient blobClient = containerClient.getBlobClient(blobName);
            
            // ruleid: java-bypassauthorizationconfigurationrule
            return "Blob content: " + blobClient.downloadContent().toString();
            // No authorization check before accessing blob content
        }
    }

    // Okta JWT - Missing token validation
    public class bad_case_11 {
        public String getProtectedResource(HttpServletRequest request) {
            String authHeader = request.getHeader("Authorization");
            
            // ruleid: java-bypassauthorizationconfigurationrule
            return "Protected resource data";
            // No JWT validation or authorization check
        }
    }

    // Keycloak - Missing role check
    public class bad_case_12 {
        @RestController
        public class ResourceController {
            @GetMapping("/api/protected-resource")
            public ResponseEntity<String> getProtectedResource(HttpServletRequest request) {
                // ruleid: java-bypassauthorizationconfigurationrule
                return ResponseEntity.ok("Protected resource data");
                // No Keycloak role check before returning protected data
            }
        }
    }

    // Auth0 JWT - Missing token verification
    public class bad_case_13 {
        public String getSecureData(HttpServletRequest request) {
            String token = request.getHeader("Authorization").replace("Bearer ", "");
            
            // ruleid: java-bypassauthorizationconfigurationrule
            return "Secure data for authenticated user";
            // No JWT verification or authorization check
        }
    }

    // Struts 2 - Missing authorization check
    public class bad_case_14 extends ActionSupport implements SessionAware {
        private Map<String, Object> session;
        
        public String viewAdminPanel() {
            // ruleid: java-bypassauthorizationconfigurationrule
            return "admin";
            // No authorization check before returning admin view
        }
        
        @Override
        public void setSession(Map<String, Object> session) {
            this.session = session;
        }
    }

    // Pac4j - Missing authorization check
    public class bad_case_15 {
        public void configureRoutes() {
            spark.Spark.get("/api/user-data", (Request request, Response response) -> {
                SparkWebContext context = new SparkWebContext(request, response);
                ProfileManager<CommonProfile> profileManager = new ProfileManager<>(context);
                
                // ruleid: java-bypassauthorizationconfigurationrule
                return "User data: XYZ";
                // No authorization check before returning user data
            });
        }
    }
}

// True Negative Examples (Safe/Secure Code)

public class GoodAuthorizationExamples {
    
    // Spring Security - Proper authorization check
    public class good_case_1 {
        @RestController
        public class UserController {
            @GetMapping("/api/users/{id}")
            // ok: java-bypassauthorizationconfigurationrule
            @PreAuthorize("hasRole('ADMIN') or authentication.principal.id == #id")
            public ResponseEntity<String> getUserDetails(@PathVariable String id) {
                return ResponseEntity.ok("User details for ID: " + id);
            }
        }
    }

    // Apache Shiro - Proper permission check
    public class good_case_2 {
        public class AdminController {
            // ok: java-bypassauthorizationconfigurationrule
            @RequiresPermissions("admin:view")
            public String getAdminData() {
                return "Sensitive admin data: XYZ";
            }
        }
    }

    // AWS S3 - Proper authorization check
    public class good_case_3 {
        public String getS3Object(HttpServletRequest request, Authentication authentication) {
            String bucketName = request.getParameter("bucket");
            String key = request.getParameter("key");
            
            // ok: java-bypassauthorizationconfigurationrule
            if (authentication != null && authentication.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_S3_USER"))) {
                AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
                return s3Client.getObject(bucketName, key).toString();
            } else {
                throw new SecurityException("Unauthorized access to S3 resource");
            }
        }
    }

    // Google Cloud Storage - Proper access control
    public class good_case_4 {
        public String getGCSObject(HttpServletRequest request) {
            String bucketName = request.getParameter("bucket");
            String blobName = request.getParameter("blob");
            
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            
            // ok: java-bypassauthorizationconfigurationrule
            if (auth != null && auth.isAuthenticated() && 
                auth.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_GCS_USER"))) {
                Storage storage = StorageOptions.getDefaultInstance().getService();
                return storage.get(BlobId.of(bucketName, blobName)).toString();
            } else {
                throw new SecurityException("Unauthorized access to GCS resource");
            }
        }
    }

    // Play Framework - Proper authorization
    public class good_case_5 {
        @Security.Authenticated(AdminAuthenticator.class)
        public class AdminController extends play.mvc.Controller {
            // ok: java-bypassauthorizationconfigurationrule
            public Result getAdminDashboard(Http.Request request) {
                return ok("Admin dashboard data");
            }
        }
        
        public class AdminAuthenticator extends Security.Authenticator {
            @Override
            public String getUsername(Http.Request request) {
                String username = request.session().get("username");
                if (username != null && isAdmin(username)) {
                    return username;
                }
                return null;
            }
            
            private boolean isAdmin(String username) {
                // Check if user is admin
                return true; // Simplified for example
            }
        }
    }

    // Javalin - Proper authorization check
    public class good_case_6 {
        public void configureRoutes() {
            Javalin app = Javalin.create(config -> {
                config.accessManager((handler, ctx, permittedRoles) -> {
                    String userRole = getUserRole(ctx);
                    if (permittedRoles.contains(userRole)) {
                        handler.handle(ctx);
                    } else {
                        ctx.status(401).result("Unauthorized");
                    }
                });
            }).start(7000);
            
            // ok: java-bypassauthorizationconfigurationrule
            app.get("/admin/users", ctx -> {
                ctx.json(Collections.singletonMap("users", Arrays.asList("user1", "user2")));
            }, Collections.singleton("ADMIN"));
        }
        
        private String getUserRole(io.javalin.http.Context ctx) {
            // Get user role from context
            return "USER"; // Simplified for example
        }
    }

    // Micronaut - Proper secured annotation
    public class good_case_7 {
        @Controller("/api/admin")
        public class AdminController {
            // ok: java-bypassauthorizationconfigurationrule
            @Secured(SecurityRule.IS_AUTHENTICATED)
            @Get("/users")
            public HttpResponse<?> getUsers(HttpRequest<?> request) {
                return HttpResponse.ok(Collections.singletonMap("users", Arrays.asList("user1", "user2")));
            }
        }
    }

    // Spark Framework - Proper authorization check
    public class good_case_8 {
        public void setupRoutes() {
            spark.Spark.before("/api/confidential", (request, response) -> {
                String token = request.headers("Authorization");
                if (token == null || !isValidToken(token)) {
                    halt(401, "Unauthorized");
                }
            });
            
            // ok: java-bypassauthorizationconfigurationrule
            spark.Spark.get("/api/confidential", (request, response) -> {
                return "Confidential data: XYZ";
            });
        }
        
        private boolean isValidToken(String token) {
            // Validate token
            return true; // Simplified for example
        }
    }

    // Ratpack - Proper authorization
    public class good_case_9 {
        public void setupServer() throws Exception {
            RatpackServer.start(server -> server
                .handlers(chain -> chain
                    .all(ctx -> {
                        if (ctx.getPath().startsWith("api/admin/") && !isAdmin(ctx)) {
                            ctx.getResponse().status(401).send("Unauthorized");
                        } else {
                            ctx.next();
                        }
                    })
                    // ok: java-bypassauthorizationconfigurationrule
                    .get("api/admin/reports", ctx -> {
                        ctx.render("Admin reports data");
                    })
                )
            );
        }
        
        private boolean isAdmin(ratpack.handling.Context ctx) {
            // Check if user is admin
            return true; // Simplified for example
        }
    }

    // Azure Blob Storage - Proper access control
    public class good_case_10 {
        public String getAzureBlobContent(HttpServletRequest request, Authentication authentication) {
            String containerName = request.getParameter("container");
            String blobName = request.getParameter("blob");
            
            // ok: java-bypassauthorizationconfigurationrule
            if (authentication != null && authentication.isAuthenticated() && 
                authentication.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_STORAGE_USER"))) {
                BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
                    .connectionString("connection-string")
                    .buildClient();
                BlobContainerClient containerClient = blobServiceClient.getBlobContainerClient(containerName);
                BlobClient blobClient = containerClient.getBlobClient(blobName);
                
                return "Blob content: " + blobClient.downloadContent().toString();
            } else {
                throw new SecurityException("Unauthorized access to Azure Blob");
            }
        }
    }

    // Okta JWT - Proper token validation
    public class good_case_11 {
        private AccessTokenVerifier tokenVerifier;
        
// {fact rule=missing-authorization@v1.0 defects=0}
        public good_case_11() {
            this.tokenVerifier = JwtVerifiers.accessTokenVerifierBuilder()
                .setIssuer("https://your-org.okta.com/oauth2/default")
                .build();
        }
        
        public String getProtectedResource(HttpServletRequest request) throws Exception {
            String authHeader = request.getHeader("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                throw new SecurityException("Missing or invalid Authorization header");
            }
            
            String token = authHeader.substring(7);
            
            // ok: java-bypassauthorizationconfigurationrule
            Jwt jwt = tokenVerifier.decode(token);
            // JWT is valid, proceed with request
            return "Protected resource data";
        }
    }
// {/fact}

    // Keycloak - Proper role check
    public class good_case_12 {
        @RestController
        public class ResourceController {
            // ok: java-bypassauthorizationconfigurationrule
            @PreAuthorize("hasRole('ROLE_PROTECTED_RESOURCE_USER')")
            @GetMapping("/api/protected-resource")
            public ResponseEntity<String> getProtectedResource() {
                return ResponseEntity.ok("Protected resource data");
            }
        }
    }

    // Auth0 JWT - Proper token verification
    public class good_case_13 {
        private Algorithm algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID("secret");
        
        public String getSecureData(HttpServletRequest request) {
            String authHeader = request.getHeader("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                throw new SecurityException("Missing or invalid Authorization header");
            }
            
            String token = authHeader.substring(7);
            
            try {
                // ok: java-bypassauthorizationconfigurationrule
                DecodedJWT jwt = JWT.require(algorithm)
                    .withIssuer("auth0")
                    .build()
                    .verify(token);
                
                // JWT is valid, proceed with request
                return "Secure data for authenticated user";
            } catch (Exception e) {
                throw new SecurityException("Invalid token", e);
            }
        }
    }

    // Struts 2 - Proper authorization check
    public class good_case_14 extends ActionSupport implements SessionAware {
        private Map<String, Object> session;
        
        public String viewAdminPanel() {
            // ok: java-bypassauthorizationconfigurationrule
            if (session.containsKey("user_role") && "ADMIN".equals(session.get("user_role"))) {
                return "admin";
            } else {
                return "unauthorized";
            }
        }
        
        @Override
        public void setSession(Map<String, Object> session) {
            this.session = session;
        }
    }

    // Pac4j - Proper authorization check
    public class good_case_15 {
        public void configureRoutes() {
            // ok: java-bypassauthorizationconfigurationrule
            spark.Spark.before("/api/user-data", new SecurityFilter(
                new Config(), "HeaderClient", "admin"));
            
            spark.Spark.get("/api/user-data", (Request request, Response response) -> {
                return "User data: XYZ";
            });
        }
    }
}