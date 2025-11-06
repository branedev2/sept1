import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.apache.struts2.interceptor.ServletRequestAware;
import org.apache.struts.action.Action;
import org.apache.struts.action.ActionForm;
import org.apache.struts.action.ActionForward;
import org.apache.struts.action.ActionMapping;
import javax.servlet.ServletException;
import java.io.IOException;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.GenerateDataKeyRequest;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.CryptoKeyName;
import com.google.cloud.kms.v1.GenerateRandomBytesRequest;
import com.azure.security.keyvault.keys.KeyClient;
import com.azure.security.keyvault.keys.KeyClientBuilder;
import com.azure.security.keyvault.keys.models.CreateKeyOptions;
import com.azure.security.keyvault.keys.models.KeyType;
import io.vertx.core.Vertx;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import play.mvc.Controller;
import play.mvc.Result;
import spark.Request;
import spark.Response;
import ratpack.handling.Context;
import ratpack.handling.Handler;
import org.jboss.resteasy.spi.HttpRequest;
import org.jboss.resteasy.spi.HttpResponse;
import io.quarkus.security.identity.SecurityIdentity;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;

// Security Issue: Using insecure cryptographic algorithms with javax.crypto.KeyGenerator

// True Positive Examples (Vulnerable/Insecure Code)
public class InsecureKeyGeneratorExamples {

    // Spring MVC example
    @RestController
    public static class BadCase1 {
        @RequestMapping("/generate-key")
        public String generateKey(HttpServletRequest request) {
            try {
                String algorithm = request.getParameter("algorithm");
                // ruleid: java-crypto-key-generator
                KeyGenerator keyGen = KeyGenerator.getInstance("DES");
                SecretKey key = keyGen.generateKey();
                return "Key generated with algorithm: DES";
            } catch (NoSuchAlgorithmException e) {
                return "Error: " + e.getMessage();
            }
        }
    }

    // Apache Struts example
    public static class BadCase2 extends Action implements ServletRequestAware {
        private HttpServletRequest request;

        public ActionForward execute(ActionMapping mapping, ActionForm form,
                                    HttpServletRequest request, HttpServletResponse response) {
            try {
                // ruleid: java-crypto-key-generator
                KeyGenerator keyGen = KeyGenerator.getInstance("RC4");
                SecretKey key = keyGen.generateKey();
                request.setAttribute("keyAlgorithm", "RC4");
                return mapping.findForward("success");
            } catch (NoSuchAlgorithmException e) {
                return mapping.findForward("error");
            }
        }

        @Override
        public void setServletRequest(HttpServletRequest request) {
            this.request = request;
        }
    }

    // Servlet API example
    public static class BadCase3 extends javax.servlet.http.HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response)
                throws ServletException, IOException {
            try {
                // ruleid: java-crypto-key-generator
                KeyGenerator keyGen = KeyGenerator.getInstance("Blowfish");
                keyGen.init(128);
                SecretKey key = keyGen.generateKey();
                response.getWriter().println("Generated key using Blowfish algorithm");
            } catch (NoSuchAlgorithmException e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    // Vert.x example
    public static class BadCase4 {
        public void setupRouter(Vertx vertx) {
            Router router = Router.router(vertx);
            
            router.get("/generate-key").handler(this::generateKey);
            
            vertx.createHttpServer().requestHandler(router).listen(8080);
        }
        
        private void generateKey(RoutingContext ctx) {
            try {
                // ruleid: java-crypto-key-generator
                KeyGenerator keyGen = KeyGenerator.getInstance("RC2");
                SecretKey key = keyGen.generateKey();
                ctx.response().end("Generated key using RC2 algorithm");
            } catch (NoSuchAlgorithmException e) {
                ctx.response().end("Error: " + e.getMessage());
            }
        }
    }

    // Play Framework example
    public static class BadCase5 extends Controller {
        public Result generateKey() {
            try {
                // ruleid: java-crypto-key-generator
                KeyGenerator keyGen = KeyGenerator.getInstance("ARCFOUR");
                SecretKey key = keyGen.generateKey();
                return ok("Generated key using ARCFOUR algorithm");
            } catch (NoSuchAlgorithmException e) {
                return internalServerError("Error: " + e.getMessage());
            }
        }
    }

    // Spark Framework example
    public static class BadCase6 {
        public void setupRoutes() {
            spark.Spark.get("/generate-key", this::generateKey);
        }
        
        private String generateKey(Request request, Response response) {
            try {
                // ruleid: java-crypto-key-generator
                KeyGenerator keyGen = KeyGenerator.getInstance("DESede");
                SecretKey key = keyGen.generateKey();
                return "Generated key using DESede (Triple DES) algorithm";
            } catch (NoSuchAlgorithmException e) {
                response.status(500);
                return "Error: " + e.getMessage();
            }
        }
    }

    // Ratpack example
    public static class BadCase7 implements Handler {
        @Override
        public void handle(Context ctx) {
            try {
                // ruleid: java-crypto-key-generator
                KeyGenerator keyGen = KeyGenerator.getInstance("HmacMD5");
                SecretKey key = keyGen.generateKey();
                ctx.getResponse().send("Generated key using HmacMD5 algorithm");
            } catch (NoSuchAlgorithmException e) {
                ctx.getResponse().status(500).send("Error: " + e.getMessage());
            }
        }
    }

    // RESTEasy example
    public static class BadCase8 {
        public void generateKey(HttpRequest request, HttpResponse response) {
            try {
                // ruleid: java-crypto-key-generator
                KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA1");
                SecretKey key = keyGen.generateKey();
                response.getOutputStream().write("Generated key using HmacSHA1 algorithm".getBytes());
            } catch (Exception e) {
                // Handle exception
            }
        }
    }

    // Quarkus example
    @io.quarkus.security.Authenticated
    public static class BadCase9 {
        @javax.ws.rs.GET
        @javax.ws.rs.Path("/generate-key")
        public String generateKey(SecurityIdentity identity) {
            try {
                // ruleid: java-crypto-key-generator
                KeyGenerator keyGen = KeyGenerator.getInstance("HmacMD5");
                SecretKey key = keyGen.generateKey();
                return "Generated key using HmacMD5 algorithm for user: " + identity.getPrincipal().getName();
            } catch (NoSuchAlgorithmException e) {
                return "Error: " + e.getMessage();
            }
        }
    }

    // Micronaut example
    @Controller("/crypto")
    public static class BadCase10 {
        @Get("/generate-key")
        public HttpResponse<String> generateKey(HttpRequest<?> request) {
            try {
                // ruleid: java-crypto-key-generator
                KeyGenerator keyGen = KeyGenerator.getInstance("RC4");
                SecretKey key = keyGen.generateKey();
                return HttpResponse.ok("Generated key using RC4 algorithm");
            } catch (NoSuchAlgorithmException e) {
                return HttpResponse.serverError("Error: " + e.getMessage());
            }
        }
    }

    // Apache HttpClient example
    public static class BadCase11 {
        public void fetchAndGenerateKey() {
            try {
                HttpClient client = HttpClients.createDefault();
                HttpGet request = new HttpGet("https://example.com/api/crypto-config");
                HttpResponse response = client.execute(request);
                String algorithm = EntityUtils.toString(response.getEntity());
                
                // ruleid: java-crypto-key-generator
                KeyGenerator keyGen = KeyGenerator.getInstance("DES");
                SecretKey key = keyGen.generateKey();
                System.out.println("Generated key with algorithm: DES");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    // AWS KMS integration example
    public static class BadCase12 {
        public void generateKeyWithAWS(HttpServletRequest request) {
            try {
                AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
                
                // Generate a local key first
                // ruleid: java-crypto-key-generator
                KeyGenerator keyGen = KeyGenerator.getInstance("Blowfish");
                SecretKey localKey = keyGen.generateKey();
                
                // Then use AWS KMS for additional operations
                GenerateDataKeyRequest dataKeyRequest = new GenerateDataKeyRequest()
                    .withKeyId(request.getParameter("keyId"))
                    .withKeySpec("AES_256");
                
                kmsClient.generateDataKey(dataKeyRequest);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    // Google Cloud KMS integration example
    public static class BadCase13 {
        public void generateKeyWithGCP(HttpServletRequest request) {
            try {
                // Local key generation with weak algorithm
                // ruleid: java-crypto-key-generator
                KeyGenerator keyGen = KeyGenerator.getInstance("RC2");
                SecretKey localKey = keyGen.generateKey();
                
                // Then use Google Cloud KMS
                try (KeyManagementServiceClient client = KeyManagementServiceClient.create()) {
                    String projectId = request.getParameter("projectId");
                    String locationId = request.getParameter("locationId");
                    String keyRingId = request.getParameter("keyRingId");
                    String cryptoKeyId = request.getParameter("cryptoKeyId");
                    
                    CryptoKeyName keyName = CryptoKeyName.of(projectId, locationId, keyRingId, cryptoKeyId);
                    GenerateRandomBytesRequest randomBytesRequest = 
                        GenerateRandomBytesRequest.newBuilder()
                            .setLocation(locationId)
                            .setLengthBytes(32)
                            .build();
                    
                    client.generateRandomBytes(randomBytesRequest);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    // Azure Key Vault integration example
    public static class BadCase14 {
        public void generateKeyWithAzure(HttpServletRequest request) {
            try {
                // Local key generation with weak algorithm
                // ruleid: java-crypto-key-generator
                KeyGenerator keyGen = KeyGenerator.getInstance("DESede");
                SecretKey localKey = keyGen.generateKey();
                
                // Then use Azure Key Vault
                String keyVaultUrl = request.getParameter("keyVaultUrl");
                KeyClient keyClient = new KeyClientBuilder()
                    .vaultUrl(keyVaultUrl)
                    .buildClient();
                
                keyClient.createKey(new CreateKeyOptions("myKey", KeyType.RSA)
                    .setExpiresOn(null)
                    .setNotBefore(null));
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    // JAX-RS example
    public static class BadCase15 {
        @javax.ws.rs.GET
        @javax.ws.rs.Path("/generate-key")
        public javax.ws.rs.core.Response generateKey(@javax.ws.rs.core.Context javax.ws.rs.core.HttpHeaders headers) {
            try {
                String algorithm = headers.getHeaderString("X-Crypto-Algorithm");
                if (algorithm == null) {
                    algorithm = "HmacMD5";
                }
                
                // ruleid: java-crypto-key-generator
                KeyGenerator keyGen = KeyGenerator.getInstance("HmacMD5");
                SecretKey key = keyGen.generateKey();
                
                return javax.ws.rs.core.Response.ok("Generated key using algorithm: HmacMD5").build();
            } catch (NoSuchAlgorithmException e) {
                return javax.ws.rs.core.Response.serverError().entity("Error: " + e.getMessage()).build();
            }
        }
    }

    // True Negative Examples (Safe/Secure Code)
    
    // Spring MVC example with secure algorithm
    @RestController
    public static class GoodCase1 {
        @RequestMapping("/generate-secure-key")
        public String generateSecureKey(HttpServletRequest request) {
            try {
                // ok: java-crypto-key-generator
                KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                keyGen.init(256);
                SecretKey key = keyGen.generateKey();
                return "Key generated with secure algorithm: AES";
            } catch (NoSuchAlgorithmException e) {
                return "Error: " + e.getMessage();
            }
        }
    }

    // Apache Struts example with secure algorithm
    public static class GoodCase2 extends Action implements ServletRequestAware {
        private HttpServletRequest request;

        public ActionForward execute(ActionMapping mapping, ActionForm form,
                                    HttpServletRequest request, HttpServletResponse response) {
            try {
                // ok: java-crypto-key-generator
                KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
                SecretKey key = keyGen.generateKey();
                request.setAttribute("keyAlgorithm", "HmacSHA256");
                return mapping.findForward("success");
            } catch (NoSuchAlgorithmException e) {
                return mapping.findForward("error");
            }
        }

        @Override
        public void setServletRequest(HttpServletRequest request) {
            this.request = request;
        }
    }

    // Servlet API example with secure algorithm
    public static class GoodCase3 extends javax.servlet.http.HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response)
                throws ServletException, IOException {
            try {
                // ok: java-crypto-key-generator
                KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA384");
                SecretKey key = keyGen.generateKey();
                response.getWriter().println("Generated key using secure HmacSHA384 algorithm");
            } catch (NoSuchAlgorithmException e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    // Vert.x example with secure algorithm
    public static class GoodCase4 {
        public void setupRouter(Vertx vertx) {
            Router router = Router.router(vertx);
            
            router.get("/generate-secure-key").handler(this::generateSecureKey);
            
            vertx.createHttpServer().requestHandler(router).listen(8080);
        }
        
        private void generateSecureKey(RoutingContext ctx) {
            try {
                // ok: java-crypto-key-generator
                KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA512");
                SecretKey key = keyGen.generateKey();
                ctx.response().end("Generated key using secure HmacSHA512 algorithm");
            } catch (NoSuchAlgorithmException e) {
                ctx.response().end("Error: " + e.getMessage());
            }
        }
    }

    // Play Framework example with secure algorithm
    public static class GoodCase5 extends Controller {
        public Result generateSecureKey() {
            try {
                // ok: java-crypto-key-generator
                KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                keyGen.init(256);
                SecretKey key = keyGen.generateKey();
                return ok("Generated key using secure AES algorithm");
            } catch (NoSuchAlgorithmException e) {
                return internalServerError("Error: " + e.getMessage());
            }
        }
    }

    // Spark Framework example with secure algorithm
    public static class GoodCase6 {
        public void setupRoutes() {
            spark.Spark.get("/generate-secure-key", this::generateSecureKey);
        }
        
        private String generateSecureKey(Request request, Response response) {
            try {
                // ok: java-crypto-key-generator
                KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA224");
                SecretKey key = keyGen.generateKey();
                return "Generated key using secure HmacSHA224 algorithm";
            } catch (NoSuchAlgorithmException e) {
                response.status(500);
                return "Error: " + e.getMessage();
            }
        }
    }

    // Ratpack example with secure algorithm
    public static class GoodCase7 implements Handler {
        @Override
        public void handle(Context ctx) {
            try {
                // ok: java-crypto-key-generator
                KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                keyGen.init(256);
                SecretKey key = keyGen.generateKey();
                ctx.getResponse().send("Generated key using secure AES algorithm");
            } catch (NoSuchAlgorithmException e) {
                ctx.getResponse().status(500).send("Error: " + e.getMessage());
            }
        }
    }

    // RESTEasy example with secure algorithm
    public static class GoodCase8 {
        public void generateSecureKey(HttpRequest request, HttpResponse response) {
            try {
                // ok: java-crypto-key-generator
                KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
                SecretKey key = keyGen.generateKey();
                response.getOutputStream().write("Generated key using secure HmacSHA256 algorithm".getBytes());
            } catch (Exception e) {
                // Handle exception
            }
        }
    }

    // Quarkus example with secure algorithm
    @io.quarkus.security.Authenticated
    public static class GoodCase9 {
        @javax.ws.rs.GET
        @javax.ws.rs.Path("/generate-secure-key")
        public String generateSecureKey(SecurityIdentity identity) {
            try {
                // ok: java-crypto-key-generator
                KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA384");
                SecretKey key = keyGen.generateKey();
                return "Generated secure key using HmacSHA384 algorithm for user: " + identity.getPrincipal().getName();
            } catch (NoSuchAlgorithmException e) {
                return "Error: " + e.getMessage();
            }
        }
    }

    // Micronaut example with secure algorithm
    @Controller("/crypto")
    public static class GoodCase10 {
        @Get("/generate-secure-key")
        public HttpResponse<String> generateSecureKey(io.micronaut.http.HttpRequest<?> request) {
            try {
                // ok: java-crypto-key-generator
                KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA512");
                SecretKey key = keyGen.generateKey();
                return HttpResponse.ok("Generated key using secure HmacSHA512 algorithm");
            } catch (NoSuchAlgorithmException e) {
                return HttpResponse.serverError("Error: " + e.getMessage());
            }
        }
    }

    // Apache HttpClient example with secure algorithm
    public static class GoodCase11 {
        public void fetchAndGenerateSecureKey() {
            try {
                HttpClient client = HttpClients.createDefault();
                HttpGet request = new HttpGet("https://example.com/api/crypto-config");
                HttpResponse response = client.execute(request);
                String algorithm = EntityUtils.toString(response.getEntity());
                
                // ok: java-crypto-key-generator
                KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                keyGen.init(256);
                SecretKey key = keyGen.generateKey();
                System.out.println("Generated key with secure algorithm: AES");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    // AWS KMS integration example with secure algorithm
    public static class GoodCase12 {
        public void generateSecureKeyWithAWS(HttpServletRequest request) {
            try {
                AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
                
                // Generate a local key with secure algorithm
                // ok: java-crypto-key-generator
                KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
                SecretKey localKey = keyGen.generateKey();
                
                // Then use AWS KMS for additional operations
                GenerateDataKeyRequest dataKeyRequest = new GenerateDataKeyRequest()
                    .withKeyId(request.getParameter("keyId"))
                    .withKeySpec("AES_256");
                
                kmsClient.generateDataKey(dataKeyRequest);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    // Google Cloud KMS integration example with secure algorithm
    public static class GoodCase13 {
        public void generateSecureKeyWithGCP(HttpServletRequest request) {
            try {
                // Local key generation with secure algorithm
                // ok: java-crypto-key-generator
                KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA384");
                SecretKey localKey = keyGen.generateKey();
                
                // Then use Google Cloud KMS
                try (KeyManagementServiceClient client = KeyManagementServiceClient.create()) {
                    String projectId = request.getParameter("projectId");
                    String locationId = request.getParameter("locationId");
                    String keyRingId = request.getParameter("keyRingId");
                    String cryptoKeyId = request.getParameter("cryptoKeyId");
                    
                    CryptoKeyName keyName = CryptoKeyName.of(projectId, locationId, keyRingId, cryptoKeyId);
                    GenerateRandomBytesRequest randomBytesRequest = 
                        GenerateRandomBytesRequest.newBuilder()
                            .setLocation(locationId)
                            .setLengthBytes(32)
                            .build();
                    
                    client.generateRandomBytes(randomBytesRequest);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    // Azure Key Vault integration example with secure algorithm
    public static class GoodCase14 {
        public void generateSecureKeyWithAzure(HttpServletRequest request) {
            try {
                // Local key generation with secure algorithm
                // ok: java-crypto-key-generator
                KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                keyGen.init(256);
                SecretKey localKey = keyGen.generateKey();
                
                // Then use Azure Key Vault
                String keyVaultUrl = request.getParameter("keyVaultUrl");
                KeyClient keyClient = new KeyClientBuilder()
                    .vaultUrl(keyVaultUrl)
                    .buildClient();
                
                keyClient.createKey(new CreateKeyOptions("myKey", KeyType.RSA)
                    .setExpiresOn(null)
                    .setNotBefore(null));
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    // JAX-RS example with secure algorithm
    public static class GoodCase15 {
        @javax.ws.rs.GET
        @javax.ws.rs.Path("/generate-secure-key")
        public javax.ws.rs.core.Response generateSecureKey(@javax.ws.rs.core.Context javax.ws.rs.core.HttpHeaders headers) {
            try {
                String algorithm = headers.getHeaderString("X-Crypto-Algorithm");
                if (algorithm == null) {
                    algorithm = "HmacSHA512";
                }
                
                // ok: java-crypto-key-generator
                KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA512");
                SecretKey key = keyGen.generateKey();
                
                return javax.ws.rs.core.Response.ok("Generated key using secure algorithm: HmacSHA512").build();
            } catch (NoSuchAlgorithmException e) {
                return javax.ws.rs.core.Response.serverError().entity("Error: " + e.getMessage()).build();
            }
        }
    }
}