import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Base64;
import java.util.Properties;
import java.io.FileInputStream;
import java.util.Map;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import com.squareup.okhttp.MediaType;
import com.squareup.okhttp.RequestBody;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.javanet.NetHttpTransport;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import com.azure.core.credential.TokenCredential;
import com.azure.core.http.HttpHeader;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.storage.blob.BlobServiceClient;
import com.azure.storage.blob.BlobServiceClientBuilder;
import com.mashape.unirest.http.Unirest;
import org.asynchttpclient.AsyncHttpClient;
import org.asynchttpclient.Dsl;
import org.asynchttpclient.RequestBuilder;
import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;
import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.services.oauth2.Oauth2;
import com.google.api.services.oauth2.model.Tokeninfo;
import org.apache.http.client.fluent.Request;
import org.apache.http.entity.ContentType;
import org.apache.http.client.fluent.Content;
import org.glassfish.jersey.client.JerseyClientBuilder;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import io.vertx.core.Vertx;
import io.vertx.ext.web.client.WebClient;
import io.vertx.ext.web.client.WebClientOptions;
import org.eclipse.jetty.client.HttpClient as JettyHttpClient;
import org.eclipse.jetty.client.api.ContentResponse;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import io.ktor.client.HttpClient as KtorHttpClient;
import io.ktor.client.request.get;
import io.ktor.client.request.header;
import java.util.concurrent.TimeUnit;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.VaultResponse;
import io.kubernetes.client.openapi.ApiClient;
import io.kubernetes.client.openapi.Configuration;
import io.kubernetes.client.util.Config;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;

// Security Issue: Hardcoded OAuth client secrets in HTTP headers

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1() {
    // Java 11 HttpClient with hardcoded OAuth client secret
    HttpClient client = HttpClient.newHttpClient();
    String clientId = "my-client-id";
    String clientSecret = "my-secret-value-12345";
    String credentials = clientId + ":" + clientSecret;
    String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());
    
    // ruleid: java-hardcoded-o-auth-secret
    HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://api.example.com/oauth/token"))
            .header("Authorization", "Basic " + encodedCredentials)
            .POST(HttpRequest.BodyPublishers.ofString("grant_type=client_credentials"))
            .build();
    
    try {
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        System.out.println(response.body());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_2() {
    // Apache HttpClient with hardcoded OAuth client secret
    try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
        String clientId = "api-client";
        String clientSecret = "super-secret-password";
        String authHeader = "Basic " + Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes());
        
        org.apache.http.client.methods.HttpPost httpPost = new org.apache.http.client.methods.HttpPost("https://auth.service.com/token");
        
        // ruleid: java-hardcoded-o-auth-secret
        httpPost.setHeader("Authorization", authHeader);
        httpPost.setHeader("Content-Type", "application/x-www-form-urlencoded");
        
        org.apache.http.HttpResponse response = httpClient.execute(httpPost);
        System.out.println(response.getStatusLine());
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_3() {
    // Spring RestTemplate with hardcoded OAuth client secret
    RestTemplate restTemplate = new RestTemplate();
    HttpHeaders headers = new HttpHeaders();
    String clientId = "spring-app";
    String clientSecret = "spring-secret-key-123";
    String auth = clientId + ":" + clientSecret;
    String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes());
    
    // ruleid: java-hardcoded-o-auth-secret
    headers.add("Authorization", "Basic " + encodedAuth);
    
    HttpEntity<String> entity = new HttpEntity<>("grant_type=client_credentials", headers);
    ResponseEntity<String> response = restTemplate.exchange(
            "https://oauth.example.org/token",
            HttpMethod.POST,
            entity,
            String.class);
    
    System.out.println(response.getBody());
}

public void bad_case_4() {
    // OkHttp3 with hardcoded OAuth client secret
    OkHttpClient client = new OkHttpClient();
    String clientId = "okhttp-client";
    String clientSecret = "okhttp-secret-456";
    String credentials = clientId + ":" + clientSecret;
    String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());
    
    // ruleid: java-hardcoded-o-auth-secret
    Request request = new Request.Builder()
            .url("https://api.service.com/oauth2/token")
            .addHeader("Authorization", "Basic " + encodedCredentials)
            .post(okhttp3.RequestBody.create("grant_type=client_credentials", okhttp3.MediaType.parse("application/x-www-form-urlencoded")))
            .build();
    
    try (Response response = client.newCall(request).execute()) {
        System.out.println(response.body().string());
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_5() {
    // Apache Commons HttpClient with hardcoded OAuth client secret
    HttpClient client = new HttpClient();
    GetMethod method = new GetMethod("https://api.example.com/protected-resource");
    
    String clientId = "commons-client";
    String clientSecret = "commons-secret-789";
    String auth = clientId + ":" + clientSecret;
    String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes());
    
    // ruleid: java-hardcoded-o-auth-secret
    method.addRequestHeader("Authorization", "Basic " + encodedAuth);
    
    try {
        client.executeMethod(method);
        String response = method.getResponseBodyAsString();
        System.out.println(response);
    } catch (IOException e) {
        e.printStackTrace();
    } finally {
        method.releaseConnection();
    }
}

public void bad_case_6() {
    // Google HTTP Client with hardcoded OAuth client secret
    try {
        HttpRequestFactory requestFactory = new NetHttpTransport().createRequestFactory();
        GenericUrl url = new GenericUrl("https://api.google.com/service");
        
        String clientId = "google-client";
        String clientSecret = "google-secret-abc";
        String credentials = clientId + ":" + clientSecret;
        String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());
        
        // ruleid: java-hardcoded-o-auth-secret
        com.google.api.client.http.HttpRequest request = requestFactory.buildGetRequest(url)
                .setHeaders(new com.google.api.client.http.HttpHeaders()
                        .setAuthorization("Basic " + encodedCredentials));
        
        String response = request.execute().parseAsString();
        System.out.println(response);
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_7() {
    // Unirest with hardcoded OAuth client secret
    try {
        String clientId = "unirest-client";
        String clientSecret = "unirest-secret-xyz";
        String credentials = clientId + ":" + clientSecret;
        String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());
        
        // ruleid: java-hardcoded-o-auth-secret
        com.mashape.unirest.http.HttpResponse<String> response = Unirest.post("https://api.example.com/oauth/token")
                .header("Authorization", "Basic " + encodedCredentials)
                .field("grant_type", "client_credentials")
                .asString();
        
        System.out.println(response.getBody());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_8() {
    // AsyncHttpClient with hardcoded OAuth client secret
    AsyncHttpClient client = Dsl.asyncHttpClient();
    String clientId = "async-client";
    String clientSecret = "async-secret-123";
    String credentials = clientId + ":" + clientSecret;
    String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());
    
    try {
        // ruleid: java-hardcoded-o-auth-secret
        org.asynchttpclient.Request request = new RequestBuilder("POST")
                .setUrl("https://auth.service.io/token")
                .addHeader("Authorization", "Basic " + encodedCredentials)
                .setBody("grant_type=client_credentials")
                .build();
        
        client.executeRequest(request).toCompletableFuture().thenAccept(response -> {
            System.out.println(response.getResponseBody());
        }).join();
    } finally {
        try {
            client.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

public void bad_case_9() {
    // Retrofit with hardcoded OAuth client secret
    Retrofit retrofit = new Retrofit.Builder()
            .baseUrl("https://api.example.com/")
            .addConverterFactory(GsonConverterFactory.create())
            .build();
    
    String clientId = "retrofit-client";
    String clientSecret = "retrofit-secret-456";
    String credentials = clientId + ":" + clientSecret;
    String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());
    
    // This is a simplified example as Retrofit typically uses interfaces
    // ruleid: java-hardcoded-o-auth-secret
    okhttp3.OkHttpClient client = new okhttp3.OkHttpClient.Builder()
            .addInterceptor(chain -> {
                okhttp3.Request original = chain.request();
                okhttp3.Request request = original.newBuilder()
                        .header("Authorization", "Basic " + encodedCredentials)
                        .method(original.method(), original.body())
                        .build();
                return chain.proceed(request);
            })
            .build();
}

public void bad_case_10() {
    // Apache HTTP Fluent API with hardcoded OAuth client secret
    try {
        String clientId = "fluent-client";
        String clientSecret = "fluent-secret-789";
        String credentials = clientId + ":" + clientSecret;
        String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());
        
        // ruleid: java-hardcoded-o-auth-secret
        Content content = Request.Post("https://api.example.com/oauth/token")
                .addHeader("Authorization", "Basic " + encodedCredentials)
                .bodyString("grant_type=client_credentials", ContentType.APPLICATION_FORM_URLENCODED)
                .execute()
                .returnContent();
        
        System.out.println(content.asString());
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_11() {
    // Jersey Client with hardcoded OAuth client secret
    Client client = JerseyClientBuilder.createClient();
    WebTarget target = client.target("https://api.example.com/oauth/token");
    
    String clientId = "jersey-client";
    String clientSecret = "jersey-secret-abc";
    String credentials = clientId + ":" + clientSecret;
    String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());
    
    // ruleid: java-hardcoded-o-auth-secret
    javax.ws.rs.core.Response response = target.request(MediaType.APPLICATION_JSON)
            .header("Authorization", "Basic " + encodedCredentials)
            .post(javax.ws.rs.client.Entity.entity("grant_type=client_credentials", 
                  javax.ws.rs.core.MediaType.APPLICATION_FORM_URLENCODED));
    
    System.out.println(response.readEntity(String.class));
    client.close();
}

public void bad_case_12() {
    // Vert.x Web Client with hardcoded OAuth client secret
    Vertx vertx = Vertx.vertx();
    WebClient client = WebClient.create(vertx, new WebClientOptions());
    
    String clientId = "vertx-client";
    String clientSecret = "vertx-secret-xyz";
    String credentials = clientId + ":" + clientSecret;
    String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());
    
    // ruleid: java-hardcoded-o-auth-secret
    client.post(443, "api.example.com", "/oauth/token")
            .ssl(true)
            .putHeader("Authorization", "Basic " + encodedCredentials)
            .putHeader("Content-Type", "application/x-www-form-urlencoded")
            .sendForm(
                    io.vertx.core.MultiMap.caseInsensitiveMultiMap().add("grant_type", "client_credentials"),
                    ar -> {
                        if (ar.succeeded()) {
                            System.out.println(ar.result().bodyAsString());
                        } else {
                            ar.cause().printStackTrace();
                        }
                        vertx.close();
                    }
            );
}

public void bad_case_13() {
    // Jetty HTTP Client with hardcoded OAuth client secret
    JettyHttpClient client = new JettyHttpClient();
    
    try {
        client.start();
        
        String clientId = "jetty-client";
        String clientSecret = "jetty-secret-123";
        String credentials = clientId + ":" + clientSecret;
        String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());
        
        // ruleid: java-hardcoded-o-auth-secret
        ContentResponse response = client.newRequest("https://api.example.com/oauth/token")
                .method(org.eclipse.jetty.http.HttpMethod.POST)
                .header("Authorization", "Basic " + encodedCredentials)
                .content(new org.eclipse.jetty.client.util.StringContentProvider(
                        "grant_type=client_credentials", "application/x-www-form-urlencoded"))
                .send();
        
        System.out.println(response.getContentAsString());
    } catch (Exception e) {
        e.printStackTrace();
    } finally {
        try {
            client.stop();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

public void bad_case_14() {
    // Firebase Admin SDK with hardcoded OAuth client secret
    try {
        String clientId = "firebase-client";
        String clientSecret = "firebase-secret-456";
        String credentials = clientId + ":" + clientSecret;
        String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());
        
        // Using Firebase with custom HTTP client for auth
        OkHttpClient okHttpClient = new OkHttpClient();
        
        // ruleid: java-hardcoded-o-auth-secret
        Request request = new Request.Builder()
                .url("https://oauth2.googleapis.com/token")
                .addHeader("Authorization", "Basic " + encodedCredentials)
                .post(okhttp3.RequestBody.create("grant_type=client_credentials", 
                      okhttp3.MediaType.parse("application/x-www-form-urlencoded")))
                .build();
        
        try (Response response = okHttpClient.newCall(request).execute()) {
            // Use token to initialize Firebase
            String token = response.body().string();
            System.out.println("Got token: " + token);
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_15() {
    // Kubernetes Java Client with hardcoded OAuth client secret
    try {
        String clientId = "k8s-client";
        String clientSecret = "k8s-secret-789";
        String credentials = clientId + ":" + clientSecret;
        String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());
        
        // Custom HTTP client for Kubernetes authentication
        OkHttpClient okHttpClient = new OkHttpClient();
        
        // ruleid: java-hardcoded-o-auth-secret
        Request request = new Request.Builder()
                .url("https://kubernetes.default.svc/oauth/token")
                .addHeader("Authorization", "Basic " + encodedCredentials)
                .post(okhttp3.RequestBody.create("grant_type=client_credentials", 
                      okhttp3.MediaType.parse("application/x-www-form-urlencoded")))
                .build();
        
        try (Response response = okHttpClient.newCall(request).execute()) {
            // Use token to configure Kubernetes client
            String token = response.body().string();
            System.out.println("Got Kubernetes token: " + token);
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1() {
    // Java 11 HttpClient with secret from environment variable
    HttpClient client = HttpClient.newHttpClient();
    String clientId = "my-client-id";
    String clientSecret = System.getenv("OAUTH_CLIENT_SECRET");
    String credentials = clientId + ":" + clientSecret;
    String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());
    
    // ok: java-hardcoded-o-auth-secret
    HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://api.example.com/oauth/token"))
            .header("Authorization", "Basic " + encodedCredentials)
            .POST(HttpRequest.BodyPublishers.ofString("grant_type=client_credentials"))
            .build();
    
    try {
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        System.out.println(response.body());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_2() {
    // Apache HttpClient with secret from properties file
    try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
        // Load properties from a secure location
        Properties properties = new Properties();
        properties.load(new FileInputStream("config/secure.properties"));
        
        String clientId = "api-client";
        String clientSecret = properties.getProperty("oauth.client.secret");
        String authHeader = "Basic " + Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes());
        
        org.apache.http.client.methods.HttpPost httpPost = new org.apache.http.client.methods.HttpPost("https://auth.service.com/token");
        
        // ok: java-hardcoded-o-auth-secret
        httpPost.setHeader("Authorization", authHeader);
        httpPost.setHeader("Content-Type", "application/x-www-form-urlencoded");
        
        org.apache.http.HttpResponse response = httpClient.execute(httpPost);
        System.out.println(response.getStatusLine());
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_3() {
    // Spring RestTemplate with secret from system property
    RestTemplate restTemplate = new RestTemplate();
    HttpHeaders headers = new HttpHeaders();
    String clientId = "spring-app";
    String clientSecret = System.getProperty("oauth.client.secret");
    String auth = clientId + ":" + clientSecret;
    String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes());
    
    // ok: java-hardcoded-o-auth-secret
    headers.add("Authorization", "Basic " + encodedAuth);
    
    HttpEntity<String> entity = new HttpEntity<>("grant_type=client_credentials", headers);
    ResponseEntity<String> response = restTemplate.exchange(
            "https://oauth.example.org/token",
            HttpMethod.POST,
            entity,
            String.class);
    
    System.out.println(response.getBody());
}

public void good_case_4() {
    // OkHttp3 with secret from environment variable
    OkHttpClient client = new OkHttpClient();
    String clientId = "okhttp-client";
    String clientSecret = System.getenv("OKHTTP_CLIENT_SECRET");
    String credentials = clientId + ":" + clientSecret;
    String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());
    
    // ok: java-hardcoded-o-auth-secret
    Request request = new Request.Builder()
            .url("https://api.service.com/oauth2/token")
            .addHeader("Authorization", "Basic " + encodedCredentials)
            .post(okhttp3.RequestBody.create("grant_type=client_credentials", okhttp3.MediaType.parse("application/x-www-form-urlencoded")))
            .build();
    
    try (Response response = client.newCall(request).execute()) {
        System.out.println(response.body().string());
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_5() {
    // Apache Commons HttpClient with secret from configuration service
    HttpClient client = new HttpClient();
    GetMethod method = new GetMethod("https://api.example.com/protected-resource");
    
    // Simulating a configuration service that securely retrieves secrets
    String clientId = "commons-client";
    String clientSecret = getSecretFromConfigService("commons.oauth.secret");
    String auth = clientId + ":" + clientSecret;
    String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes());
    
    // ok: java-hardcoded-o-auth-secret
    method.addRequestHeader("Authorization", "Basic " + encodedAuth);
    
    try {
        client.executeMethod(method);
        String response = method.getResponseBodyAsString();
        System.out.println(response);
    } catch (IOException e) {
        e.printStackTrace();
    } finally {
        method.releaseConnection();
    }
}

private String getSecretFromConfigService(String key) {
    // This would be implemented to securely retrieve secrets
    // For example, from AWS Secrets Manager, HashiCorp Vault, etc.
    return System.getenv(key.toUpperCase().replace('.', '_'));
}

public void good_case_6() {
    // Google HTTP Client with secret from secure storage
    try {
        HttpRequestFactory requestFactory = new NetHttpTransport().createRequestFactory();
        GenericUrl url = new GenericUrl("https://api.google.com/service");
        
        String clientId = "google-client";
        // Retrieve secret from a secure key store
        String clientSecret = loadSecretFromKeyStore("google-api-secret");
        String credentials = clientId + ":" + clientSecret;
        String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());
        
        // ok: java-hardcoded-o-auth-secret
        com.google.api.client.http.HttpRequest request = requestFactory.buildGetRequest(url)
                .setHeaders(new com.google.api.client.http.HttpHeaders()
                        .setAuthorization("Basic " + encodedCredentials));
        
        String response = request.execute().parseAsString();
        System.out.println(response);
    } catch (IOException e) {
        e.printStackTrace();
    }
}

private String loadSecretFromKeyStore(String alias) {
    // This would be implemented to load secrets from a secure key store
    return System.getenv("SECRET_" + alias.toUpperCase().replace('-', '_'));
}

public void good_case_7() {
    // Unirest with secret from environment variable
    try {
        String clientId = "unirest-client";
        String clientSecret = System.getenv("UNIREST_CLIENT_SECRET");
        String credentials = clientId + ":" + clientSecret;
        String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());
        
        // ok: java-hardcoded-o-auth-secret
        com.mashape.unirest.http.HttpResponse<String> response = Unirest.post("https://api.example.com/oauth/token")
                .header("Authorization", "Basic " + encodedCredentials)
                .field("grant_type", "client_credentials")
                .asString();
        
        System.out.println(response.getBody());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_8() {
    // AsyncHttpClient with secret from properties
    AsyncHttpClient client = Dsl.asyncHttpClient();
    
    // Load properties from a secure location
    Properties properties = new Properties();
    try {
        properties.load(new FileInputStream("config/secure.properties"));
        String clientId = "async-client";
        String clientSecret = properties.getProperty("async.client.secret");
        String credentials = clientId + ":" + clientSecret;
        String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());
        
        // ok: java-hardcoded-o-auth-secret
        org.asynchttpclient.Request request = new RequestBuilder("POST")
                .setUrl("https://auth.service.io/token")
                .addHeader("Authorization", "Basic " + encodedCredentials)
                .setBody("grant_type=client_credentials")
                .build();
        
        client.executeRequest(request).toCompletableFuture().thenAccept(response -> {
            System.out.println(response.getResponseBody());
        }).join();
    } catch (IOException e) {
        e.printStackTrace();
    } finally {
        try {
            client.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

public void good_case_9() {
    // Retrofit with secret from secure storage
    Retrofit retrofit = new Retrofit.Builder()
            .baseUrl("https://api.example.com/")
            .addConverterFactory(GsonConverterFactory.create())
            .build();
    
    String clientId = "retrofit-client";
    // Get secret from a secure source
    String clientSecret = getSecretFromSecureStorage("retrofit.oauth.secret");
    String credentials = clientId + ":" + clientSecret;
    String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());
    
    // ok: java-hardcoded-o-auth-secret
    okhttp3.OkHttpClient client = new okhttp3.OkHttpClient.Builder()
            .addInterceptor(chain -> {
                okhttp3.Request original = chain.request();
                okhttp3.Request request = original.newBuilder()
                        .header("Authorization", "Basic " + encodedCredentials)
                        .method(original.method(), original.body())
                        .build();
                return chain.proceed(request);
            })
            .build();
}

private String getSecretFromSecureStorage(String key) {
    // This would be implemented to retrieve secrets from secure storage
    return System.getenv(key.toUpperCase().replace('.', '_'));
}

public void good_case_10() {
    // Apache HTTP Fluent API with secret from environment
    try {
        String clientId = "fluent-client";
        String clientSecret = System.getenv("FLUENT_CLIENT_SECRET");
        String credentials = clientId + ":" + clientSecret;
        String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());
        
        // ok: java-hardcoded-o-auth-secret
        Content content = Request.Post("https://api.example.com/oauth/token")
                .addHeader("Authorization", "Basic " + encodedCredentials)
                .bodyString("grant_type=client_credentials", ContentType.APPLICATION_FORM_URLENCODED)
                .execute()
                .returnContent();
        
        System.out.println(content.asString());
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_11() {
    // Jersey Client with secret from HashiCorp Vault
    Client client = JerseyClientBuilder.createClient();
    WebTarget target = client.target("https://api.example.com/oauth/token");
    
    String clientId = "jersey-client";
    // Simulating retrieval from HashiCorp Vault
    String clientSecret = getSecretFromVault("jersey/oauth/client-secret");
    String credentials = clientId + ":" + clientSecret;
    String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());
    
    // ok: java-hardcoded-o-auth-secret
    javax.ws.rs.core.Response response = target.request(MediaType.APPLICATION_JSON)
            .header("Authorization", "Basic " + encodedCredentials)
            .post(javax.ws.rs.client.Entity.entity("grant_type=client_credentials", 
                  javax.ws.rs.core.MediaType.APPLICATION_FORM_URLENCODED));
    
    System.out.println(response.readEntity(String.class));
    client.close();
}

private String getSecretFromVault(String path) {
    // This would be implemented to retrieve secrets from HashiCorp Vault
    // For demonstration, we'll use an environment variable
    return System.getenv("VAULT_" + path.toUpperCase().replace('/', '_').replace('-', '_'));
}

public void good_case_12() {
    // Vert.x Web Client with secret from config
    Vertx vertx = Vertx.vertx();
    WebClient client = WebClient.create(vertx, new WebClientOptions());
    
    String clientId = "vertx-client";
    // Get secret from Vert.x config
    String clientSecret = vertx.sharedData().getLocalMap("secrets").get("vertx.oauth.secret").toString();
    String credentials = clientId + ":" + clientSecret;
    String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());
    
    // ok: java-hardcoded-o-auth-secret
    client.post(443, "api.example.com", "/oauth/token")
            .ssl(true)
            .putHeader("Authorization", "Basic " + encodedCredentials)
            .putHeader("Content-Type", "application/x-www-form-urlencoded")
            .sendForm(
                    io.vertx.core.MultiMap.caseInsensitiveMultiMap().add("grant_type", "client_credentials"),
                    ar -> {
                        if (ar.succeeded()) {
                            System.out.println(ar.result().bodyAsString());
                        } else {
                            ar.cause().printStackTrace();
                        }
                        vertx.close();
                    }
            );
}

public void good_case_13() {
    // Jetty HTTP Client with secret from AWS Secrets Manager
    JettyHttpClient client = new JettyHttpClient();
    
    try {
        client.start();
        
        String clientId = "jetty-client";
        // Simulating retrieval from AWS Secrets Manager
        String clientSecret = getSecretFromAwsSecretsManager("jetty/oauth/client-secret");
        String credentials = clientId + ":" + clientSecret;
        String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());
        
        // ok: java-hardcoded-o-auth-secret
        ContentResponse response = client.newRequest("https://api.example.com/oauth/token")
                .method(org.eclipse.jetty.http.HttpMethod.POST)
                .header("Authorization", "Basic " + encodedCredentials)
                .content(new org.eclipse.jetty.client.util.StringContentProvider(
                        "grant_type=client_credentials", "application/x-www-form-urlencoded"))
                .send();
        
        System.out.println(response.getContentAsString());
    } catch (Exception e) {
        e.printStackTrace();
    } finally {
        try {
            client.stop();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

private String getSecretFromAwsSecretsManager(String secretId) {
    // This would be implemented to retrieve secrets from AWS Secrets Manager
    // For demonstration, we'll use an environment variable
    return System.getenv("AWS_SECRET_" + secretId.toUpperCase().replace('/', '_').replace('-', '_'));
}

public void good_case_14() {
    // Firebase Admin SDK with secret from Google Cloud Secret Manager
    try {
        String clientId = "firebase-client";
        // Simulating retrieval from Google Cloud Secret Manager
        String clientSecret = getSecretFromGoogleSecretManager("firebase-oauth-secret");
        String credentials = clientId + ":" + clientSecret;
        String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());
        
        // Using Firebase with custom HTTP client for auth
        OkHttpClient okHttpClient = new OkHttpClient();
        
        // ok: java-hardcoded-o-auth-secret
        Request request = new Request.Builder()
                .url("https://oauth2.googleapis.com/token")
                .addHeader("Authorization", "Basic " + encodedCredentials)
                .post(okhttp3.RequestBody.create("grant_type=client_credentials", 
                      okhttp3.MediaType.parse("application/x-www-form-urlencoded")))
                .build();
        
        try (Response response = okHttpClient.newCall(request).execute()) {
            // Use token to initialize Firebase
            String token = response.body().string();
            System.out.println("Got token: " + token);
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

private String getSecretFromGoogleSecretManager(String secretId) {
    // This would be implemented to retrieve secrets from Google Cloud Secret Manager
    // For demonstration, we'll use an environment variable
    return System.getenv("GCP_SECRET_" + secretId.toUpperCase().replace('-', '_'));
}

public void good_case_15() {
    // Kubernetes Java Client with secret from Kubernetes Secrets
    try {
        String clientId = "k8s-client";
        // Simulating retrieval from Kubernetes Secrets
        String clientSecret = getSecretFromKubernetesSecrets("oauth-client-secret");
        String credentials = clientId + ":" + clientSecret;
        String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());
        
        // Custom HTTP client for Kubernetes authentication
        OkHttpClient okHttpClient = new OkHttpClient();
        
        // ok: java-hardcoded-o-auth-secret
        Request request = new Request.Builder()
                .url("https://kubernetes.default.svc/oauth/token")
                .addHeader("Authorization", "Basic " + encodedCredentials)
                .post(okhttp3.RequestBody.create("grant_type=client_credentials", 
                      okhttp3.MediaType.parse("application/x-www-form-urlencoded")))
                .build();
        
        try (Response response = okHttpClient.newCall(request).execute()) {
            // Use token to configure Kubernetes client
            String token = response.body().string();
            System.out.println("Got Kubernetes token: " + token);
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

private String getSecretFromKubernetesSecrets(String secretName) {
    // This would be implemented to retrieve secrets from Kubernetes Secrets
    // For demonstration, we'll use an environment variable
    return System.getenv("K8S_SECRET_" + secretName.toUpperCase().replace('-', '_'));
}

// Main method for demonstration purposes
public static void main(String[] args) {
    System.out.println("This file contains examples of secure and insecure OAuth client secret handling.");
}