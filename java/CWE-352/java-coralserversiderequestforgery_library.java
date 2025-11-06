import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import com.squareup.okhttp.Call;
import com.squareup.okhttp.Callback;

import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.GetObjectRequest;

import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.model.GetObjectRequest.Builder;

import com.azure.storage.blob.BlobClient;
import com.azure.storage.blob.BlobServiceClient;
import com.azure.storage.blob.BlobServiceClientBuilder;

import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

import java.net.http.HttpRequest;
import java.net.http.HttpClient.Builder;
import java.net.http.HttpResponse.BodyHandlers;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.javanet.NetHttpTransport;

import feign.Feign;
import feign.RequestLine;

import kong.unirest.Unirest;

import org.asynchttpclient.AsyncHttpClient;
import org.asynchttpclient.Dsl;

// Security Issue: Server-Side Request Forgery (SSRF) in Coral service

// True Positive Examples (Vulnerable/Insecure Code)
public class CoralServerSideRequestForgeryTest {

// {fact rule=coral-csrf-rule@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) {
        try {
            // Using Java's built-in HttpURLConnection
            String userUrl = request.getParameter("url");
            
            // ruleid: java-coralserversiderequestforgery
            URL url = new URL(userUrl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            
            BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            String inputLine;
            StringBuffer content = new StringBuffer();
            while ((inputLine = in.readLine()) != null) {
                content.append(inputLine);
            }
            in.close();
            connection.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_2(HttpServletRequest request) {
        try {
            // Using Apache HttpClient
            String targetUrl = request.getParameter("target");
            HttpClient client = HttpClients.createDefault();
            
            // ruleid: java-coralserversiderequestforgery
            HttpGet httpGet = new HttpGet(targetUrl);
            HttpResponse response = client.execute(httpGet);
            HttpEntity entity = response.getEntity();
            String result = EntityUtils.toString(entity);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_3(HttpServletRequest request) {
        // Using Spring RestTemplate
        String apiUrl = request.getParameter("api");
        RestTemplate restTemplate = new RestTemplate();
        
        // ruleid: java-coralserversiderequestforgery
        ResponseEntity<String> response = restTemplate.getForEntity(apiUrl, String.class);
        String body = response.getBody();
    }

    public void bad_case_4(HttpServletRequest request) {
        try {
            // Using OkHttp3
            String endpoint = request.getHeader("X-Target-Url");
            OkHttpClient client = new OkHttpClient();
            
            // ruleid: java-coralserversiderequestforgery
            Request okRequest = new Request.Builder()
                    .url(endpoint)
                    .build();
            
            Response response = client.newCall(okRequest).execute();
            String responseBody = response.body().string();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_5(HttpServletRequest request) {
        try {
            // Using Java 11 HttpClient
            String targetUri = request.getParameter("uri");
            java.net.http.HttpClient client = java.net.http.HttpClient.newBuilder().build();
            
            // ruleid: java-coralserversiderequestforgery
            java.net.http.HttpRequest httpRequest = java.net.http.HttpRequest.newBuilder()
                    .uri(URI.create(targetUri))
                    .GET()
                    .build();
            
            java.net.http.HttpResponse<String> response = client.send(httpRequest, BodyHandlers.ofString());
            String body = response.body();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_6(HttpServletRequest request) {
        try {
            // Using JSoup
            String webPage = request.getParameter("page");
            
            // ruleid: java-coralserversiderequestforgery
            Document doc = Jsoup.connect(webPage).get();
            String title = doc.title();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_7(HttpServletRequest request) {
        try {
            // Using Google HTTP Client
            String targetUrl = request.getParameter("target");
            HttpRequestFactory requestFactory = new NetHttpTransport().createRequestFactory();
            
            // ruleid: java-coralserversiderequestforgery
            com.google.api.client.http.HttpRequest googleRequest = 
                requestFactory.buildGetRequest(new GenericUrl(targetUrl));
            
            com.google.api.client.http.HttpResponse googleResponse = googleRequest.execute();
            String content = googleResponse.parseAsString();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_8(HttpServletRequest request) {
        // Using Unirest
        String apiEndpoint = request.getParameter("endpoint");
        
        // ruleid: java-coralserversiderequestforgery
        kong.unirest.HttpResponse<String> response = Unirest.get(apiEndpoint)
                .asString();
        
        String responseBody = response.getBody();
    }

    public void bad_case_9(HttpServletRequest request) {
        try {
            // Using AsyncHttpClient
            String targetUrl = request.getParameter("url");
            AsyncHttpClient asyncClient = Dsl.asyncHttpClient();
            
            // ruleid: java-coralserversiderequestforgery
            org.asynchttpclient.Response response = asyncClient
                    .prepareGet(targetUrl)
                    .execute()
                    .get();
            
            String responseBody = response.getResponseBody();
            asyncClient.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    interface GitHubService {
        @RequestLine("GET")
        String fetchRepo();
    }

    public void bad_case_10(HttpServletRequest request) {
        // Using Feign client
        String baseUrl = request.getParameter("github_url");
        
        // ruleid: java-coralserversiderequestforgery
        GitHubService github = Feign.builder()
                .target(GitHubService.class, baseUrl);
        
        String response = github.fetchRepo();
    }

    public void bad_case_11(HttpServletRequest request) {
        try {
            // Using Retrofit
            String baseUrl = request.getParameter("api_base");
            
            // ruleid: java-coralserversiderequestforgery
            Retrofit retrofit = new Retrofit.Builder()
                    .baseUrl(baseUrl)
                    .addConverterFactory(GsonConverterFactory.create())
                    .build();
            
            // Further API calls would be made using this retrofit instance
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_12(HttpServletRequest request) {
        try {
            // Using URLConnection
            String resourceUrl = request.getParameter("resource");
            
            // ruleid: java-coralserversiderequestforgery
            URL url = new URL(resourceUrl);
            URLConnection connection = url.openConnection();
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            String line;
            StringBuilder content = new StringBuilder();
            while ((line = reader.readLine()) != null) {
                content.append(line);
            }
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_13(HttpServletRequest request) {
        try {
            // Using OkHttp (older version)
            String targetUrl = request.getParameter("target");
            com.squareup.okhttp.OkHttpClient client = new com.squareup.okhttp.OkHttpClient();
            
            // ruleid: java-coralserversiderequestforgery
            com.squareup.okhttp.Request okRequest = new com.squareup.okhttp.Request.Builder()
                    .url(targetUrl)
                    .build();
            
            com.squareup.okhttp.Response response = client.newCall(okRequest).execute();
            String responseBody = response.body().string();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_14(HttpServletRequest request) {
        try {
            // Using AWS S3 with user-provided URL for redirect
            String userProvidedUrl = request.getParameter("redirect_url");
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            
            // ruleid: java-coralserversiderequestforgery
            GetObjectRequest getObjectRequest = new GetObjectRequest("bucket-name", "key")
                    .withResponseHeaders(Map.of("Location", userProvidedUrl));
            
            s3Client.getObject(getObjectRequest);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_15(HttpServletRequest request) {
        try {
            // Using Azure Blob Storage with user-provided URL
            String userProvidedUrl = request.getParameter("storage_url");
            
            // ruleid: java-coralserversiderequestforgery
            BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
                    .endpoint(userProvidedUrl)
                    .buildClient();
            
            BlobClient blobClient = blobServiceClient
                    .getBlobContainerClient("container")
                    .getBlobClient("blob");
            
            blobClient.downloadToFile("downloaded-file.txt");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // True Negative Examples (Safe/Secure Code)
    public void good_case_1(HttpServletRequest request) {
        try {
            // Using Java's built-in HttpURLConnection with validation
            String userUrl = request.getParameter("url");
            
            // Validate URL against whitelist
            List<String> allowedDomains = List.of("api.example.com", "data.example.org");
            boolean isAllowed = false;
            
            for (String domain : allowedDomains) {
                if (userUrl != null && userUrl.startsWith("https://" + domain)) {
                    isAllowed = true;
                    break;
                }
            }
            
            if (isAllowed) {
                // ok: java-coralserversiderequestforgery
                URL url = new URL(userUrl);
                HttpURLConnection connection = (HttpURLConnection) url.openConnection();
                // Process the connection...
            } else {
                throw new SecurityException("URL is not in the allowed list");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_2(HttpServletRequest request) {
        try {
            // Using Apache HttpClient with URL validation
            String targetUrl = request.getParameter("target");
            
            // Validate URL is internal and not accessing sensitive endpoints
            Pattern validUrlPattern = Pattern.compile("^https://internal\\.example\\.com/api/[a-zA-Z0-9]+$");
            
            if (validUrlPattern.matcher(targetUrl).matches()) {
                HttpClient client = HttpClients.createDefault();
                // ok: java-coralserversiderequestforgery
                HttpGet httpGet = new HttpGet(targetUrl);
                HttpResponse response = client.execute(httpGet);
                // Process response...
            } else {
                throw new SecurityException("Invalid URL format or target");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_3(HttpServletRequest request) {
        // Using Spring RestTemplate with URL validation
        String apiUrl = request.getParameter("api");
        
        // Validate URL is pointing to allowed API endpoints
        Set<String> allowedEndpoints = Set.of(
            "https://api.internal.com/data",
            "https://api.internal.com/users",
            "https://api.internal.com/products"
        );
        
        if (allowedEndpoints.contains(apiUrl)) {
            RestTemplate restTemplate = new RestTemplate();
            // ok: java-coralserversiderequestforgery
            ResponseEntity<String> response = restTemplate.getForEntity(apiUrl, String.class);
            // Process response...
        } else {
            throw new SecurityException("API URL not in allowed list");
        }
    }

    public void good_case_4(HttpServletRequest request) {
        try {
            // Using OkHttp3 with hostname verification
            String endpoint = request.getHeader("X-Target-Url");
            URL url = new URL(endpoint);
            String host = url.getHost();
            
            // Validate hostname
            if ("api.trusted-domain.com".equals(host)) {
                OkHttpClient client = new OkHttpClient();
                // ok: java-coralserversiderequestforgery
                Request okRequest = new Request.Builder()
                        .url(endpoint)
                        .build();
                
                Response response = client.newCall(okRequest).execute();
                // Process response...
            } else {
                throw new SecurityException("Untrusted host: " + host);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_5(HttpServletRequest request) {
        try {
            // Using Java 11 HttpClient with URL path validation
            String targetUri = request.getParameter("uri");
            URI uri = URI.create(targetUri);
            
            // Validate URI is using HTTPS and is from allowed domain
            if ("https".equals(uri.getScheme()) && 
                "api.company.com".equals(uri.getHost()) && 
                uri.getPath().startsWith("/public/")) {
                
                java.net.http.HttpClient client = java.net.http.HttpClient.newBuilder().build();
                // ok: java-coralserversiderequestforgery
                java.net.http.HttpRequest httpRequest = java.net.http.HttpRequest.newBuilder()
                        .uri(uri)
                        .GET()
                        .build();
                
                java.net.http.HttpResponse<String> response = client.send(httpRequest, BodyHandlers.ofString());
                // Process response...
            } else {
                throw new SecurityException("URI validation failed");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_6(HttpServletRequest request) {
        try {
            // Using JSoup with URL validation
            String webPage = request.getParameter("page");
            
            // Validate URL is in allowed domains
            URL url = new URL(webPage);
            List<String> allowedDomains = List.of("docs.example.com", "blog.example.com");
            
            if (allowedDomains.contains(url.getHost())) {
                // ok: java-coralserversiderequestforgery
                Document doc = Jsoup.connect(webPage).get();
                // Process document...
            } else {
                throw new SecurityException("Domain not allowed: " + url.getHost());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_7(HttpServletRequest request) {
        try {
            // Using Google HTTP Client with URL validation
            String targetUrl = request.getParameter("target");
            URL url = new URL(targetUrl);
            
            // Check if URL is using HTTPS and is an allowed domain
            if ("https".equals(url.getProtocol()) && 
                url.getHost().endsWith(".googleapis.com")) {
                
                HttpRequestFactory requestFactory = new NetHttpTransport().createRequestFactory();
                // ok: java-coralserversiderequestforgery
                com.google.api.client.http.HttpRequest googleRequest = 
                    requestFactory.buildGetRequest(new GenericUrl(targetUrl));
                
                com.google.api.client.http.HttpResponse googleResponse = googleRequest.execute();
                // Process response...
            } else {
                throw new SecurityException("URL validation failed");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_8(HttpServletRequest request) {
        // Using Unirest with URL validation
        String apiEndpoint = request.getParameter("endpoint");
        
        // Use a predefined base URL and append only the path from user input
        String basePath = "https://api.trusted-service.com";
        
        // Extract and validate path
        if (apiEndpoint != null && apiEndpoint.startsWith("/") && !apiEndpoint.contains("..")) {
            String validatedUrl = basePath + apiEndpoint;
            
            // ok: java-coralserversiderequestforgery
            kong.unirest.HttpResponse<String> response = Unirest.get(validatedUrl)
                    .asString();
            
            // Process response...
        } else {
            throw new SecurityException("Invalid API endpoint path");
        }
    }

    public void good_case_9(HttpServletRequest request) {
        try {
            // Using AsyncHttpClient with URL validation
            String targetUrl = request.getParameter("url");
            
            // Validate URL is using HTTPS and is from trusted domain
            URL url = new URL(targetUrl);
            if ("https".equals(url.getProtocol()) && 
                "api.internal-system.com".equals(url.getHost())) {
                
                AsyncHttpClient asyncClient = Dsl.asyncHttpClient();
                // ok: java-coralserversiderequestforgery
                org.asynchttpclient.Response response = asyncClient
                        .prepareGet(targetUrl)
                        .execute()
                        .get();
                
                // Process response...
                asyncClient.close();
            } else {
                throw new SecurityException("URL validation failed");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_10(HttpServletRequest request) {
        // Using Feign client with predefined base URL
        String repoName = request.getParameter("repo");
        
        // Use fixed base URL and only append validated path parameter
        String baseUrl = "https://api.github.com";
        
        if (repoName != null && repoName.matches("[a-zA-Z0-9\\-_]+")) {
            String validatedUrl = baseUrl + "/repos/" + repoName;
            
            // ok: java-coralserversiderequestforgery
            GitHubService github = Feign.builder()
                    .target(GitHubService.class, validatedUrl);
            
            // Make API call...
        } else {
            throw new SecurityException("Invalid repository name");
        }
    }

    public void good_case_11(HttpServletRequest request) {
        try {
            // Using Retrofit with fixed base URL
            String apiVersion = request.getParameter("version");
            
            // Validate version parameter
            if (apiVersion != null && apiVersion.matches("v[0-9]+(\\.[0-9]+)*")) {
                // Use fixed base URL
                String baseUrl = "https://api.company.com/" + apiVersion + "/";
                
                // ok: java-coralserversiderequestforgery
                Retrofit retrofit = new Retrofit.Builder()
                        .baseUrl(baseUrl)
                        .addConverterFactory(GsonConverterFactory.create())
                        .build();
                
                // Use retrofit instance...
            } else {
                throw new SecurityException("Invalid API version format");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_12(HttpServletRequest request) {
        try {
            // Using URLConnection with URL validation
            String resourceId = request.getParameter("id");
            
            // Validate ID and construct URL from trusted base
            if (resourceId != null && resourceId.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")) {
                String validatedUrl = "https://resources.internal.com/api/resource/" + resourceId;
                
                // ok: java-coralserversiderequestforgery
                URL url = new URL(validatedUrl);
                URLConnection connection = url.openConnection();
                
                // Process connection...
            } else {
                throw new SecurityException("Invalid resource ID format");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_13(HttpServletRequest request) {
        try {
            // Using OkHttp (older version) with URL validation
            String path = request.getParameter("path");
            
            // Validate path and construct URL with fixed base
            if (path != null && path.matches("^[a-zA-Z0-9\\-_/]+$") && !path.contains("..")) {
                String validatedUrl = "https://api.trusted-service.com/" + path;
                
                com.squareup.okhttp.OkHttpClient client = new com.squareup.okhttp.OkHttpClient();
                // ok: java-coralserversiderequestforgery
                com.squareup.okhttp.Request okRequest = new com.squareup.okhttp.Request.Builder()
                        .url(validatedUrl)
                        .build();
                
                // Process request...
            } else {
                throw new SecurityException("Invalid path format");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_14(HttpServletRequest request) {
        try {
            // Using AWS S3 with fixed endpoints
            String bucketName = request.getParameter("bucket");
            String objectKey = request.getParameter("key");
            
            // Validate bucket name and object key
            if (bucketName != null && bucketName.matches("^[a-z0-9][a-z0-9\\-]{1,61}[a-z0-9]$") &&
                objectKey != null && objectKey.matches("^[a-zA-Z0-9\\-_./]+$") && !objectKey.contains("..")) {
                
                AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
                
                // ok: java-coralserversiderequestforgery
                GetObjectRequest getObjectRequest = new GetObjectRequest(bucketName, objectKey);
                
                s3Client.getObject(getObjectRequest);
            } else {
                throw new SecurityException("Invalid bucket name or object key");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_15(HttpServletRequest request) {
        try {
            // Using Azure Blob Storage with fixed endpoint
            String containerName = request.getParameter("container");
            String blobName = request.getParameter("blob");
            
            // Fixed storage account URL
            String storageUrl = "https://mycompanystorage.blob.core.windows.net";
            
            // Validate container and blob names
            if (containerName != null && containerName.matches("^[a-z0-9][a-z0-9\\-]{1,61}[a-z0-9]$") &&
                blobName != null && blobName.matches("^[a-zA-Z0-9\\-_./]+$") && !blobName.contains("..")) {
                
                // ok: java-coralserversiderequestforgery
                BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
                        .endpoint(storageUrl)
                        .buildClient();
                
                BlobClient blobClient = blobServiceClient
                        .getBlobContainerClient(containerName)
                        .getBlobClient(blobName);
                
                blobClient.downloadToFile("downloaded-file.txt");
            } else {
                throw new SecurityException("Invalid container or blob name");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
// {/fact}