import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.mashape.unirest.http.Unirest;
import com.squareup.okhttp.Call;

import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;
import retrofit2.http.GET;
import retrofit2.http.Url;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

import kong.unirest.HttpResponse;

import feign.Feign;
import feign.RequestLine;

import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;

import org.asynchttpclient.AsyncHttpClient;
import org.asynchttpclient.Dsl;

import io.vertx.core.Vertx;
import io.vertx.ext.web.client.WebClient;

import java.io.InputStream;
import java.net.InetAddress;
import java.util.HashSet;
import java.util.Set;

// Security Issue: Server-Side Request Forgery (SSRF) - CWE-918
// This vulnerability occurs when an application makes HTTP requests to an arbitrary domain specified by the user
// without proper validation, potentially allowing attackers to access internal services or perform actions on behalf of the server.

@RestController
public class SSRFVulnerabilityExamples {

    // True Positive Examples (Vulnerable/Insecure Code)
    
    // Example 1: Using java.net.URL with user input
// {fact rule=server-side-request-forgery@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) {
        try {
            String userInput = request.getParameter("url");
            
            // ruleid: java-server-side-request-forgery
            URL url = new URL(userInput);
            URLConnection connection = url.openConnection();
            BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            
            String inputLine;
            StringBuilder content = new StringBuilder();
            while ((inputLine = in.readLine()) != null) {
                content.append(inputLine);
            }
            in.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Example 2: Using Apache HttpClient with user input
    public void bad_case_2(HttpServletRequest request) {
        String userUrl = request.getParameter("targetUrl");
        
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            // ruleid: java-server-side-request-forgery
            HttpGet httpGet = new HttpGet(userUrl);
            CloseableHttpResponse response = httpClient.execute(httpGet);
            
            // Process response
            BufferedReader reader = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
            StringBuilder result = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                result.append(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    // Example 3: Using Spring RestTemplate with user input
    @GetMapping("/fetch-data")
    public String bad_case_3(@RequestParam String remoteUrl) {
        RestTemplate restTemplate = new RestTemplate();
        
        // ruleid: java-server-side-request-forgery
        String result = restTemplate.getForObject(remoteUrl, String.class);
        
        return result;
    }
    
    // Example 4: Using OkHttp library with user input
    public void bad_case_4(HttpServletRequest request) {
        String targetUrl = request.getParameter("url");
        OkHttpClient client = new OkHttpClient();
        
        // ruleid: java-server-side-request-forgery
        Request okHttpRequest = new Request.Builder()
                .url(targetUrl)
                .build();
                
        try {
            Response response = client.newCall(okHttpRequest).execute();
            String responseBody = response.body().string();
            System.out.println(responseBody);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    // Example 5: Using Google HTTP Client with user input
    public void bad_case_5(HttpServletRequest request) {
        try {
            String userUrl = request.getParameter("targetUrl");
            HttpRequestFactory requestFactory = new NetHttpTransport().createRequestFactory();
            
            // ruleid: java-server-side-request-forgery
            HttpRequest googleRequest = requestFactory.buildGetRequest(new GenericUrl(userUrl));
            String rawResponse = googleRequest.execute().parseAsString();
            
            System.out.println("Response: " + rawResponse);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    // Example 6: Using Unirest library with user input
    public void bad_case_6(HttpServletRequest request) {
        String targetUrl = request.getParameter("endpoint");
        
        try {
            // ruleid: java-server-side-request-forgery
            com.mashape.unirest.http.HttpResponse<String> response = Unirest.get(targetUrl).asString();
            System.out.println("Status: " + response.getStatus());
            System.out.println("Body: " + response.getBody());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Example 7: Using JSoup with user input
    public void bad_case_7(HttpServletRequest request) {
        String webpageUrl = request.getParameter("webpage");
        
        try {
            // ruleid: java-server-side-request-forgery
            Document doc = Jsoup.connect(webpageUrl).get();
            String title = doc.title();
            System.out.println("Title: " + title);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    // Example 8: Using Retrofit with user input
    public void bad_case_8(HttpServletRequest request) {
        String baseUrl = request.getParameter("api");
        
        interface ApiService {
            @GET
            retrofit2.Call<String> getDataFromUrl(@Url String url);
        }
        
        Retrofit retrofit = new Retrofit.Builder()
                .baseUrl("http://example.com/") // Placeholder base URL
                .addConverterFactory(GsonConverterFactory.create())
                .build();
        
        ApiService service = retrofit.create(ApiService.class);
        
        try {
            // ruleid: java-server-side-request-forgery
            retrofit2.Call<String> call = service.getDataFromUrl(baseUrl);
            retrofit2.Response<String> response = call.execute();
            if (response.isSuccessful()) {
                System.out.println(response.body());
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    // Example 9: Using Kong Unirest with user input
    public void bad_case_9(HttpServletRequest request) {
        String apiUrl = request.getParameter("apiEndpoint");
        
        // ruleid: java-server-side-request-forgery
        HttpResponse<String> response = kong.unirest.Unirest.get(apiUrl).asString();
        
        if (response.isSuccess()) {
            System.out.println("Response: " + response.getBody());
        }
    }
    
    // Example 10: Using Feign client with user input
    public void bad_case_10(HttpServletRequest request) {
        String dynamicUrl = request.getParameter("service");
        
        interface DynamicClient {
            @RequestLine("GET")
            String getData();
        }
        
        // ruleid: java-server-side-request-forgery
        DynamicClient client = Feign.builder()
                .target(DynamicClient.class, dynamicUrl);
        
        String response = client.getData();
        System.out.println(response);
    }
    
    // Example 11: Using AsyncHttpClient with user input
    public void bad_case_11(HttpServletRequest request) {
        String targetUrl = request.getParameter("target");
        
        try (AsyncHttpClient asyncHttpClient = Dsl.asyncHttpClient()) {
            // ruleid: java-server-side-request-forgery
            org.asynchttpclient.Response response = asyncHttpClient
                    .prepareGet(targetUrl)
                    .execute()
                    .get();
            
            System.out.println(response.getResponseBody());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Example 12: Using Vert.x WebClient with user input
    public void bad_case_12(HttpServletRequest request) {
        String url = request.getParameter("resource");
        
        Vertx vertx = Vertx.vertx();
        WebClient client = WebClient.create(vertx);
        
        URI uri;
        try {
            uri = new URI(url);
            // ruleid: java-server-side-request-forgery
            client.get(uri.getPort(), uri.getHost(), uri.getPath())
                  .send(ar -> {
                      if (ar.succeeded()) {
                          System.out.println("Got HTTP response with status " + ar.result().statusCode());
                      } else {
                          System.out.println("Something went wrong " + ar.cause().getMessage());
                      }
                      vertx.close();
                  });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Example 13: Using java.net.HttpURLConnection with user input
    public void bad_case_13(HttpServletRequest request) {
        String urlString = request.getParameter("endpoint");
        
        try {
            URL url = new URL(urlString);
            // ruleid: java-server-side-request-forgery
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            
            BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            String inputLine;
            StringBuilder content = new StringBuilder();
            while ((inputLine = in.readLine()) != null) {
                content.append(inputLine);
            }
            in.close();
            connection.disconnect();
            
            System.out.println(content.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Example 14: Using AWS S3 client with user input
    public void bad_case_14(HttpServletRequest request) {
        String bucketName = "my-bucket";
        String objectKey = request.getParameter("objectKey");
        
        S3Client s3 = S3Client.builder().build();
        
        // ruleid: java-server-side-request-forgery
        GetObjectRequest getObjectRequest = GetObjectRequest.builder()
                .bucket(bucketName)
                .key(objectKey)
                .build();
        
        try (InputStream s3Object = s3.getObject(getObjectRequest)) {
            // Process the object
            BufferedReader reader = new BufferedReader(new InputStreamReader(s3Object));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    // Example 15: Using InetAddress with user input
    public void bad_case_15(HttpServletRequest request) {
        String hostInput = request.getParameter("hostname");
        
        try {
            // ruleid: java-server-side-request-forgery
            InetAddress address = InetAddress.getByName(hostInput);
            System.out.println("Host name: " + address.getHostName());
            System.out.println("IP address: " + address.getHostAddress());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // True Negative Examples (Safe/Secure Code)
    
    // Example 1: Using java.net.URL with allowlist validation
    public void good_case_1(HttpServletRequest request) {
        try {
            String userInput = request.getParameter("url");
            
            // Define allowed domains
            Set<String> allowedDomains = new HashSet<>(Arrays.asList(
                    "api.example.com", "data.example.com", "content.example.org"));
            
            URL url = new URL(userInput);
            String host = url.getHost();
            
            if (allowedDomains.contains(host)) {
                // ok: java-server-side-request-forgery
                URLConnection connection = url.openConnection();
                BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                
                String inputLine;
                StringBuilder content = new StringBuilder();
                while ((inputLine = in.readLine()) != null) {
                    content.append(inputLine);
                }
                in.close();
            } else {
                throw new SecurityException("Domain not allowed: " + host);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Example 2: Using Apache HttpClient with URL validation
    public void good_case_2(HttpServletRequest request) {
        String userUrl = request.getParameter("targetUrl");
        
        try {
            URL url = new URL(userUrl);
            String host = url.getHost();
            
            // Validate URL is pointing to allowed domains
            if (host.endsWith(".example.com") || host.equals("example.com")) {
                try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
                    // ok: java-server-side-request-forgery
                    HttpGet httpGet = new HttpGet(userUrl);
                    CloseableHttpResponse response = httpClient.execute(httpGet);
                    
                    // Process response
                    BufferedReader reader = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
                    StringBuilder result = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        result.append(line);
                    }
                }
            } else {
                System.out.println("URL not allowed: " + userUrl);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    // Example 3: Using Spring RestTemplate with URL validation regex
    @GetMapping("/fetch-data-safe")
    public String good_case_3(@RequestParam String remoteUrl) {
        // Validate URL pattern
        Pattern validUrlPattern = Pattern.compile("^https://api\\.mycompany\\.com/v[0-9]+/.*$");
        
        if (validUrlPattern.matcher(remoteUrl).matches()) {
            RestTemplate restTemplate = new RestTemplate();
            
            // ok: java-server-side-request-forgery
            String result = restTemplate.getForObject(remoteUrl, String.class);
            return result;
        } else {
            return "Invalid URL pattern";
        }
    }
    
    // Example 4: Using OkHttp with URL validation and fixed base URL
    public void good_case_4(HttpServletRequest request) {
        String endpoint = request.getParameter("endpoint");
        
        // Validate endpoint is just a path without protocol or domain
        if (endpoint.startsWith("/") && !endpoint.contains("://") && !endpoint.contains("..")) {
            String baseUrl = "https://api.myservice.com";
            String fullUrl = baseUrl + endpoint;
            
            OkHttpClient client = new OkHttpClient();
            
            // ok: java-server-side-request-forgery
            Request okHttpRequest = new Request.Builder()
                    .url(fullUrl)
                    .build();
                    
            try {
                Response response = client.newCall(okHttpRequest).execute();
                String responseBody = response.body().string();
                System.out.println(responseBody);
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else {
            System.out.println("Invalid endpoint path");
        }
    }
    
    // Example 5: Using Google HTTP Client with predefined URLs
    public void good_case_5(HttpServletRequest request) {
        try {
            String apiEndpoint = request.getParameter("endpoint");
            
            // Map user input to predefined URLs
            Map<String, String> allowedEndpoints = Map.of(
                "users", "https://api.example.com/users",
                "products", "https://api.example.com/products",
                "orders", "https://api.example.com/orders"
            );
            
            if (allowedEndpoints.containsKey(apiEndpoint)) {
                String safeUrl = allowedEndpoints.get(apiEndpoint);
                HttpRequestFactory requestFactory = new NetHttpTransport().createRequestFactory();
                
                // ok: java-server-side-request-forgery
                HttpRequest googleRequest = requestFactory.buildGetRequest(new GenericUrl(safeUrl));
                String rawResponse = googleRequest.execute().parseAsString();
                
                System.out.println("Response: " + rawResponse);
            } else {
                System.out.println("Invalid endpoint requested");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    // Example 6: Using Unirest with URL validation
    public void good_case_6(HttpServletRequest request) {
        String targetPath = request.getParameter("path");
        
        // Validate path format and construct full URL
        if (targetPath.matches("^[a-zA-Z0-9_/-]+$")) {
            String baseUrl = "https://api.myservice.com";
            String fullUrl = baseUrl + "/" + targetPath;
            
            try {
                // ok: java-server-side-request-forgery
                com.mashape.unirest.http.HttpResponse<String> response = Unirest.get(fullUrl).asString();
                System.out.println("Status: " + response.getStatus());
                System.out.println("Body: " + response.getBody());
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            System.out.println("Invalid path format");
        }
    }
    
    // Example 7: Using JSoup with domain validation
    public void good_case_7(HttpServletRequest request) {
        String webpageUrl = request.getParameter("webpage");
        
        try {
            URL url = new URL(webpageUrl);
            String host = url.getHost();
            
            // Check if domain is allowed
            List<String> allowedDomains = Arrays.asList("example.com", "example.org", "trusted-site.com");
            boolean isDomainAllowed = allowedDomains.stream().anyMatch(host::endsWith);
            
            if (isDomainAllowed) {
                // ok: java-server-side-request-forgery
                Document doc = Jsoup.connect(webpageUrl).get();
                String title = doc.title();
                System.out.println("Title: " + title);
            } else {
                System.out.println("Domain not allowed: " + host);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    // Example 8: Using Retrofit with fixed base URL
    public void good_case_8(HttpServletRequest request) {
        String endpoint = request.getParameter("endpoint");
        
        // Validate endpoint is just a path
        if (endpoint.matches("^/[a-zA-Z0-9_/-]+$")) {
            interface ApiService {
                @GET
                retrofit2.Call<String> getDataFromPath(@Url String path);
            }
            
            // Fixed base URL
            Retrofit retrofit = new Retrofit.Builder()
                    .baseUrl("https://api.mycompany.com/")
                    .addConverterFactory(GsonConverterFactory.create())
                    .build();
            
            ApiService service = retrofit.create(ApiService.class);
            
            try {
                // ok: java-server-side-request-forgery
                retrofit2.Call<String> call = service.getDataFromPath(endpoint);
                retrofit2.Response<String> response = call.execute();
                if (response.isSuccessful()) {
                    System.out.println(response.body());
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else {
            System.out.println("Invalid endpoint format");
        }
    }
    
    // Example 9: Using Kong Unirest with URL validation
    public void good_case_9(HttpServletRequest request) {
        String resourceId = request.getParameter("id");
        
        // Validate ID format
        if (resourceId.matches("^[0-9]+$")) {
            String safeUrl = "https://api.example.com/resources/" + resourceId;
            
            // ok: java-server-side-request-forgery
            HttpResponse<String> response = kong.unirest.Unirest.get(safeUrl).asString();
            
            if (response.isSuccess()) {
                System.out.println("Response: " + response.getBody());
            }
        } else {
            System.out.println("Invalid resource ID format");
        }
    }
    
    // Example 10: Using Feign client with fixed URL
    public void good_case_10(HttpServletRequest request) {
        String resourceType = request.getParameter("type");
        
        // Validate and map to fixed URLs
        Map<String, String> serviceMap = Map.of(
            "users", "https://users-api.example.com",
            "products", "https://products-api.example.com",
            "orders", "https://orders-api.example.com"
        );
        
        if (serviceMap.containsKey(resourceType)) {
            String serviceUrl = serviceMap.get(resourceType);
            
            interface ServiceClient {
                @RequestLine("GET /api/v1/data")
                String getData();
            }
            
            // ok: java-server-side-request-forgery
            ServiceClient client = Feign.builder()
                    .target(ServiceClient.class, serviceUrl);
            
            String response = client.getData();
            System.out.println(response);
        } else {
            System.out.println("Invalid resource type");
        }
    }
    
    // Example 11: Using AsyncHttpClient with URL validation
    public void good_case_11(HttpServletRequest request) {
        String resourceId = request.getParameter("id");
        
        // Validate ID and construct safe URL
        if (resourceId.matches("^[a-zA-Z0-9-]+$")) {
            String safeUrl = "https://api.myservice.com/resources/" + resourceId;
            
            try (AsyncHttpClient asyncHttpClient = Dsl.asyncHttpClient()) {
                // ok: java-server-side-request-forgery
                org.asynchttpclient.Response response = asyncHttpClient
                        .prepareGet(safeUrl)
                        .execute()
                        .get();
                
                System.out.println(response.getResponseBody());
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            System.out.println("Invalid resource ID format");
        }
    }
    
    // Example 12: Using Vert.x WebClient with fixed host and port
    public void good_case_12(HttpServletRequest request) {
        String path = request.getParameter("path");
        
        // Validate path format
        if (path.matches("^/[a-zA-Z0-9_/-]+$")) {
            Vertx vertx = Vertx.vertx();
            WebClient client = WebClient.create(vertx);
            
            // Fixed host and port
            String host = "api.mycompany.com";
            int port = 443;
            
            // ok: java-server-side-request-forgery
            client.get(port, host, path)
                  .ssl(true)
                  .send(ar -> {
                      if (ar.succeeded()) {
                          System.out.println("Got HTTP response with status " + ar.result().statusCode());
                      } else {
                          System.out.println("Something went wrong " + ar.cause().getMessage());
                      }
                      vertx.close();
                  });
        } else {
            System.out.println("Invalid path format");
        }
    }
    
    // Example 13: Using java.net.HttpURLConnection with URL validation
    public void good_case_13(HttpServletRequest request) {
        String apiPath = request.getParameter("path");
        
        try {
            // Validate path and construct URL
            if (apiPath.matches("^[a-zA-Z0-9_/-]+$")) {
                String baseUrl = "https://api.example.com/";
                URL url = new URL(baseUrl + apiPath);
                
                // Verify host is as expected
                if ("api.example.com".equals(url.getHost())) {
                    // ok: java-server-side-request-forgery
                    HttpURLConnection connection = (HttpURLConnection) url.openConnection();
                    connection.setRequestMethod("GET");
                    
                    BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                    String inputLine;
                    StringBuilder content = new StringBuilder();
                    while ((inputLine = in.readLine()) != null) {
                        content.append(inputLine);
                    }
                    in.close();
                    connection.disconnect();
                    
                    System.out.println(content.toString());
                } else {
                    System.out.println("URL host validation failed");
                }
            } else {
                System.out.println("Invalid API path format");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Example 14: Using AWS S3 client with input validation
    public void good_case_14(HttpServletRequest request) {
        String objectKey = request.getParameter("objectKey");
        
        // Validate object key format and prefix
        if (objectKey.matches("^[a-zA-Z0-9/_.-]+$") && objectKey.startsWith("public/")) {
            String bucketName = "my-bucket";
            
            S3Client s3 = S3Client.builder().build();
            
            // ok: java-server-side-request-forgery
            GetObjectRequest getObjectRequest = GetObjectRequest.builder()
                    .bucket(bucketName)
                    .key(objectKey)
                    .build();
            
            try (InputStream s3Object = s3.getObject(getObjectRequest)) {
                // Process the object
                BufferedReader reader = new BufferedReader(new InputStreamReader(s3Object));
                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println(line);
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else {
            System.out.println("Invalid object key format or unauthorized access attempt");
        }
    }
    
    // Example 15: Using InetAddress with allowlist validation
    public void good_case_15(HttpServletRequest request) {
        String hostInput = request.getParameter("hostname");
        
        // Define allowed hosts
        List<String> allowedHosts = Arrays.asList(
                "api.example.com", 
                "service.example.com", 
                "database.internal.net");
        
        if (allowedHosts.contains(hostInput)) {
            try {
                // ok: java-server-side-request-forgery
                InetAddress address = InetAddress.getByName(hostInput);
                System.out.println("Host name: " + address.getHostName());
                System.out.println("IP address: " + address.getHostAddress());
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            System.out.println("Host not in allowed list: " + hostInput);
        }
    }
}
// {/fact}