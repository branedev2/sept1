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

import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;

import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.javanet.NetHttpTransport;

import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;

import org.asynchttpclient.AsyncHttpClient;
import org.asynchttpclient.Dsl;

import kong.unirest.HttpResponse;

import io.vertx.core.Vertx;
import io.vertx.ext.web.client.WebClient;

import org.eclipse.jetty.client.HttpClient;

import java.net.http.HttpClient.Builder;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;

// Security Issue: Server-Side Request Forgery (SSRF) - CWE-918
// This file demonstrates various scenarios where user input from HTTP requests is used to make 
// server-side requests without proper validation, which can lead to SSRF vulnerabilities.

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) {
    try {
        String userProvidedUrl = request.getParameter("url");
        
        // ruleid: java-serversiderequestforgery
        URL url = new URL(userProvidedUrl);
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

public void bad_case_2(HttpServletRequest request) {
    String targetUrl = request.getParameter("target");
    CloseableHttpClient httpClient = HttpClients.createDefault();
    
    try {
        // ruleid: java-serversiderequestforgery
        HttpGet httpGet = new HttpGet(targetUrl);
        CloseableHttpResponse response = httpClient.execute(httpGet);
        
        // Process response
        httpClient.close();
    } catch (IOException e) {
        e.printStackTrace();
    }
}

@RestController
public class bad_case_3 {
    
    @GetMapping("/fetch")
    public String fetchUrl(@RequestParam String url) {
        RestTemplate restTemplate = new RestTemplate();
        
        // ruleid: java-serversiderequestforgery
        String result = restTemplate.getForObject(url, String.class);
        
        return result;
    }
}

public void bad_case_4(HttpServletRequest request) {
    String url = request.getParameter("url");
    OkHttpClient client = new OkHttpClient();
    
    try {
        // ruleid: java-serversiderequestforgery
        Request okHttpRequest = new Request.Builder()
            .url(url)
            .build();
        
        Response response = client.newCall(okHttpRequest).execute();
        String responseBody = response.body().string();
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_5(HttpServletRequest request) {
    String url = request.getParameter("site");
    
    try {
        // ruleid: java-serversiderequestforgery
        com.mashape.unirest.http.HttpResponse<String> response = Unirest.get(url)
            .asString();
        
        String body = response.getBody();
    } catch (UnirestException e) {
        e.printStackTrace();
    }
}

public void bad_case_6(HttpServletRequest request) {
    try {
        String userUrl = request.getParameter("document");
        
        // ruleid: java-serversiderequestforgery
        Document doc = Jsoup.connect(userUrl).get();
        String title = doc.title();
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_7(HttpServletRequest request) {
    try {
        String targetUrl = request.getParameter("api");
        HttpRequestFactory requestFactory = new NetHttpTransport().createRequestFactory();
        
        // ruleid: java-serversiderequestforgery
        HttpRequest googleRequest = requestFactory.buildGetRequest(new GenericUrl(targetUrl));
        String rawResponse = googleRequest.execute().parseAsString();
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_8(HttpServletRequest request) {
    String baseUrl = request.getParameter("service");
    
    // ruleid: java-serversiderequestforgery
    Retrofit retrofit = new Retrofit.Builder()
        .baseUrl(baseUrl)
        .addConverterFactory(GsonConverterFactory.create())
        .build();
    
    // Service interface would be used here
}

public void bad_case_9(HttpServletRequest request) {
    String targetUrl = request.getParameter("target");
    AsyncHttpClient asyncHttpClient = Dsl.asyncHttpClient();
    
    try {
        // ruleid: java-serversiderequestforgery
        org.asynchttpclient.Response response = asyncHttpClient
            .prepareGet(targetUrl)
            .execute()
            .get();
    } catch (Exception e) {
        e.printStackTrace();
    } finally {
        try {
            asyncHttpClient.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

public void bad_case_10(HttpServletRequest request) {
    String url = request.getParameter("endpoint");
    
    // ruleid: java-serversiderequestforgery
    HttpResponse<String> response = kong.unirest.Unirest.get(url)
        .asString();
    
    String responseBody = response.getBody();
}

public void bad_case_11(HttpServletRequest request, Vertx vertx) {
    String url = request.getParameter("resource");
    WebClient client = WebClient.create(vertx);
    
    URI uri;
    try {
        uri = new URI(url);
        int port = uri.getPort() > 0 ? uri.getPort() : 80;
        
        // ruleid: java-serversiderequestforgery
        client.get(port, uri.getHost(), uri.getPath())
            .send(ar -> {
                if (ar.succeeded()) {
                    String body = ar.result().bodyAsString();
                    System.out.println("Response: " + body);
                } else {
                    System.out.println("Error: " + ar.cause().getMessage());
                }
            });
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_12(HttpServletRequest request) {
    String targetUrl = request.getParameter("fetch");
    
    try {
        HttpClient client = new HttpClient();
        client.start();
        
        // ruleid: java-serversiderequestforgery
        org.eclipse.jetty.client.api.ContentResponse response = client.GET(targetUrl);
        
        String content = response.getContentAsString();
        client.stop();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_13(HttpServletRequest request) {
    String url = request.getParameter("api");
    
    try {
        java.net.http.HttpClient client = java.net.http.HttpClient.newHttpClient();
        
        // ruleid: java-serversiderequestforgery
        java.net.http.HttpRequest httpRequest = java.net.http.HttpRequest.newBuilder()
            .uri(URI.create(url))
            .build();
        
        java.net.http.HttpResponse<String> response = client.send(
            httpRequest, 
            BodyHandlers.ofString()
        );
        
        String body = response.body();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_14(HttpServletRequest request) {
    String urlString = request.getHeader("X-Forward-Url");
    
    try {
        // ruleid: java-serversiderequestforgery
        URL url = new URL(urlString);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(connection.getInputStream())
        );
        
        String line;
        StringBuilder response = new StringBuilder();
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        reader.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_15(HttpServletRequest request) {
    // Extract URL from request body
    String jsonBody = "";
    try {
        BufferedReader reader = request.getReader();
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            sb.append(line);
        }
        jsonBody = sb.toString();
    } catch (Exception e) {
        e.printStackTrace();
    }
    
    // Assume we extract a URL from JSON
    String extractedUrl = jsonBody.split("\"url\":\"")[1].split("\"")[0];
    
    try {
        // ruleid: java-serversiderequestforgery
        URL url = new URL(extractedUrl);
        URLConnection conn = url.openConnection();
        BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        
        String inputLine;
        while ((inputLine = in.readLine()) != null) {
            System.out.println(inputLine);
        }
        in.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) {
    try {
        String userProvidedUrl = request.getParameter("url");
        
        // Whitelist validation
        List<String> allowedDomains = Arrays.asList("api.example.com", "data.example.org");
        URL url = new URL(userProvidedUrl);
        String host = url.getHost();
        
        if (!allowedDomains.contains(host)) {
            throw new SecurityException("Domain not allowed");
        }
        
        // ok: java-serversiderequestforgery
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

public void good_case_2(HttpServletRequest request) {
    String targetUrl = request.getParameter("target");
    CloseableHttpClient httpClient = HttpClients.createDefault();
    
    try {
        // Validate URL is pointing to allowed resources
        URL url = new URL(targetUrl);
        if (!url.getHost().endsWith(".trusted-domain.com")) {
            throw new SecurityException("URL not allowed");
        }
        
        // ok: java-serversiderequestforgery
        HttpGet httpGet = new HttpGet(targetUrl);
        CloseableHttpResponse response = httpClient.execute(httpGet);
        
        // Process response
        httpClient.close();
    } catch (IOException | SecurityException e) {
        e.printStackTrace();
    }
}

@RestController
public class good_case_3 {
    
    private final List<String> ALLOWED_DOMAINS = Arrays.asList(
        "api.internal.com", "data.company.org"
    );
    
    @GetMapping("/fetch")
    public String fetchUrl(@RequestParam String url) {
        RestTemplate restTemplate = new RestTemplate();
        
        try {
            URL parsedUrl = new URL(url);
            String host = parsedUrl.getHost();
            
            // Validate against whitelist
            if (!ALLOWED_DOMAINS.contains(host)) {
                return "Access denied: Domain not in whitelist";
            }
            
            // ok: java-serversiderequestforgery
            String result = restTemplate.getForObject(url, String.class);
            return result;
        } catch (MalformedURLException e) {
            return "Invalid URL";
        }
    }
}

public void good_case_4(HttpServletRequest request) {
    String url = request.getParameter("url");
    OkHttpClient client = new OkHttpClient();
    
    try {
        // Validate URL scheme (only allow HTTP/HTTPS)
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            throw new IllegalArgumentException("Only HTTP/HTTPS URLs are allowed");
        }
        
        // Validate URL is not accessing internal resources
        URL parsedUrl = new URL(url);
        String host = parsedUrl.getHost();
        if (host.equals("localhost") || host.equals("127.0.0.1") || host.contains("192.168.") || 
            host.contains("10.") || host.equals("0.0.0.0")) {
            throw new SecurityException("Access to internal resources is forbidden");
        }
        
        // ok: java-serversiderequestforgery
        Request okHttpRequest = new Request.Builder()
            .url(url)
            .build();
        
        Response response = client.newCall(okHttpRequest).execute();
        String responseBody = response.body().string();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_5(HttpServletRequest request) {
    String url = request.getParameter("site");
    
    // Define regex pattern for allowed URLs
    Pattern pattern = Pattern.compile("^https?://([a-zA-Z0-9-]+\\.)*example\\.com(/.*)?$");
    
    try {
        // Validate URL against pattern
        if (!pattern.matcher(url).matches()) {
            throw new SecurityException("URL does not match allowed pattern");
        }
        
        // ok: java-serversiderequestforgery
        com.mashape.unirest.http.HttpResponse<String> response = Unirest.get(url)
            .asString();
        
        String body = response.getBody();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_6(HttpServletRequest request) {
    try {
        String userUrl = request.getParameter("document");
        
        // Use URL parser to validate components
        URL parsedUrl = new URL(userUrl);
        String protocol = parsedUrl.getProtocol();
        String host = parsedUrl.getHost();
        
        // Only allow specific protocol and domain
        if (!"https".equals(protocol) || !host.endsWith(".trusted-docs.com")) {
            throw new SecurityException("Invalid URL: only HTTPS URLs from trusted-docs.com are allowed");
        }
        
        // ok: java-serversiderequestforgery
        Document doc = Jsoup.connect(userUrl).get();
        String title = doc.title();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_7(HttpServletRequest request) {
    try {
        // Instead of using user input directly, use a predefined API endpoint and append safe parameters
        String apiId = request.getParameter("api_id");
        
        // Validate apiId format (e.g., only alphanumeric)
        if (!apiId.matches("^[a-zA-Z0-9]+$")) {
            throw new IllegalArgumentException("Invalid API ID format");
        }
        
        // Construct URL with safe base and validated parameter
        String safeBaseUrl = "https://api.company.com/v1/";
        String targetUrl = safeBaseUrl + "resources/" + apiId;
        
        HttpRequestFactory requestFactory = new NetHttpTransport().createRequestFactory();
        
        // ok: java-serversiderequestforgery
        HttpRequest googleRequest = requestFactory.buildGetRequest(new GenericUrl(targetUrl));
        String rawResponse = googleRequest.execute().parseAsString();
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_8(HttpServletRequest request) {
    // Instead of using user input for the base URL, use a fixed base URL
    String serviceId = request.getParameter("service");
    
    // Validate serviceId
    if (!serviceId.matches("^[a-z0-9-]+$")) {
        throw new IllegalArgumentException("Invalid service ID");
    }
    
    // Use a fixed base URL
    String baseUrl = "https://api.company.com/";
    
    // ok: java-serversiderequestforgery
    Retrofit retrofit = new Retrofit.Builder()
        .baseUrl(baseUrl) // Fixed, trusted base URL
        .addConverterFactory(GsonConverterFactory.create())
        .build();
    
    // Service interface would be used here with the validated serviceId as a parameter
}

public void good_case_9(HttpServletRequest request) {
    // Use a URL builder with fixed components and validated parameters
    String resourceId = request.getParameter("resource");
    
    // Validate resourceId
    if (!resourceId.matches("^[a-zA-Z0-9_-]+$")) {
        throw new IllegalArgumentException("Invalid resource ID");
    }
    
    // Build URL with fixed trusted domain and path
    String targetUrl = "https://api.trusted-service.com/resources/" + resourceId;
    
    AsyncHttpClient asyncHttpClient = Dsl.asyncHttpClient();
    
    try {
        // ok: java-serversiderequestforgery
        org.asynchttpclient.Response response = asyncHttpClient
            .prepareGet(targetUrl)
            .execute()
            .get();
    } catch (Exception e) {
        e.printStackTrace();
    } finally {
        try {
            asyncHttpClient.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

public void good_case_10(HttpServletRequest request) {
    // Use an enum to limit possible endpoints
    String endpointName = request.getParameter("endpoint");
    
    // Map of allowed endpoints
    Map<String, String> allowedEndpoints = Map.of(
        "users", "https://api.example.com/users",
        "products", "https://api.example.com/products",
        "orders", "https://api.example.com/orders"
    );
    
    // Check if requested endpoint is allowed
    if (!allowedEndpoints.containsKey(endpointName)) {
        throw new IllegalArgumentException("Endpoint not allowed");
    }
    
    String url = allowedEndpoints.get(endpointName);
    
    // ok: java-serversiderequestforgery
    HttpResponse<String> response = kong.unirest.Unirest.get(url)
        .asString();
    
    String responseBody = response.getBody();
}

public void good_case_11(HttpServletRequest request, Vertx vertx) {
    String resourceType = request.getParameter("type");
    String resourceId = request.getParameter("id");
    
    // Validate parameters
    if (!resourceType.matches("^[a-z]+$") || !resourceId.matches("^[0-9]+$")) {
        throw new IllegalArgumentException("Invalid resource parameters");
    }
    
    // Construct URL with fixed host and validated parameters
    String host = "api.internal-service.com";
    String path = "/" + resourceType + "/" + resourceId;
    
    WebClient client = WebClient.create(vertx);
    
    // ok: java-serversiderequestforgery
    client.get(443, host, path)
        .ssl(true)
        .send(ar -> {
            if (ar.succeeded()) {
                String body = ar.result().bodyAsString();
                System.out.println("Response: " + body);
            } else {
                System.out.println("Error: " + ar.cause().getMessage());
            }
        });
}

public void good_case_12(HttpServletRequest request) {
    // Use a predefined set of URLs
    String urlKey = request.getParameter("resource");
    
    // Map keys to actual URLs
    Map<String, String> urlMap = Map.of(
        "weather", "https://api.weather.com/current",
        "news", "https://api.news.com/latest",
        "stocks", "https://api.stocks.com/market"
    );
    
    // Check if key exists in map
    if (!urlMap.containsKey(urlKey)) {
        throw new IllegalArgumentException("Invalid resource key");
    }
    
    String targetUrl = urlMap.get(urlKey);
    
    try {
        HttpClient client = new HttpClient();
        client.start();
        
        // ok: java-serversiderequestforgery
        org.eclipse.jetty.client.api.ContentResponse response = client.GET(targetUrl);
        
        String content = response.getContentAsString();
        client.stop();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_13(HttpServletRequest request) {
    // Use path parameters with a fixed domain
    String category = request.getParameter("category");
    String itemId = request.getParameter("item");
    
    // Validate parameters
    if (!category.matches("^[a-z]+$") || !itemId.matches("^[0-9]+$")) {
        throw new IllegalArgumentException("Invalid parameters");
    }
    
    // Construct URL with fixed domain and validated path parameters
    String url = "https://api.secure-service.com/" + category + "/" + itemId;
    
    try {
        java.net.http.HttpClient client = java.net.http.HttpClient.newHttpClient();
        
        // ok: java-serversiderequestforgery
        java.net.http.HttpRequest httpRequest = java.net.http.HttpRequest.newBuilder()
            .uri(URI.create(url))
            .build();
        
        java.net.http.HttpResponse<String> response = client.send(
            httpRequest, 
            BodyHandlers.ofString()
        );
        
        String body = response.body();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_14(HttpServletRequest request) {
    // Use a URL proxy pattern with validation
    String urlPath = request.getParameter("path");
    
    // Validate path format
    if (!urlPath.matches("^[a-zA-Z0-9/_-]+$")) {
        throw new IllegalArgumentException("Invalid path format");
    }
    
    // Construct URL with fixed base and validated path
    String baseUrl = "https://api.trusted-domain.com";
    String fullUrl = baseUrl + urlPath;
    
    try {
        // ok: java-serversiderequestforgery
        URL url = new URL(fullUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(connection.getInputStream())
        );
        
        String line;
        StringBuilder response = new StringBuilder();
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        reader.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_15(HttpServletRequest request) {
    // Use a service registry pattern
    String serviceName = request.getParameter("service");
    String operation = request.getParameter("operation");
    
    // Validate parameters
    if (!serviceName.matches("^[a-z-]+$") || !operation.matches("^[a-z]+$")) {
        throw new IllegalArgumentException("Invalid service parameters");
    }
    
    // Service registry with predefined URLs
    Map<String, String> serviceRegistry = Map.of(
        "user-service", "https://users.internal.com/api",
        "order-service", "https://orders.internal.com/api",
        "product-service", "https://products.internal.com/api"
    );
    
    // Check if service exists
    if (!serviceRegistry.containsKey(serviceName)) {
        throw new IllegalArgumentException("Unknown service");
    }
    
    String baseUrl = serviceRegistry.get(serviceName);
    String fullUrl = baseUrl + "/" + operation;
    
    try {
        // ok: java-serversiderequestforgery
        URL url = new URL(fullUrl);
        URLConnection conn = url.openConnection();
        BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        
        String inputLine;
        while ((inputLine = in.readLine()) != null) {
            System.out.println(inputLine);
        }
        in.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}