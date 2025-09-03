import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.regex.Pattern;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

@RestController
public class SSRFExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=server-side-request-forgery@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String url = request.getParameter("url");
        
        // ruleid: java-server-side-request-forgery
        URL urlObj = new URL(url);
        HttpURLConnection connection = (HttpURLConnection) urlObj.openConnection();
        connection.setRequestMethod("GET");
        
        BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        String inputLine;
        StringBuilder content = new StringBuilder();
        while ((inputLine = in.readLine()) != null) {
            content.append(inputLine);
        }
        in.close();
        connection.disconnect();
        
        response.getWriter().write(content.toString());
    }
    
    @GetMapping("/fetch-resource")
    public String bad_case_2(@RequestParam String resourceUrl) {
        RestTemplate restTemplate = new RestTemplate();
        
        // ruleid: java-server-side-request-forgery
        ResponseEntity<String> response = restTemplate.getForEntity(resourceUrl, String.class);
        return response.getBody();
    }
    
    public void bad_case_3(HttpServletRequest request) throws IOException {
        String targetUrl = request.getParameter("target");
        
        CloseableHttpClient httpClient = HttpClients.createDefault();
        // ruleid: java-server-side-request-forgery
        HttpGet httpGet = new HttpGet(targetUrl);
        httpClient.execute(httpGet);
        httpClient.close();
    }
    
    public String bad_case_4(HttpServletRequest request) throws IOException, InterruptedException {
        String endpoint = request.getParameter("endpoint");
        
        HttpClient client = HttpClient.newHttpClient();
        // ruleid: java-server-side-request-forgery
        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(endpoint))
                .build();
        
        HttpResponse<String> response = client.send(httpRequest, HttpResponse.BodyHandlers.ofString());
        return response.body();
    }
    
    public String bad_case_5(HttpServletRequest request) throws IOException {
        String apiUrl = request.getHeader("X-Api-Url");
        
        OkHttpClient client = new OkHttpClient();
        // ruleid: java-server-side-request-forgery
        Request okRequest = new Request.Builder()
                .url(apiUrl)
                .build();
                
        Response response = client.newCall(okRequest).execute();
        return response.body().string();
    }
    
    public void bad_case_6(HttpServletRequest request) throws IOException {
        String urlString = request.getParameter("url");
        if (urlString != null) {
            // ruleid: java-server-side-request-forgery
            URL url = new URL(urlString);
            URLConnection conn = url.openConnection();
            BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
            reader.close();
        }
    }
    
    public String bad_case_7(HttpServletRequest request) throws IOException, InterruptedException {
        String target = request.getParameter("target");
        String method = request.getParameter("method");
        
        HttpClient client = HttpClient.newBuilder().build();
        // ruleid: java-server-side-request-forgery
        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(target))
                .method(method, HttpRequest.BodyPublishers.noBody())
                .build();
                
        HttpResponse<String> response = client.send(httpRequest, HttpResponse.BodyHandlers.ofString());
        return response.body();
    }
    
    @GetMapping("/proxy")
    public ResponseEntity<String> bad_case_8(@RequestParam String url) {
        RestTemplate restTemplate = new RestTemplate();
        
        // ruleid: java-server-side-request-forgery
        return restTemplate.getForEntity(url, String.class);
    }
    
    public void bad_case_9(HttpServletRequest request) throws IOException {
        String url = request.getParameter("url");
        String requestMethod = request.getParameter("method");
        
        // ruleid: java-server-side-request-forgery
        HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
        connection.setRequestMethod(requestMethod);
        
        BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println(line);
        }
        reader.close();
    }
    
    public String bad_case_10(HttpServletRequest request) throws IOException {
        String baseUrl = "https://api.example.com";
        String path = request.getParameter("path");
        String fullUrl = baseUrl + path;  // Still vulnerable as path can be "/../malicious-endpoint"
        
        OkHttpClient client = new OkHttpClient();
        // ruleid: java-server-side-request-forgery
        Request okRequest = new Request.Builder()
                .url(fullUrl)
                .build();
                
        Response response = client.newCall(okRequest).execute();
        return response.body().string();
    }
    
    public void bad_case_11(HttpServletRequest request) throws IOException {
        String host = request.getParameter("host");
        int port = Integer.parseInt(request.getParameter("port"));
        
        // ruleid: java-server-side-request-forgery
        URL url = new URL("http", host, port, "/index.html");
        URLConnection connection = url.openConnection();
        BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println(line);
        }
        reader.close();
    }
    
    public String bad_case_12(HttpServletRequest request) throws IOException, InterruptedException {
        String protocol = request.getParameter("protocol"); // http or https
        String domain = request.getParameter("domain");
        String endpoint = request.getParameter("endpoint");
        String url = protocol + "://" + domain + endpoint;
        
        HttpClient client = HttpClient.newHttpClient();
        // ruleid: java-server-side-request-forgery
        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .GET()
                .build();
                
        HttpResponse<String> response = client.send(httpRequest, HttpResponse.BodyHandlers.ofString());
        return response.body();
    }
    
    public void bad_case_13(HttpServletRequest request) throws IOException {
        String scheme = request.getParameter("scheme");
        String authority = request.getParameter("authority");
        String path = request.getParameter("path");
        
        try {
            URI uri = new URI(scheme, authority, path, null, null);
            // ruleid: java-server-side-request-forgery
            URL url = uri.toURL();
            URLConnection connection = url.openConnection();
            BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    @GetMapping("/redirect")
    public void bad_case_14(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String redirectUrl = request.getParameter("url");
        
        // This is still SSRF as it can redirect to internal resources
        // ruleid: java-server-side-request-forgery
        response.sendRedirect(redirectUrl);
    }
    
    public String bad_case_15(HttpServletRequest request) throws IOException {
        // Even with some basic checks, this is still vulnerable
        String url = request.getParameter("url");
        
        if (url.startsWith("http://") || url.startsWith("https://")) {
            OkHttpClient client = new OkHttpClient();
            // ruleid: java-server-side-request-forgery
            Request okRequest = new Request.Builder()
                    .url(url)
                    .build();
                    
            Response response = client.newCall(okRequest).execute();
            return response.body().string();
        }
        
        return "Invalid URL";
    }
    
    // True Negative Examples (Safe Code)
    
    public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String url = request.getParameter("url");
        
        // Validate URL against whitelist
        String[] allowedDomains = {"api.example.com", "data.example.org"};
        boolean isAllowed = false;
        
        try {
            URL urlObj = new URL(url);
            String host = urlObj.getHost();
            
            for (String domain : allowedDomains) {
                if (host.equals(domain)) {
                    isAllowed = true;
                    break;
                }
            }
            
            if (isAllowed) {
                // ok: java-server-side-request-forgery
                HttpURLConnection connection = (HttpURLConnection) urlObj.openConnection();
                // Rest of the code to handle the connection
            } else {
                response.getWriter().write("URL not allowed");
            }
        } catch (MalformedURLException e) {
            response.getWriter().write("Invalid URL");
        }
    }
    
    @GetMapping("/fetch-resource-safe")
    public String good_case_2(@RequestParam String resourceId) {
        // Use resource ID to construct URL from known base
        String baseUrl = "https://api.trusted-source.com/resources/";
        
        // ok: java-server-side-request-forgery
        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<String> response = restTemplate.getForEntity(baseUrl + resourceId, String.class);
        return response.getBody();
    }
    
    public void good_case_3(HttpServletRequest request) throws IOException {
        String resourceId = request.getParameter("id");
        
        // Predefined URL pattern with parameter
        String targetUrl = "https://api.internal.com/resources/" + resourceId;
        
        // Validate that resourceId only contains alphanumeric characters
        if (!resourceId.matches("^[a-zA-Z0-9]+$")) {
            throw new IllegalArgumentException("Invalid resource ID");
        }
        
        CloseableHttpClient httpClient = HttpClients.createDefault();
        // ok: java-server-side-request-forgery
        HttpGet httpGet = new HttpGet(targetUrl);
        httpClient.execute(httpGet);
        httpClient.close();
    }
    
    public String good_case_4(HttpServletRequest request) throws IOException, InterruptedException {
        String endpoint = request.getParameter("endpoint");
        
        // Validate against regex pattern for allowed endpoints
        Pattern pattern = Pattern.compile("^/api/v1/[a-zA-Z0-9-_/]+$");
        if (!pattern.matcher(endpoint).matches()) {
            throw new IllegalArgumentException("Invalid endpoint format");
        }
        
        String baseUrl = "https://api.trusted-domain.com";
        HttpClient client = HttpClient.newHttpClient();
        // ok: java-server-side-request-forgery
        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + endpoint))
                .build();
        
        HttpResponse<String> response = client.send(httpRequest, HttpResponse.BodyHandlers.ofString());
        return response.body();
    }
    
    public String good_case_5(HttpServletRequest request) throws IOException {
        // Use a fixed set of allowed API endpoints
        String apiEndpoint = request.getParameter("endpoint");
        String apiBaseUrl = "https://api.trusted-service.com";
        
        // Map user input to predefined endpoints
        String fullUrl;
        switch (apiEndpoint) {
            case "users":
                fullUrl = apiBaseUrl + "/users";
                break;
            case "products":
                fullUrl = apiBaseUrl + "/products";
                break;
            case "orders":
                fullUrl = apiBaseUrl + "/orders";
                break;
            default:
                throw new IllegalArgumentException("Invalid endpoint");
        }
        
        OkHttpClient client = new OkHttpClient();
        // ok: java-server-side-request-forgery
        Request okRequest = new Request.Builder()
                .url(fullUrl)
                .build();
                
        Response response = client.newCall(okRequest).execute();
        return response.body().string();
    }
    
    public void good_case_6(HttpServletRequest request) throws IOException {
        String urlString = request.getParameter("url");
        
        try {
            URL url = new URL(urlString);
            String host = url.getHost();
            
            // Check if URL is pointing to internal network
            if (isInternalHost(host)) {
                throw new SecurityException("Access to internal hosts is not allowed");
            }
            
            // ok: java-server-side-request-forgery
            URLConnection conn = url.openConnection();
            BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            // Process the response
        } catch (Exception e) {
            // Handle exceptions
        }
    }
    
    private boolean isInternalHost(String host) {
        return host.equals("localhost") || 
               host.equals("127.0.0.1") || 
               host.startsWith("192.168.") || 
               host.startsWith("10.") || 
               host.startsWith("172.16.");
    }
    
    public String good_case_7(HttpServletRequest request) throws IOException, InterruptedException {
        // Use a configuration map to restrict allowed targets
        String targetKey = request.getParameter("target");
        
        // Map of allowed targets
        java.util.Map<String, String> allowedTargets = new java.util.HashMap<>();
        allowedTargets.put("weather", "https://api.weather.com/current");
        allowedTargets.put("news", "https://api.news.com/latest");
        allowedTargets.put("stocks", "https://api.stocks.com/quotes");
        
        if (!allowedTargets.containsKey(targetKey)) {
            throw new IllegalArgumentException("Invalid target key");
        }
        
        String targetUrl = allowedTargets.get(targetKey);
        HttpClient client = HttpClient.newHttpClient();
        // ok: java-server-side-request-forgery
        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(targetUrl))
                .GET()
                .build();
                
        HttpResponse<String> response = client.send(httpRequest, HttpResponse.BodyHandlers.ofString());
        return response.body();
    }
    
    @GetMapping("/proxy-safe")
    public ResponseEntity<String> good_case_8(@RequestParam String service, @RequestParam String resource) {
        // Construct URL from known parts
        String baseUrl = "https://api.trusted-services.com/";
        
        // Validate service parameter
        if (!service.matches("^[a-z-]+$")) {
            throw new IllegalArgumentException("Invalid service name");
        }
        
        // Validate resource parameter
        if (!resource.matches("^[a-zA-Z0-9-_/]+$")) {
            throw new IllegalArgumentException("Invalid resource path");
        }
        
        String url = baseUrl + service + "/v1/" + resource;
        
        RestTemplate restTemplate = new RestTemplate();
        // ok: java-server-side-request-forgery
        return restTemplate.getForEntity(url, String.class);
    }
    
    public void good_case_9(HttpServletRequest request) throws IOException {
        // Use URL builder pattern with validation
        String host = request.getParameter("host");
        String path = request.getParameter("path");
        
        // Whitelist of allowed hosts
        java.util.Set<String> allowedHosts = new java.util.HashSet<>();
        allowedHosts.add("api.example.com");
        allowedHosts.add("data.example.com");
        allowedHosts.add("cdn.example.com");
        
        if (!allowedHosts.contains(host)) {
            throw new SecurityException("Host not allowed");
        }
        
        // Validate path format
        if (!path.matches("^/[a-zA-Z0-9-_/.]+$")) {
            throw new IllegalArgumentException("Invalid path format");
        }
        
        // ok: java-server-side-request-forgery
        URL url = new URL("https", host, path);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        // Process the connection
    }
    
    public String good_case_10(HttpServletRequest request) throws IOException {
        // Use a URL parser to validate and normalize URLs
        String urlInput = request.getParameter("url");
        
        try {
            URL url = new URL(urlInput);
            String protocol = url.getProtocol();
            String host = url.getHost();
            
            // Only allow http and https protocols
            if (!("http".equals(protocol) || "https".equals(protocol))) {
                throw new SecurityException("Only HTTP and HTTPS protocols are allowed");
            }
            
            // Check against whitelist
            java.util.List<String> allowedDomains = java.util.Arrays.asList(
                "api.trusted.com", "data.trusted.com", "cdn.trusted.com");
                
            if (!allowedDomains.contains(host)) {
                throw new SecurityException("Domain not in whitelist");
            }
            
            OkHttpClient client = new OkHttpClient();
            // ok: java-server-side-request-forgery
            Request okRequest = new Request.Builder()
                    .url(url.toString())
                    .build();
                    
            Response response = client.newCall(okRequest).execute();
            return response.body().string();
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("Invalid URL format");
        }
    }
    
    public void good_case_11(HttpServletRequest request) throws IOException {
        // Use URL signing to prevent tampering
        String endpoint = request.getParameter("endpoint");
        String signature = request.getParameter("signature");
        
        // Verify signature (simplified example)
        String secretKey = "your-secret-key";
        String expectedSignature = calculateHmac(endpoint, secretKey);
        
        if (!expectedSignature.equals(signature)) {
            throw new SecurityException("Invalid URL signature");
        }
        
        // Base URL is fixed
        String baseUrl = "https://api.trusted-service.com";
        String fullUrl = baseUrl + endpoint;
        
        // ok: java-server-side-request-forgery
        URL url = new URL(fullUrl);
        URLConnection connection = url.openConnection();
        // Process the connection
    }
    
    private String calculateHmac(String data, String key) {
        // Simplified HMAC_REDACTED_TWILIO_ID calculation for example purposes
        return java.util.Base64.getEncoder().encodeToString((data + key).getBytes());
    }
    
    public String good_case_12(HttpServletRequest request) throws IOException, InterruptedException {
        // Use a URL builder with strict validation
        String resourceType = request.getParameter("type");
        String resourceId = request.getParameter("id");
        
        // Validate resource type
        if (!resourceType.matches("^(users|products|orders)$")) {
            throw new IllegalArgumentException("Invalid resource type");
        }
        
        // Validate resource ID
        if (!resourceId.matches("^[a-zA-Z0-9-]+$")) {
            throw new IllegalArgumentException("Invalid resource ID");
        }
        
        // Construct URL from validated components
        URI uri = new URI("https", "api.example.com", 
                          "/api/v1/" + resourceType + "/" + resourceId, 
                          null, null);
        
        HttpClient client = HttpClient.newHttpClient();
        // ok: java-server-side-request-forgery
        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(uri)
                .GET()
                .build();
                
        HttpResponse<String> response = client.send(httpRequest, HttpResponse.BodyHandlers.ofString());
        return response.body();
    }
    
    public void good_case_13(HttpServletRequest request) throws IOException {
        // Use a proxy service to restrict outbound requests
        String targetUrl = request.getParameter("url");
        
        // Validate URL format
        if (!isValidUrl(targetUrl)) {
            throw new IllegalArgumentException("Invalid URL format");
        }
        
        // Use internal proxy service that enforces additional security checks
        String proxyUrl = "https://internal-proxy.example.com/fetch?url=" + 
                           java.net.URLEncoder.encode(targetUrl, "UTF-8");
        
        // ok: java-server-side-request-forgery
        URL url = new URL(proxyUrl);
        URLConnection connection = url.openConnection();
        // Process the connection
    }
    
    private boolean isValidUrl(String url) {
        try {
            new URL(url);
            return true;
        } catch (MalformedURLException e) {
            return false;
        }
    }
    
    @GetMapping("/redirect-safe")
    public void good_case_14(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String page = request.getParameter("page");
        
        // Map of allowed redirect destinations
        java.util.Map<String, String> allowedRedirects = new java.util.HashMap<>();
        allowedRedirects.put("home", "/home");
        allowedRedirects.put("about", "/about");
        allowedRedirects.put("contact", "/contact");
        allowedRedirects.put("login", "/auth/login");
        
        if (!allowedRedirects.containsKey(page)) {
            // Default to home page if invalid
            page = "home";
        }
        
        String redirectUrl = allowedRedirects.get(page);
        // ok: java-server-side-request-forgery
        response.sendRedirect(redirectUrl);
    }
    
    public String good_case_15(HttpServletRequest request) throws IOException {
        // Use URL objects with strict protocol and host validation
        String path = request.getParameter("path");
        
        // Validate path format
        if (!path.matches("^/[a-zA-Z0-9-_/.]+$")) {
            throw new IllegalArgumentException("Invalid path format");
        }
        
        // Fixed base URL
        String baseUrl = "https://api.trusted-domain.com";
        String fullUrl = baseUrl + path;
        
        URL url = new URL(fullUrl);
        
        // Double-check that the constructed URL hasn't been manipulated
        if (!url.getHost().equals("api.trusted-domain.com") || 
            !url.getProtocol().equals("https")) {
            throw new SecurityException("URL manipulation detected");
        }
        
        OkHttpClient client = new OkHttpClient();
        // ok: java-server-side-request-forgery
        Request okRequest = new Request.Builder()
                .url(url)
                .build();
                
        Response response = client.newCall(okRequest).execute();
        return response.body().string();
    }
}
// {/fact}