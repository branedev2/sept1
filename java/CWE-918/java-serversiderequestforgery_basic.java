import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
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

    // TRUE POSITIVES (Vulnerable Code)

// {fact rule=server-side-request-forgery@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String url = request.getParameter("url");
        
        URL urlObj = new URL(url);
        // ruleid: java-serversiderequestforgery
        HttpURLConnection connection = (HttpURLConnection) urlObj.openConnection();
        connection.setRequestMethod("GET");
        
        BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        String inputLine;
        StringBuffer content = new StringBuffer();
        while ((inputLine = in.readLine()) != null) {
            content.append(inputLine);
        }
        in.close();
        connection.disconnect();
        
        response.getWriter().write(content.toString());
    }
    
    public void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws IOException, InterruptedException {
        String targetUrl = request.getParameter("target");
        
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(targetUrl))
                .build();
        
        // ruleid: java-serversiderequestforgery
        HttpResponse<String> httpResponse = client.send(httpRequest, HttpResponse.BodyHandlers.ofString());
        
        response.getWriter().write(httpResponse.body());
    }
    
    public void bad_case_3(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String endpoint = request.getHeader("X-Target-Endpoint");
        
        CloseableHttpClient httpClient = HttpClients.createDefault();
        // ruleid: java-serversiderequestforgery
        HttpGet httpGet = new HttpGet(endpoint);
        
        org.apache.http.HttpResponse httpResponse = httpClient.execute(httpGet);
        BufferedReader reader = new BufferedReader(new InputStreamReader(httpResponse.getEntity().getContent()));
        
        String line;
        StringBuilder result = new StringBuilder();
        while ((line = reader.readLine()) != null) {
            result.append(line);
        }
        
        response.getWriter().write(result.toString());
    }
    
    @GetMapping("/proxy")
    public ResponseEntity<String> bad_case_4(@RequestParam String destination) {
        RestTemplate restTemplate = new RestTemplate();
        // ruleid: java-serversiderequestforgery
        String result = restTemplate.getForObject(destination, String.class);
        return ResponseEntity.ok(result);
    }
    
    public void bad_case_5(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String apiUrl = request.getParameter("api");
        
        OkHttpClient client = new OkHttpClient();
        Request okRequest = new Request.Builder()
                .url(apiUrl)
                .build();
        
        // ruleid: java-serversiderequestforgery
        Response okResponse = client.newCall(okRequest).execute();
        
        response.getWriter().write(okResponse.body().string());
    }
    
    public void bad_case_6(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String baseUrl = "https://api.example.com";
        String path = request.getParameter("path");
        String fullUrl = baseUrl + path;
        
        URL url = new URL(fullUrl);
        // ruleid: java-serversiderequestforgery
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        
        BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        String inputLine;
        StringBuffer content = new StringBuffer();
        while ((inputLine = in.readLine()) != null) {
            content.append(inputLine);
        }
        in.close();
        
        response.getWriter().write(content.toString());
    }
    
    public void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws IOException, InterruptedException {
        String protocol = request.getParameter("protocol");
        String domain = request.getParameter("domain");
        String path = request.getParameter("path");
        String fullUrl = protocol + "://" + domain + "/" + path;
        
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(fullUrl))
                .build();
        
        // ruleid: java-serversiderequestforgery
        HttpResponse<String> httpResponse = client.send(httpRequest, HttpResponse.BodyHandlers.ofString());
        
        response.getWriter().write(httpResponse.body());
    }
    
    public void bad_case_8(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userId = request.getParameter("id");
        String apiUrl = "http://internal-api/user/" + userId;
        
        URL url = new URL(apiUrl);
        // ruleid: java-serversiderequestforgery
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        
        BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        String content = in.readLine();
        in.close();
        
        response.getWriter().write(content);
    }
    
    public void bad_case_9(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String service = request.getParameter("service");
        String apiKey = request.getParameter("key");
        
        String urlString = "https://" + service + ".example.com/api?key=" + apiKey;
        
        URL url = new URL(urlString);
        // ruleid: java-serversiderequestforgery
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        
        BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        String inputLine;
        StringBuilder content = new StringBuilder();
        while ((inputLine = in.readLine()) != null) {
            content.append(inputLine);
        }
        in.close();
        
        response.getWriter().write(content.toString());
    }
    
    @GetMapping("/fetch-resource")
    public ResponseEntity<String> bad_case_10(@RequestParam String resourceUrl) {
        RestTemplate restTemplate = new RestTemplate();
        // ruleid: java-serversiderequestforgery
        String result = restTemplate.getForObject(resourceUrl, String.class);
        return ResponseEntity.ok(result);
    }
    
    public void bad_case_11(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String host = request.getParameter("host");
        int port = Integer.parseInt(request.getParameter("port"));
        String path = request.getParameter("path");
        
        URL url = new URL("http", host, port, path);
        // ruleid: java-serversiderequestforgery
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        
        BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        String inputLine;
        StringBuilder content = new StringBuilder();
        while ((inputLine = in.readLine()) != null) {
            content.append(inputLine);
        }
        in.close();
        
        response.getWriter().write(content.toString());
    }
    
    public void bad_case_12(HttpServletRequest request, HttpServletResponse response) throws IOException, InterruptedException {
        String server = request.getParameter("server");
        String endpoint = "/api/data";
        String fullUrl = "https://" + server + endpoint;
        
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(fullUrl))
                .build();
        
        // ruleid: java-serversiderequestforgery
        HttpResponse<String> httpResponse = client.send(httpRequest, HttpResponse.BodyHandlers.ofString());
        
        response.getWriter().write(httpResponse.body());
    }
    
    public void bad_case_13(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String subdomain = request.getParameter("subdomain");
        String apiUrl = "https://" + subdomain + ".internal-api.example.com/data";
        
        OkHttpClient client = new OkHttpClient();
        Request okRequest = new Request.Builder()
                .url(apiUrl)
                .build();
        
        // ruleid: java-serversiderequestforgery
        Response okResponse = client.newCall(okRequest).execute();
        
        response.getWriter().write(okResponse.body().string());
    }
    
    public void bad_case_14(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String format = request.getParameter("format");
        String apiUrl = String.format("https://api.example.com/export?format=%s", format);
        
        URL url = new URL(apiUrl);
        // ruleid: java-serversiderequestforgery
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        
        BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        String inputLine;
        StringBuilder content = new StringBuilder();
        while ((inputLine = in.readLine()) != null) {
            content.append(inputLine);
        }
        in.close();
        
        response.getWriter().write(content.toString());
    }
    
    public void bad_case_15(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String callback = request.getParameter("callback");
        
        if (callback != null && !callback.isEmpty()) {
            URL url = new URL(callback);
            // ruleid: java-serversiderequestforgery
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            connection.getOutputStream().write("Operation completed".getBytes());
            
            int responseCode = connection.getResponseCode();
            response.getWriter().write("Notification sent, status: " + responseCode);
        }
    }
    
    // TRUE NEGATIVES (Safe Code)
    
    public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String url = request.getParameter("url");
        
        // Whitelist of allowed domains
        String[] allowedDomains = {"api.example.com", "data.example.com"};
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
                // ok: java-serversiderequestforgery
                HttpURLConnection connection = (HttpURLConnection) urlObj.openConnection();
                // Rest of the code to process the connection
            } else {
                response.getWriter().write("Domain not allowed");
            }
        } catch (MalformedURLException e) {
            response.getWriter().write("Invalid URL");
        }
    }
    
    public void good_case_2(HttpServletRequest request, HttpServletResponse response) throws IOException, InterruptedException {
        String targetId = request.getParameter("id");
        
        // Fixed base URL with parameterized path
        String baseUrl = "https://api.example.com/resources/";
        String fullUrl = baseUrl + targetId;
        
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(fullUrl))
                .build();
        
        // ok: java-serversiderequestforgery
        HttpResponse<String> httpResponse = client.send(httpRequest, HttpResponse.BodyHandlers.ofString());
        
        response.getWriter().write(httpResponse.body());
    }
    
    public void good_case_3(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String resourceId = request.getParameter("resource");
        
        // Using a fixed URL pattern
        String endpoint = "https://internal-api.example.com/data/" + resourceId;
        
        // Validate that resourceId contains only alphanumeric characters
        if (!resourceId.matches("^[a-zA-Z0-9]+$")) {
            response.getWriter().write("Invalid resource ID");
            return;
        }
        
        CloseableHttpClient httpClient = HttpClients.createDefault();
        // ok: java-serversiderequestforgery
        HttpGet httpGet = new HttpGet(endpoint);
        
        org.apache.http.HttpResponse httpResponse = httpClient.execute(httpGet);
        // Process response
    }
    
    @GetMapping("/safe-proxy")
    public ResponseEntity<String> good_case_4(@RequestParam String resourceType, @RequestParam String id) {
        // Constructing URL from fixed parts and validated parameters
        if (!resourceType.matches("^(users|products|orders)$")) {
            return ResponseEntity.badRequest().body("Invalid resource type");
        }
        
        if (!id.matches("^[0-9]+$")) {
            return ResponseEntity.badRequest().body("Invalid ID format");
        }
        
        String url = "https://api.example.com/" + resourceType + "/" + id;
        
        RestTemplate restTemplate = new RestTemplate();
        // ok: java-serversiderequestforgery
        String result = restTemplate.getForObject(url, String.class);
        return ResponseEntity.ok(result);
    }
    
    public void good_case_5(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String apiEndpoint = request.getParameter("endpoint");
        
        // Validate against a regex pattern for allowed endpoints
        Pattern pattern = Pattern.compile("^/(users|products|orders)/[0-9]+$");
        if (!pattern.matcher(apiEndpoint).matches()) {
            response.getWriter().write("Invalid endpoint");
            return;
        }
        
        String baseUrl = "https://api.example.com";
        String fullUrl = baseUrl + apiEndpoint;
        
        OkHttpClient client = new OkHttpClient();
        Request okRequest = new Request.Builder()
                .url(fullUrl)
                .build();
        
        // ok: java-serversiderequestforgery
        Response okResponse = client.newCall(okRequest).execute();
        
        response.getWriter().write(okResponse.body().string());
    }
    
    public void good_case_6(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Using a fixed URL, no user input
        String apiUrl = "https://api.example.com/data";
        
        URL url = new URL(apiUrl);
        // ok: java-serversiderequestforgery
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        
        BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        String inputLine;
        StringBuffer content = new StringBuffer();
        while ((inputLine = in.readLine()) != null) {
            content.append(inputLine);
        }
        in.close();
        
        response.getWriter().write(content.toString());
    }
    
    public void good_case_7(HttpServletRequest request, HttpServletResponse response) throws IOException, InterruptedException {
        String resourceId = request.getParameter("id");
        
        // Validate input format
        if (!resourceId.matches("^[a-zA-Z0-9-]+$")) {
            response.sendError(400, "Invalid resource ID format");
            return;
        }
        
        // Use a fixed base URL
        String apiUrl = "https://api.example.com/resources/" + resourceId;
        
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(apiUrl))
                .build();
        
        // ok: java-serversiderequestforgery
        HttpResponse<String> httpResponse = client.send(httpRequest, HttpResponse.BodyHandlers.ofString());
        
        response.getWriter().write(httpResponse.body());
    }
    
    public void good_case_8(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String category = request.getParameter("category");
        
        // Whitelist validation
        String[] allowedCategories = {"electronics", "books", "clothing"};
        boolean isValidCategory = false;
        
        for (String allowedCategory : allowedCategories) {
            if (allowedCategory.equals(category)) {
                isValidCategory = true;
                break;
            }
        }
        
        if (!isValidCategory) {
            response.sendError(400, "Invalid category");
            return;
        }
        
        String apiUrl = "https://api.example.com/products?category=" + category;
        
        URL url = new URL(apiUrl);
        // ok: java-serversiderequestforgery
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        
        // Process response
    }
    
    public void good_case_9(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Using an enum to restrict possible values
        String actionParam = request.getParameter("action");
        
        enum AllowedAction {
            VIEW, EDIT, DELETE
        }
        
        AllowedAction action;
        try {
            action = AllowedAction.valueOf(actionParam.toUpperCase());
        } catch (IllegalArgumentException | NullPointerException e) {
            response.sendError(400, "Invalid action");
            return;
        }
        
        String apiUrl = "https://api.example.com/perform?action=" + action.toString().toLowerCase();
        
        URL url = new URL(apiUrl);
        // ok: java-serversiderequestforgery
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        
        // Process response
    }
    
    @GetMapping("/fetch-data")
    public ResponseEntity<String> good_case_10(@RequestParam String dataType, @RequestParam Integer version) {
        // Validate dataType against allowed values
        if (!dataType.matches("^(customer|product|order)$")) {
            return ResponseEntity.badRequest().body("Invalid data type");
        }
        
        // Validate version is within acceptable range
        if (version < 1 || version > 3) {
            return ResponseEntity.badRequest().body("Invalid version");
        }
        
        String url = "https://api.example.com/data/" + dataType + "/v" + version;
        
        RestTemplate restTemplate = new RestTemplate();
        // ok: java-serversiderequestforgery
        String result = restTemplate.getForObject(url, String.class);
        return ResponseEntity.ok(result);
    }
    
    public void good_case_11(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String serverId = request.getParameter("server");
        
        // Validate server ID format
        if (!serverId.matches("^[a-z0-9]{8}$")) {
            response.sendError(400, "Invalid server ID format");
            return;
        }
        
        // Map server ID to actual server URL using a predefined mapping
        java.util.Map<String, String> serverMap = new java.util.HashMap<>();
        serverMap.put("server001", "https://api1.example.com");
        serverMap.put("server002", "https://api2.example.com");
        
        String serverUrl = serverMap.get(serverId);
        if (serverUrl == null) {
            response.sendError(400, "Unknown server ID");
            return;
        }
        
        URL url = new URL(serverUrl + "/status");
        // ok: java-serversiderequestforgery
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        
        // Process response
    }
    
    public void good_case_12(HttpServletRequest request, HttpServletResponse response) throws IOException, InterruptedException {
        String resourcePath = request.getParameter("path");
        
        // URL encode the path parameter to prevent path traversal
        String encodedPath = java.net.URLEncoder.encode(resourcePath, "UTF-8");
        
        // Use a fixed base URL
        String apiUrl = "https://api.example.com/resources?path=" + encodedPath;
        
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(apiUrl))
                .build();
        
        // ok: java-serversiderequestforgery
        HttpResponse<String> httpResponse = client.send(httpRequest, HttpResponse.BodyHandlers.ofString());
        
        response.getWriter().write(httpResponse.body());
    }
    
    public void good_case_13(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userId = request.getParameter("userId");
        
        // Validate userId is numeric
        if (!userId.matches("^[0-9]+$")) {
            response.sendError(400, "Invalid user ID");
            return;
        }
        
        // Use URL builder to construct URL safely
        URI uri = URI.create("https://api.example.com/users/" + userId);
        URL url = uri.toURL();
        
        // ok: java-serversiderequestforgery
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        
        // Process response
    }
    
    public void good_case_14(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String format = request.getParameter("format");
        
        // Validate format is one of the allowed values
        if (!format.equals("json") && !format.equals("xml") && !format.equals("csv")) {
            response.sendError(400, "Invalid format");
            return;
        }
        
        String apiUrl = "https://api.example.com/export?format=" + format;
        
        URL url = new URL(apiUrl);
        // ok: java-serversiderequestforgery
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        
        // Process response
    }
    
    public void good_case_15(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String callbackId = request.getParameter("callbackId");
        
        // Map callback ID to predefined URLs
        java.util.Map<String, String> callbackUrls = new java.util.HashMap<>();
        callbackUrls.put("success", "https://api.example.com/callback/success");
        callbackUrls.put("failure", "https://api.example.com/callback/failure");
        callbackUrls.put("pending", "https://api.example.com/callback/pending");
        
        String callbackUrl = callbackUrls.get(callbackId);
        if (callbackUrl == null) {
            response.sendError(400, "Invalid callback ID");
            return;
        }
        
        URL url = new URL(callbackUrl);
        // ok: java-serversiderequestforgery
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setDoOutput(true);
        connection.getOutputStream().write("Operation completed".getBytes());
        
        int responseCode = connection.getResponseCode();
        response.getWriter().write("Notification sent, status: " + responseCode);
    }
}
// {/fact}