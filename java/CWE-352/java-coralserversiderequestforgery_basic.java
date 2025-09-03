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
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@RestController
public class CoralSSRFExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=coral-csrf-rule@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) {
        try {
            String userProvidedUrl = request.getParameter("url");
            URL url = new URL(userProvidedUrl);
            
            // ruleid: java-coralserversiderequestforgery
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
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_2(HttpServletRequest request) {
        String targetUrl = request.getParameter("target");
        RestTemplate restTemplate = new RestTemplate();
        
        // ruleid: java-coralserversiderequestforgery
        String response = restTemplate.getForObject(targetUrl, String.class);
        System.out.println("Response: " + response);
    }

    @GetMapping("/fetch-data")
    public String bad_case_3(@RequestParam String apiUrl) {
        try {
            HttpClient client = HttpClient.newHttpClient();
            
            // ruleid: java-coralserversiderequestforgery
            HttpRequest httpRequest = HttpRequest.newBuilder()
                    .uri(URI.create(apiUrl))
                    .build();
            
            HttpResponse<String> response = client.send(httpRequest, HttpResponse.BodyHandlers.ofString());
            return response.body();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    public void bad_case_4(HttpServletRequest request) {
        try {
            String endpoint = request.getParameter("endpoint");
            URL url = new URL("https://api.example.com" + endpoint);
            
            // ruleid: java-coralserversiderequestforgery
            URLConnection connection = url.openConnection();
            BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            
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

    public void bad_case_5(HttpServletRequest request) {
        try {
            String server = request.getParameter("server");
            String fullUrl = "http://" + server + "/api/data";
            
            // ruleid: java-coralserversiderequestforgery
            URL url = new URL(fullUrl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            
            int responseCode = connection.getResponseCode();
            System.out.println("Response Code: " + responseCode);
            connection.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_6(HttpServletRequest request) {
        try {
            String urlPath = request.getParameter("path");
            String baseUrl = "https://example.org";
            URL url = new URL(baseUrl + urlPath);
            
            // ruleid: java-coralserversiderequestforgery
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            
            BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            in.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_7(HttpServletRequest request) {
        try {
            CloseableHttpClient httpClient = HttpClients.createDefault();
            String targetUrl = request.getHeader("X-Target-URL");
            
            // ruleid: java-coralserversiderequestforgery
            HttpGet httpGet = new HttpGet(targetUrl);
            httpClient.execute(httpGet);
            httpClient.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_8(HttpServletRequest request) {
        try {
            String protocol = request.getParameter("protocol");
            String domain = request.getParameter("domain");
            String fullUrl = protocol + "://" + domain + "/api/v1/data";
            
            // ruleid: java-coralserversiderequestforgery
            URL url = new URL(fullUrl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.connect();
            connection.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_9(HttpServletRequest request) {
        try {
            String subdomain = request.getParameter("subdomain");
            URL url = new URL("https://" + subdomain + ".example.com/api");
            
            // ruleid: java-coralserversiderequestforgery
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_10(HttpServletRequest request) {
        try {
            String serviceUrl = request.getParameter("service");
            HttpClient client = HttpClient.newBuilder().build();
            
            // ruleid: java-coralserversiderequestforgery
            HttpRequest httpRequest = HttpRequest.newBuilder()
                    .uri(URI.create(serviceUrl))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString("{\"query\":\"data\"}"))
                    .build();
            
            client.send(httpRequest, HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_11(HttpServletRequest request) {
        String apiEndpoint = request.getParameter("api");
        RestTemplate restTemplate = new RestTemplate();
        
        // Process the URL but still vulnerable
        String processedUrl = "https://api.example.com/" + apiEndpoint;
        
        // ruleid: java-coralserversiderequestforgery
        restTemplate.getForObject(processedUrl, String.class);
    }

    public void bad_case_12(HttpServletRequest request) {
        try {
            // Taking multiple parameters to construct URL
            String host = request.getParameter("host");
            String port = request.getParameter("port");
            String path = request.getParameter("path");
            
            String urlString = "http://" + host + ":" + port + path;
            URL url = new URL(urlString);
            
            // ruleid: java-coralserversiderequestforgery
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.getInputStream();
            connection.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_13(HttpServletRequest request) {
        try {
            // URL from cookie
            String targetUrl = request.getCookies()[0].getValue();
            URL url = new URL(targetUrl);
            
            // ruleid: java-coralserversiderequestforgery
            URLConnection connection = url.openConnection();
            BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_14(HttpServletRequest request) {
        try {
            // Attempt at obfuscation but still vulnerable
            String encodedUrl = request.getParameter("data");
            String decodedUrl = java.net.URLDecoder.decode(encodedUrl, "UTF-8");
            
            // ruleid: java-coralserversiderequestforgery
            URL url = new URL(decodedUrl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.getInputStream();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_15(HttpServletRequest request) {
        try {
            // Indirect flow
            String urlParam = request.getParameter("url");
            StringBuilder builder = new StringBuilder();
            builder.append(urlParam);
            String finalUrl = builder.toString();
            
            // ruleid: java-coralserversiderequestforgery
            URL url = new URL(finalUrl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // True Negative Examples (Secure Code)

    public void good_case_1(HttpServletRequest request) {
        try {
            String userProvidedUrl = request.getParameter("url");
            
            // ok: java-coralserversiderequestforgery
            if (!userProvidedUrl.startsWith("https://api.trusted-domain.com/")) {
                throw new IllegalArgumentException("URL is not from a trusted domain");
            }
            
            URL url = new URL(userProvidedUrl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            
            BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            in.close();
            connection.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_2(HttpServletRequest request) {
        String targetPath = request.getParameter("path");
        
        // Whitelist of allowed paths
        String[] allowedPaths = {"/api/data", "/api/users", "/api/products"};
        boolean isAllowed = false;
        
        for (String path : allowedPaths) {
            if (path.equals(targetPath)) {
                isAllowed = true;
                break;
            }
        }
        
        // ok: java-coralserversiderequestforgery
        if (isAllowed) {
            RestTemplate restTemplate = new RestTemplate();
            String baseUrl = "https://internal-api.company.com";
            String response = restTemplate.getForObject(baseUrl + targetPath, String.class);
            System.out.println("Response: " + response);
        } else {
            System.out.println("Invalid path requested");
        }
    }

    @GetMapping("/fetch-data-safe")
    public String good_case_3(@RequestParam String apiId) {
        try {
            // Map ID to predefined URLs instead of using user input directly
            String apiUrl;
            
            // ok: java-coralserversiderequestforgery
            switch (apiId) {
                case "weather":
                    apiUrl = "https://api.weather.com/current";
                    break;
                case "news":
                    apiUrl = "https://api.news.com/latest";
                    break;
                case "stocks":
                    apiUrl = "https://api.stocks.com/market";
                    break;
                default:
                    return "Invalid API ID";
            }
            
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest httpRequest = HttpRequest.newBuilder()
                    .uri(URI.create(apiUrl))
                    .build();
            
            HttpResponse<String> response = client.send(httpRequest, HttpResponse.BodyHandlers.ofString());
            return response.body();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    public void good_case_4(HttpServletRequest request) {
        try {
            String endpoint = request.getParameter("endpoint");
            
            // ok: java-coralserversiderequestforgery
            // Validate URL against regex pattern for allowed endpoints
            Pattern pattern = Pattern.compile("^/api/(users|products|orders)/\\d+$");
            if (!pattern.matcher(endpoint).matches()) {
                throw new IllegalArgumentException("Invalid endpoint format");
            }
            
            URL url = new URL("https://api.example.com" + endpoint);
            URLConnection connection = url.openConnection();
            BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_5(HttpServletRequest request) {
        try {
            String serverId = request.getParameter("server");
            
            // ok: java-coralserversiderequestforgery
            // Map server ID to predefined server addresses
            String serverAddress;
            switch (serverId) {
                case "prod":
                    serverAddress = "prod-server.internal.com";
                    break;
                case "dev":
                    serverAddress = "dev-server.internal.com";
                    break;
                case "test":
                    serverAddress = "test-server.internal.com";
                    break;
                default:
                    throw new IllegalArgumentException("Invalid server ID");
            }
            
            String fullUrl = "http://" + serverAddress + "/api/data";
            URL url = new URL(fullUrl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_6(HttpServletRequest request) {
        try {
            String resourceId = request.getParameter("id");
            
            // Validate that resourceId is numeric
            // ok: java-coralserversiderequestforgery
            if (!resourceId.matches("\\d+")) {
                throw new IllegalArgumentException("Resource ID must be numeric");
            }
            
            // Use the validated ID to construct a URL to a fixed domain
            URL url = new URL("https://api.company.com/resources/" + resourceId);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            
            BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            in.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_7(HttpServletRequest request) {
        try {
            String targetHost = request.getHeader("X-Target-Host");
            
            // ok: java-coralserversiderequestforgery
            // Validate against whitelist
            String[] allowedHosts = {"api1.company.com", "api2.company.com", "api3.company.com"};
            boolean isAllowed = false;
            
            for (String host : allowedHosts) {
                if (host.equals(targetHost)) {
                    isAllowed = true;
                    break;
                }
            }
            
            if (!isAllowed) {
                throw new IllegalArgumentException("Host not allowed");
            }
            
            CloseableHttpClient httpClient = HttpClients.createDefault();
            HttpGet httpGet = new HttpGet("https://" + targetHost + "/api/data");
            httpClient.execute(httpGet);
            httpClient.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_8(HttpServletRequest request) {
        try {
            String domain = request.getParameter("domain");
            
            // ok: java-coralserversiderequestforgery
            // Validate domain against allowed list and format
            if (!domain.endsWith(".trusted-partner.com") || domain.contains("..")) {
                throw new IllegalArgumentException("Domain not allowed");
            }
            
            String fullUrl = "https://" + domain + "/api/v1/data";
            URL url = new URL(fullUrl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.connect();
            connection.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_9(HttpServletRequest request) {
        try {
            String subdomain = request.getParameter("subdomain");
            
            // ok: java-coralserversiderequestforgery
            // Validate subdomain format (alphanumeric only)
            if (!subdomain.matches("^[a-zA-Z0-9]+$")) {
                throw new IllegalArgumentException("Invalid subdomain format");
            }
            
            URL url = new URL("https://" + subdomain + ".example.com/api");
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_10(HttpServletRequest request) {
        try {
            String serviceId = request.getParameter("service");
            
            // ok: java-coralserversiderequestforgery
            // Map service ID to fixed URLs
            Map<String, String> serviceUrlMap = new HashMap<>();
            serviceUrlMap.put("weather", "https://weather-api.example.com/current");
            serviceUrlMap.put("news", "https://news-api.example.com/latest");
            serviceUrlMap.put("stocks", "https://stocks-api.example.com/quotes");
            
            if (!serviceUrlMap.containsKey(serviceId)) {
                throw new IllegalArgumentException("Invalid service ID");
            }
            
            String serviceUrl = serviceUrlMap.get(serviceId);
            HttpClient client = HttpClient.newBuilder().build();
            HttpRequest httpRequest = HttpRequest.newBuilder()
                    .uri(URI.create(serviceUrl))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString("{\"query\":\"data\"}"))
                    .build();
            
            client.send(httpRequest, HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_11(HttpServletRequest request) {
        String apiEndpoint = request.getParameter("api");
        
        // ok: java-coralserversiderequestforgery
        // Use URL parser to validate and ensure only specific domains are allowed
        try {
            URL url = new URL(apiEndpoint);
            String host = url.getHost();
            
            if (!"api.trusted-source.com".equals(host) && !"data.trusted-source.com".equals(host)) {
                throw new IllegalArgumentException("Only trusted domains are allowed");
            }
            
            RestTemplate restTemplate = new RestTemplate();
            restTemplate.getForObject(apiEndpoint, String.class);
        } catch (MalformedURLException e) {
            System.out.println("Invalid URL format");
        }
    }

    public void good_case_12(HttpServletRequest request) {
        try {
            // ok: java-coralserversiderequestforgery
            // Use a proxy service to restrict outbound connections
            String resourcePath = request.getParameter("path");
            
            // Validate path format
            if (!resourcePath.matches("^/[a-zA-Z0-9/]+$")) {
                throw new IllegalArgumentException("Invalid resource path format");
            }
            
            // Use fixed base URL
            String baseUrl = "https://internal-api.company.com";
            URL url = new URL(baseUrl + resourcePath);
            
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.getInputStream();
            connection.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_13(HttpServletRequest request) {
        try {
            // ok: java-coralserversiderequestforgery
            // Use URL validation library (simplified example)
            String targetUrl = request.getParameter("url");
            
            // Parse the URL to extract components
            URL url = new URL(targetUrl);
            String protocol = url.getProtocol();
            String host = url.getHost();
            int port = url.getPort();
            
            // Validate components
            if (!"https".equals(protocol)) {
                throw new IllegalArgumentException("Only HTTPS protocol is allowed");
            }
            
            if (!host.endsWith(".safe-domain.com")) {
                throw new IllegalArgumentException("Only .safe-domain.com hosts are allowed");
            }
            
            if (port != -1 && port != 443) {
                throw new IllegalArgumentException("Only default HTTPS port is allowed");
            }
            
            // Now safe to connect
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_14(HttpServletRequest request) {
        try {
            // ok: java-coralserversiderequestforgery
            // Use a request signing approach for internal services
            String serviceId = request.getParameter("service");
            
            // Validate service ID
            if (!serviceId.matches("^[a-zA-Z0-9-]+$")) {
                throw new IllegalArgumentException("Invalid service ID format");
            }
            
            // Use a fixed internal domain
            String serviceUrl = "https://internal-gateway.company.com/service/" + serviceId;
            
            // Add security token
            String securityToken = generateSecurityToken(serviceId);
            
            URL url = new URL(serviceUrl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestProperty("X-Security-Token", securityToken);
            connection.getInputStream();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private String generateSecurityToken(String serviceId) {
        // Implementation of token generation
        return "secure-token-" + serviceId + "-" + System.currentTimeMillis();
    }

    public void good_case_15(HttpServletRequest request) {
        try {
            // ok: java-coralserversiderequestforgery
            // Use DNS resolution check to prevent internal SSRF
            String hostname = request.getParameter("host");
            
            // Validate hostname format
            if (!hostname.matches("^[a-zA-Z0-9.-]+$")) {
                throw new IllegalArgumentException("Invalid hostname format");
            }
            
            // Check if hostname resolves to internal IP (simplified)
            InetAddress address = InetAddress.getByName(hostname);
            String ip = address.getHostAddress();
            
            if (isInternalIP(ip)) {
                throw new IllegalArgumentException("Cannot connect to internal IP addresses");
            }
            
            URL url = new URL("https://" + hostname + "/api/public/data");
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private boolean isInternalIP(String ip) {
        // Check for private IP ranges (simplified)
        return ip.startsWith("10.") || 
               ip.startsWith("192.168.") || 
               ip.startsWith("172.16.") || 
               ip.startsWith("172.17.") || 
               ip.startsWith("172.18.") || 
               ip.startsWith("172.19.") || 
               ip.startsWith("172.20.") || 
               ip.startsWith("172.21.") || 
               ip.startsWith("172.22.") || 
               ip.startsWith("172.23.") || 
               ip.startsWith("172.24.") || 
               ip.startsWith("172.25.") || 
               ip.startsWith("172.26.") || 
               ip.startsWith("172.27.") || 
               ip.startsWith("172.28.") || 
               ip.startsWith("172.29.") || 
               ip.startsWith("172.30.") || 
               ip.startsWith("172.31.") || 
               ip.equals("127.0.0.1");
    }
}
// {/fact}