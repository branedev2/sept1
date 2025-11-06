import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Examples for java-insecure-usage-of-cache rule
 * This rule detects insecure usage of StringByteConverter with Cache
 * which can lead to buffer access length errors
 */

// Vulnerable implementation of StringByteConverter
class StringByteConverter {
    public byte[] toBytes(String input) {
        return input.getBytes();
    }
    
    public String toString(byte[] bytes) {
        return new String(bytes);
    }
}

// Safe implementation with boundary checks
class SafeStringByteConverter {
    private static final int MAX_LENGTH = 1024;
    
    public byte[] toBytes(String input) {
        if (input == null || input.length() > MAX_LENGTH) {
            throw new IllegalArgumentException("Input exceeds maximum allowed length");
        }
        return input.getBytes();
    }
    
    public String toString(byte[] bytes) {
        if (bytes == null || bytes.length > MAX_LENGTH) {
            throw new IllegalArgumentException("Input exceeds maximum allowed length");
        }
        return new String(bytes);
    }
}

// Unsafe Cache implementation
class Cache {
    private Map<String, byte[]> cache = new HashMap<>();
    
    public void put(String key, byte[] value) {
        cache.put(key, value);
    }
    
    public byte[] get(String key) {
        return cache.get(key);
    }
}

// Safe implementation with buffer management
class BufferedCache {
    private static final int MAX_BUFFER_SIZE = 1024;
    private Map<String, ByteBuffer> cache = new HashMap<>();
    
    public void put(String key, byte[] value) {
        if (value.length > MAX_BUFFER_SIZE) {
            throw new IllegalArgumentException("Value exceeds maximum buffer size");
        }
        ByteBuffer buffer = ByteBuffer.allocate(value.length);
        buffer.put(value);
        buffer.flip();
        cache.put(key, buffer);
    }
    
    public byte[] get(String key) {
        ByteBuffer buffer = cache.get(key);
        if (buffer == null) {
            return null;
        }
        byte[] result = new byte[buffer.remaining()];
        buffer.get(result);
        buffer.flip();
        return result;
    }
}

public class InsecureCacheExamples {

    // True Positive Examples (Vulnerable Code)
    
// {fact rule=incorrect-buffer-length-access@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) {
        String userData = request.getParameter("userData");
        StringByteConverter converter = new StringByteConverter();
        Cache cache = new Cache();
        
        // ruleid: java-insecure-usage-of-cache
        cache.put("user_data", converter.toBytes(userData));
    }
    
    public void bad_case_2(HttpServletRequest request) {
        String sessionId = request.getParameter("sessionId");
        Cache cache = new Cache();
        StringByteConverter converter = new StringByteConverter();
        
        // ruleid: java-insecure-usage-of-cache
        byte[] sessionBytes = converter.toBytes(sessionId);
        cache.put("session", sessionBytes);
    }
    
    public void bad_case_3(HttpServletRequest request, HttpServletResponse response) {
        String userInput = request.getParameter("input");
        Cache dataCache = new Cache();
        StringByteConverter converter = new StringByteConverter();
        
        // Process and store in cache
        // ruleid: java-insecure-usage-of-cache
        dataCache.put("processed_data", converter.toBytes(userInput + "_processed"));
    }
    
    public void bad_case_4() {
        StringByteConverter converter = new StringByteConverter();
        Cache loggingCache = new Cache();
        
        String largeLogEntry = generateLargeString(10000); // Very large string
        
        // ruleid: java-insecure-usage-of-cache
        loggingCache.put("log_entry", converter.toBytes(largeLogEntry));
    }
    
    public void bad_case_5(HttpServletRequest request) {
        Map<String, String[]> parameters = request.getParameterMap();
        Cache requestCache = new Cache();
        StringByteConverter converter = new StringByteConverter();
        
        for (String key : parameters.keySet()) {
            String[] values = parameters.get(key);
            if (values != null && values.length > 0) {
                // ruleid: java-insecure-usage-of-cache
                requestCache.put(key, converter.toBytes(values[0]));
            }
        }
    }
    
    public void bad_case_6(HttpServletRequest request) {
        String headerValue = request.getHeader("X-Custom-Header");
        Cache headerCache = new Cache();
        StringByteConverter converter = new StringByteConverter();
        
        if (headerValue != null) {
            // ruleid: java-insecure-usage-of-cache
            headerCache.put("custom_header", converter.toBytes(headerValue));
        }
    }
    
    public void bad_case_7() {
        Cache configCache = new Cache();
        StringByteConverter converter = new StringByteConverter();
        
        // Configuration with potentially large values
        String configValue = System.getProperty("app.config");
        
        // ruleid: java-insecure-usage-of-cache
        configCache.put("app_config", converter.toBytes(configValue));
    }
    
    public void bad_case_8(HttpServletRequest request) {
        String cookieValue = getCookieValue(request, "user_pref");
        Cache cookieCache = new Cache();
        StringByteConverter converter = new StringByteConverter();
        
        // ruleid: java-insecure-usage-of-cache
        cookieCache.put("user_preferences", converter.toBytes(cookieValue));
    }
    
    public void bad_case_9() {
        Cache templateCache = new Cache();
        StringByteConverter converter = new StringByteConverter();
        
        String template = loadTemplateFromFile("large_template.html");
        
        // ruleid: java-insecure-usage-of-cache
        templateCache.put("page_template", converter.toBytes(template));
    }
    
    public void bad_case_10(HttpServletRequest request) {
        String jsonData = request.getParameter("jsonData");
        Cache jsonCache = new Cache();
        StringByteConverter converter = new StringByteConverter();
        
        try {
            // Some JSON processing
            String processedJson = processJson(jsonData);
            
            // ruleid: java-insecure-usage-of-cache
            jsonCache.put("processed_json", converter.toBytes(processedJson));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_11(HttpServletRequest request) {
        String base64Data = request.getParameter("data");
        Cache dataCache = new Cache();
        StringByteConverter converter = new StringByteConverter();
        
        // ruleid: java-insecure-usage-of-cache
        dataCache.put("base64_data", converter.toBytes(base64Data));
    }
    
    public void bad_case_12() {
        StringByteConverter converter = new StringByteConverter();
        Cache multiCache = new Cache();
        
        for (int i = 0; i < 100; i++) {
            String data = "Data item " + i + ": " + generateRandomString(500);
            
            // ruleid: java-insecure-usage-of-cache
            multiCache.put("item_" + i, converter.toBytes(data));
        }
    }
    
    public void bad_case_13(HttpServletRequest request) {
        String queryString = request.getQueryString();
        Cache queryCache = new Cache();
        StringByteConverter converter = new StringByteConverter();
        
        if (queryString != null) {
            // ruleid: java-insecure-usage-of-cache
            queryCache.put("last_query", converter.toBytes(queryString));
        }
    }
    
    public void bad_case_14() {
        Cache userCache = new Cache();
        StringByteConverter converter = new StringByteConverter();
        
        // User profile with potentially large data
        String userProfile = fetchUserProfile("user123");
        
        // ruleid: java-insecure-usage-of-cache
        userCache.put("user_profile", converter.toBytes(userProfile));
    }
    
    public void bad_case_15(HttpServletRequest request) {
        String requestBody = getRequestBody(request);
        Cache requestBodyCache = new Cache();
        StringByteConverter converter = new StringByteConverter();
        
        // ruleid: java-insecure-usage-of-cache
        requestBodyCache.put("request_body", converter.toBytes(requestBody));
    }
    
    // True Negative Examples (Safe Code)
    
    public void good_case_1(HttpServletRequest request) {
        String userData = request.getParameter("userData");
        SafeStringByteConverter converter = new SafeStringByteConverter();
        Cache cache = new Cache();
        
        // ok: java-insecure-usage-of-cache
        try {
            cache.put("user_data", converter.toBytes(userData));
        } catch (IllegalArgumentException e) {
            // Handle the exception appropriately
            System.err.println("Data too large: " + e.getMessage());
        }
    }
    
    public void good_case_2(HttpServletRequest request) {
        String sessionId = request.getParameter("sessionId");
        BufferedCache cache = new BufferedCache();
        
        // ok: java-insecure-usage-of-cache
        try {
            cache.put("session", sessionId.getBytes());
        } catch (IllegalArgumentException e) {
            // Handle the exception appropriately
            System.err.println("Session data too large: " + e.getMessage());
        }
    }
    
    public void good_case_3(HttpServletRequest request) {
        String userInput = request.getParameter("input");
        
        // Using ByteBuffer directly with capacity checks
        // ok: java-insecure-usage-of-cache
        ByteBuffer buffer = ByteBuffer.allocate(1024); // Fixed size buffer
        byte[] inputBytes = userInput.getBytes();
        
        if (inputBytes.length <= buffer.capacity()) {
            buffer.put(inputBytes);
            buffer.flip();
            // Use the buffer safely
        } else {
            // Handle the overflow condition
            System.err.println("Input too large for buffer");
        }
    }
    
    public void good_case_4() {
        BufferedCache loggingCache = new BufferedCache();
        
        String largeLogEntry = generateLargeString(10000);
        
        // ok: java-insecure-usage-of-cache
        try {
            loggingCache.put("log_entry", largeLogEntry.getBytes());
        } catch (IllegalArgumentException e) {
            // Handle oversized log entry
            String truncatedLog = largeLogEntry.substring(0, 1000) + "... (truncated)";
            loggingCache.put("log_entry_truncated", truncatedLog.getBytes());
        }
    }
    
    public void good_case_5(HttpServletRequest request) {
        Map<String, String[]> parameters = request.getParameterMap();
        BufferedCache requestCache = new BufferedCache();
        
        // ok: java-insecure-usage-of-cache
        for (String key : parameters.keySet()) {
            String[] values = parameters.get(key);
            if (values != null && values.length > 0) {
                try {
                    requestCache.put(key, values[0].getBytes());
                } catch (IllegalArgumentException e) {
                    // Handle oversized parameter
                    System.err.println("Parameter too large: " + key);
                }
            }
        }
    }
    
    public void good_case_6(HttpServletRequest request) {
        String headerValue = request.getHeader("X-Custom-Header");
        SafeStringByteConverter converter = new SafeStringByteConverter();
        Cache headerCache = new Cache();
        
        if (headerValue != null) {
            // ok: java-insecure-usage-of-cache
            try {
                headerCache.put("custom_header", converter.toBytes(headerValue));
            } catch (IllegalArgumentException e) {
                // Handle oversized header
                System.err.println("Header too large: " + e.getMessage());
            }
        }
    }
    
    public void good_case_7() {
        BufferedCache configCache = new BufferedCache();
        
        // Configuration with potentially large values
        String configValue = System.getProperty("app.config");
        
        // ok: java-insecure-usage-of-cache
        try {
            configCache.put("app_config", configValue.getBytes());
        } catch (IllegalArgumentException e) {
            // Handle oversized config
            System.err.println("Config too large: " + e.getMessage());
            // Store a reference instead
            configCache.put("app_config_ref", "config_file.properties".getBytes());
        }
    }
    
    public void good_case_8(HttpServletRequest request) {
        String cookieValue = getCookieValue(request, "user_pref");
        
        // Using Java NIO ByteBuffer with capacity checks
        // ok: java-insecure-usage-of-cache
        int maxSize = 512;
        if (cookieValue != null) {
            byte[] cookieBytes = cookieValue.getBytes();
            if (cookieBytes.length <= maxSize) {
                ByteBuffer buffer = ByteBuffer.allocate(maxSize);
                buffer.put(cookieBytes);
                buffer.flip();
                // Use the buffer safely
            } else {
                // Handle oversized cookie
                System.err.println("Cookie value too large");
            }
        }
    }
    
    public void good_case_9() {
        BufferedCache templateCache = new BufferedCache();
        
        String template = loadTemplateFromFile("large_template.html");
        
        // ok: java-insecure-usage-of-cache
        try {
            templateCache.put("page_template", template.getBytes());
        } catch (IllegalArgumentException e) {
            // Handle oversized template
            System.err.println("Template too large, storing reference instead");
            templateCache.put("page_template_ref", "large_template.html".getBytes());
        }
    }
    
    public void good_case_10(HttpServletRequest request) {
        String jsonData = request.getParameter("jsonData");
        SafeStringByteConverter converter = new SafeStringByteConverter();
        Cache jsonCache = new Cache();
        
        try {
            // Some JSON processing
            String processedJson = processJson(jsonData);
            
            // ok: java-insecure-usage-of-cache
            try {
                jsonCache.put("processed_json", converter.toBytes(processedJson));
            } catch (IllegalArgumentException e) {
                // Handle oversized JSON
                System.err.println("JSON data too large: " + e.getMessage());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_11(HttpServletRequest request) {
        String base64Data = request.getParameter("data");
        BufferedCache dataCache = new BufferedCache();
        
        // ok: java-insecure-usage-of-cache
        if (base64Data != null && base64Data.length() <= 1024) {
            try {
                dataCache.put("base64_data", base64Data.getBytes());
            } catch (IllegalArgumentException e) {
                // Handle exception
                System.err.println("Data too large: " + e.getMessage());
            }
        } else {
            System.err.println("Data exceeds maximum allowed length");
        }
    }
    
    public void good_case_12() {
        BufferedCache multiCache = new BufferedCache();
        
        // ok: java-insecure-usage-of-cache
        for (int i = 0; i < 100; i++) {
            String data = "Data item " + i + ": " + generateRandomString(500);
            try {
                multiCache.put("item_" + i, data.getBytes());
            } catch (IllegalArgumentException e) {
                // Handle oversized data
                System.err.println("Item " + i + " too large, skipping");
            }
        }
    }
    
    public void good_case_13(HttpServletRequest request) {
        String queryString = request.getQueryString();
        SafeStringByteConverter converter = new SafeStringByteConverter();
        Cache queryCache = new Cache();
        
        if (queryString != null) {
            // ok: java-insecure-usage-of-cache
            try {
                queryCache.put("last_query", converter.toBytes(queryString));
            } catch (IllegalArgumentException e) {
                // Handle oversized query string
                System.err.println("Query string too large: " + e.getMessage());
            }
        }
    }
    
    public void good_case_14() {
        BufferedCache userCache = new BufferedCache();
        
        // User profile with potentially large data
        String userProfile = fetchUserProfile("user123");
        
        // ok: java-insecure-usage-of-cache
        try {
            userCache.put("user_profile", userProfile.getBytes());
        } catch (IllegalArgumentException e) {
            // Handle oversized profile
            System.err.println("User profile too large, storing reference");
            userCache.put("user_profile_ref", "user123".getBytes());
        }
    }
    
    public void good_case_15(HttpServletRequest request) {
        String requestBody = getRequestBody(request);
        
        // Using Java NIO with proper capacity checks
        // ok: java-insecure-usage-of-cache
        int maxSize = 2048;
        byte[] bodyBytes = requestBody.getBytes();
        
        if (bodyBytes.length <= maxSize) {
            ByteBuffer buffer = ByteBuffer.allocate(maxSize);
            buffer.put(bodyBytes);
            buffer.flip();
            // Use the buffer safely
        } else {
            // Handle oversized request body
            System.err.println("Request body too large for buffer");
        }
    }
    
    // Helper methods
    
    private String getCookieValue(HttpServletRequest request, String cookieName) {
        // Implementation to get cookie value
        return "sample_cookie_value";
    }
    
    private String generateLargeString(int size) {
        StringBuilder sb = new StringBuilder(size);
        for (int i = 0; i < size; i++) {
            sb.append('X');
        }
        return sb.toString();
    }
    
    private String loadTemplateFromFile(String filename) {
        // Implementation to load template
        return "<html><body>Sample template content</body></html>";
    }
    
    private String processJson(String jsonData) {
        // Implementation to process JSON
        return "{\"processed\": true, \"data\": \"" + jsonData + "\"}";
    }
    
    private String fetchUserProfile(String userId) {
        // Implementation to fetch user profile
        return "{\"id\":\"" + userId + "\",\"name\":\"John Doe\",\"email\":\"john@example.com\"}";
    }
    
    private String getRequestBody(HttpServletRequest request) {
        // Implementation to get request body
        return "sample_request_body";
    }
    
    private String generateRandomString(int length) {
        StringBuilder sb = new StringBuilder(length);
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        for (int i = 0; i < length; i++) {
            int index = (int)(chars.length() * Math.random());
            sb.append(chars.charAt(index));
        }
        return sb.toString();
    }
}
// {/fact}