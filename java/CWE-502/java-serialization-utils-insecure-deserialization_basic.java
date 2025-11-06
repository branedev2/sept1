import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Cookie;
import org.apache.commons.lang3.SerializationUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.Controller;
import org.springframework.http.ResponseEntity;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SealedObject;
import javax.crypto.spec.SecretKeySpec;

// True Positive Examples (Vulnerable Code)

@Controller
public class InsecureDeserializationExamples {
    
    // Example 1: Deserializing data from HTTP request parameter
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
    @RequestMapping("/bad1")
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String serializedData = request.getParameter("data");
        byte[] data = Base64.getDecoder().decode(serializedData);
        
        // ruleid: java-serialization-utils-insecure-deserialization
        Object obj = SerializationUtils.deserialize(data);
        
        response.getWriter().write("Deserialized object: " + obj.toString());
    }
    
    // Example 2: Deserializing data from HTTP request body
    @PostMapping("/bad2")
    public ResponseEntity<String> bad_case_2(HttpServletRequest request) throws IOException {
        InputStream inputStream = request.getInputStream();
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int length;
        while ((length = inputStream.read(buffer)) != -1) {
            result.write(buffer, 0, length);
        }
        
        // ruleid: java-serialization-utils-insecure-deserialization
        Object obj = SerializationUtils.deserialize(result.toByteArray());
        
        return ResponseEntity.ok("Processed: " + obj.toString());
    }
    
    // Example 3: Deserializing data from HTTP header
    @GetMapping("/bad3")
    public void bad_case_3(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String serializedHeader = request.getHeader("X-Serialized-Object");
        if (serializedHeader != null) {
            byte[] data = Base64.getDecoder().decode(serializedHeader);
            
            // ruleid: java-serialization-utils-insecure-deserialization
            Map<String, Object> deserializedMap = (Map<String, Object>) SerializationUtils.deserialize(data);
            
            response.getWriter().write("Header processed with keys: " + deserializedMap.keySet());
        }
    }
    
    // Example 4: Deserializing data from cookie
    @GetMapping("/bad4")
    public void bad_case_4(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("serializedData".equals(cookie.getName())) {
                    byte[] data = Base64.getDecoder().decode(cookie.getValue());
                    
                    // ruleid: java-serialization-utils-insecure-deserialization
                    Object obj = SerializationUtils.deserialize(data);
                    
                    response.getWriter().write("Cookie data: " + obj);
                    break;
                }
            }
        }
    }
    
    // Example 5: Deserializing data from file uploaded by user
    @PostMapping("/bad5")
    public ResponseEntity<String> bad_case_5(@RequestParam("file") byte[] fileData) {
        try {
            // ruleid: java-serialization-utils-insecure-deserialization
            Object obj = SerializationUtils.deserialize(fileData);
            return ResponseEntity.ok("File processed: " + obj.toString());
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error: " + e.getMessage());
        }
    }
    
    // Example 6: Deserializing data from URL parameter with try-catch
    @GetMapping("/bad6")
    public void bad_case_6(HttpServletRequest request, HttpServletResponse response) {
        try {
            String base64Data = request.getParameter("serializedObj");
            byte[] serializedData = Base64.getDecoder().decode(base64Data);
            
            // ruleid: java-serialization-utils-insecure-deserialization
            Object obj = SerializationUtils.deserialize(serializedData);
            
            response.getWriter().write("Object class: " + obj.getClass().getName());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Example 7: Deserializing data from a POST request with JSON wrapper
    @PostMapping("/bad7")
    public ResponseEntity<String> bad_case_7(@RequestBody Map<String, String> payload) {
        try {
            String base64Data = payload.get("serializedContent");
            byte[] binaryData = Base64.getDecoder().decode(base64Data);
            
            // ruleid: java-serialization-utils-insecure-deserialization
            Object result = SerializationUtils.deserialize(binaryData);
            
            return ResponseEntity.ok("Processed object of type: " + result.getClass().getName());
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error processing data: " + e.getMessage());
        }
    }
    
    // Example 8: Deserializing from a multipart form submission
    @PostMapping("/bad8")
    public void bad_case_8(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (request.getContentType() != null && request.getContentType().startsWith("multipart/form-data")) {
            byte[] serializedBytes = request.getPart("serializedObject").getInputStream().readAllBytes();
            
            // ruleid: java-serialization-utils-insecure-deserialization
            Object deserializedObject = SerializationUtils.deserialize(serializedBytes);
            
            response.getWriter().write("Processed multipart object: " + deserializedObject);
        }
    }
    
    // Example 9: Deserializing from an external URL
    @GetMapping("/bad9")
    public ResponseEntity<String> bad_case_9(@RequestParam String dataUrl) throws IOException {
        URL url = new URL(dataUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        
        try (InputStream inputStream = connection.getInputStream()) {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            int bytesRead;
            byte[] data = new byte[1024];
            while ((bytesRead = inputStream.read(data, 0, data.length)) != -1) {
                buffer.write(data, 0, bytesRead);
            }
            
            // ruleid: java-serialization-utils-insecure-deserialization
            Object obj = SerializationUtils.deserialize(buffer.toByteArray());
            
            return ResponseEntity.ok("Retrieved and deserialized: " + obj);
        }
    }
    
    // Example 10: Deserializing with conditional logic
    @GetMapping("/bad10")
    public void bad_case_10(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String action = request.getParameter("action");
        String serializedData = request.getParameter("data");
        
        if ("process".equals(action) && serializedData != null && !serializedData.isEmpty()) {
            byte[] data = Base64.getDecoder().decode(serializedData);
            
            // ruleid: java-serialization-utils-insecure-deserialization
            Object obj = SerializationUtils.deserialize(data);
            
            response.getWriter().write("Processed: " + obj);
        } else {
            response.getWriter().write("No action taken");
        }
    }
    
    // Example 11: Deserializing in a loop for batch processing
    @PostMapping("/bad11")
    public ResponseEntity<String> bad_case_11(@RequestBody Map<String, String[]> batchData) {
        StringBuilder results = new StringBuilder();
        String[] encodedObjects = batchData.get("batchItems");
        
        if (encodedObjects != null) {
            for (String encoded : encodedObjects) {
                byte[] data = Base64.getDecoder().decode(encoded);
                
                // ruleid: java-serialization-utils-insecure-deserialization
                Object obj = SerializationUtils.deserialize(data);
                
                results.append("Processed: ").append(obj).append("\n");
            }
        }
        
        return ResponseEntity.ok(results.toString());
    }
    
    // Example 12: Deserializing with a wrapper method
    @GetMapping("/bad12")
    public void bad_case_12(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String serializedData = request.getParameter("objData");
        byte[] data = Base64.getDecoder().decode(serializedData);
        
        Object obj = deserializeData(data);
        response.getWriter().write("Object: " + obj);
    }
    
    private Object deserializeData(byte[] data) {
        // ruleid: java-serialization-utils-insecure-deserialization
        return SerializationUtils.deserialize(data);
    }
    
    // Example 13: Deserializing from a base64 string with transformation
    @PostMapping("/bad13")
    public ResponseEntity<String> bad_case_13(@RequestBody String base64Data) {
        try {
            // Remove any whitespace or newlines that might be in the base64 string
            base64Data = base64Data.replaceAll("\\s", "");
            byte[] binaryData = Base64.getDecoder().decode(base64Data);
            
            // ruleid: java-serialization-utils-insecure-deserialization
            Object result = SerializationUtils.deserialize(binaryData);
            
            return ResponseEntity.ok("Successfully processed: " + result);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error: " + e.getMessage());
        }
    }
    
    // Example 14: Deserializing with error handling and logging
    @GetMapping("/bad14")
    public void bad_case_14(HttpServletRequest request, HttpServletResponse response) {
        try {
            String serializedData = request.getParameter("data");
            if (serializedData == null || serializedData.isEmpty()) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing data parameter");
                return;
            }
            
            byte[] binaryData = Base64.getDecoder().decode(serializedData);
            
            // ruleid: java-serialization-utils-insecure-deserialization
            Object obj = SerializationUtils.deserialize(binaryData);
            
            response.setContentType("text/plain");
            response.getWriter().write("Successfully processed object of type: " + obj.getClass().getName());
        } catch (Exception e) {
            try {
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error processing data: " + e.getMessage());
            } catch (IOException ex) {
                // Log the error
                System.err.println("Failed to send error response: " + ex.getMessage());
            }
        }
    }
    
    // Example 15: Deserializing with a switch statement based on content type
    @PostMapping("/bad15")
    public ResponseEntity<String> bad_case_15(HttpServletRequest request, @RequestParam String contentType) throws IOException {
        byte[] data;
        
        switch (contentType) {
            case "form":
                data = Base64.getDecoder().decode(request.getParameter("formData"));
                break;
            case "body":
                ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                InputStream inputStream = request.getInputStream();
                int bytesRead;
                byte[] temp = new byte[1024];
                while ((bytesRead = inputStream.read(temp)) != -1) {
                    buffer.write(temp, 0, bytesRead);
                }
                data = buffer.toByteArray();
                break;
            case "header":
                data = Base64.getDecoder().decode(request.getHeader("X-Serialized-Data"));
                break;
            default:
                return ResponseEntity.badRequest().body("Unknown content type");
        }
        
        // ruleid: java-serialization-utils-insecure-deserialization
        Object obj = SerializationUtils.deserialize(data);
        
        return ResponseEntity.ok("Processed " + contentType + " data: " + obj);
    }
    
    // True Negative Examples (Secure Code)
    
    // Example 1: Using JSON deserialization instead of SerializationUtils
    @PostMapping("/good1")
    public ResponseEntity<String> good_case_1(@RequestBody String jsonData) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        
        // ok: java-serialization-utils-insecure-deserialization
        Map<String, Object> data = mapper.readValue(jsonData, Map.class);
        
        return ResponseEntity.ok("Processed JSON data with keys: " + data.keySet());
    }
    
    // Example 2: Using a custom whitelist-based deserialization
    @PostMapping("/good2")
    public ResponseEntity<String> good_case_2(HttpServletRequest request) throws IOException {
        String serializedData = request.getParameter("data");
        byte[] data = Base64.getDecoder().decode(serializedData);
        
        // ok: java-serialization-utils-insecure-deserialization
        Object obj = safeDeserialize(data, allowedClasses);
        
        return ResponseEntity.ok("Safely deserialized: " + obj);
    }
    
    private static final Class<?>[] allowedClasses = {String.class, Integer.class, HashMap.class};
    
    private Object safeDeserialize(byte[] data, Class<?>[] allowedClasses) throws IOException, ClassNotFoundException {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(data);
             ObjectInputStream ois = new ObjectInputStreamWithWhitelist(bis, allowedClasses)) {
            return ois.readObject();
        }
    }
    
    // Custom ObjectInputStream that only allows specific classes
    private static class ObjectInputStreamWithWhitelist extends ObjectInputStream {
        private final Class<?>[] allowedClasses;
        
        public ObjectInputStreamWithWhitelist(InputStream in, Class<?>[] allowedClasses) throws IOException {
            super(in);
            this.allowedClasses = allowedClasses;
        }
        
        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
            String className = desc.getName();
            for (Class<?> allowedClass : allowedClasses) {
                if (className.equals(allowedClass.getName())) {
                    return super.resolveClass(desc);
                }
            }
            throw new ClassNotFoundException("Unauthorized deserialization attempt: " + className);
        }
    }
    
    // Example 3: Using encrypted and signed serialized data
    @PostMapping("/good3")
    public ResponseEntity<String> good_case_3(HttpServletRequest request) throws Exception {
        String encryptedData = request.getParameter("encryptedData");
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedData);
        
        // Decrypt the data with a secure key
        SecretKeySpec key = new SecretKeySpec(getSecretKey(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        
        // ok: java-serialization-utils-insecure-deserialization
        SealedObject sealedObject = new SealedObject(new ByteArrayInputStream(encryptedBytes), cipher);
        Object obj = sealedObject.getObject(key);
        
        return ResponseEntity.ok("Decrypted and verified object: " + obj);
    }
    
    private byte[] getSecretKey() {
        // In a real application, this would be securely stored and retrieved
        return "ThisIsASecretKey".getBytes();
    }
    
    // Example 4: Using a database to store and retrieve objects instead of serialization
    @GetMapping("/good4")
    public ResponseEntity<Map<String, Object>> good_case_4(@RequestParam Long id) {
        // ok: java-serialization-utils-insecure-deserialization
        // Instead of deserializing, retrieve from database and construct object
        Map<String, Object> userData = retrieveUserDataFromDatabase(id);
        
        return ResponseEntity.ok(userData);
    }
    
    private Map<String, Object> retrieveUserDataFromDatabase(Long id) {
        // This would be a database call in a real application
        Map<String, Object> userData = new HashMap<>();
        userData.put("id", id);
        userData.put("name", "User " + id);
        userData.put("role", "standard");
        return userData;
    }
    
    // Example 5: Using a secure serialization library
    @PostMapping("/good5")
    public ResponseEntity<String> good_case_5(HttpServletRequest request) throws IOException {
        String jsonData = request.getParameter("data");
        
        // ok: java-serialization-utils-insecure-deserialization
        ObjectMapper mapper = new ObjectMapper();
        mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL, JsonTypeInfo.As.PROPERTY);
        Object obj = mapper.readValue(jsonData, Object.class);
        
        return ResponseEntity.ok("Processed with secure serialization: " + obj);
    }
    
    // Example 6: Using parameter validation and type checking
    @PostMapping("/good6")
    public ResponseEntity<String> good_case_6(@RequestBody Map<String, Object> data) {
        // ok: java-serialization-utils-insecure-deserialization
        // Instead of deserializing unknown objects, we accept a specific data structure
        // and validate its contents
        if (!isValidUserData(data)) {
            return ResponseEntity.badRequest().body("Invalid user data format");
        }
        
        String username = (String) data.get("username");
        Integer age = (Integer) data.get("age");
        
        return ResponseEntity.ok("Processed user: " + username + ", age: " + age);
    }
    
    private boolean isValidUserData(Map<String, Object> data) {
        if (!data.containsKey("username") || !data.containsKey("age")) {
            return false;
        }
        
        return data.get("username") instanceof String && data.get("age") instanceof Integer;
    }
    
    // Example 7: Using a custom serialization format with validation
    @PostMapping("/good7")
    public ResponseEntity<String> good_case_7(@RequestParam String serializedData) {
        // ok: java-serialization-utils-insecure-deserialization
        // Custom string-based serialization format with validation
        String[] parts = serializedData.split("\\|");
        if (parts.length != 3) {
            return ResponseEntity.badRequest().body("Invalid format");
        }
        
        try {
            String type = parts[0];
            String name = parts[1];
            int value = Integer.parseInt(parts[2]);
            
            // Only allow specific types
            if (!type.equals("config") && !type.equals("user")) {
                return ResponseEntity.badRequest().body("Invalid type");
            }
            
            return ResponseEntity.ok("Processed " + type + ": " + name + " with value " + value);
        } catch (NumberFormatException e) {
            return ResponseEntity.badRequest().body("Invalid number format");
        }
    }
    
    // Example 8: Using a factory pattern for safe object creation
    @PostMapping("/good8")
    public ResponseEntity<String> good_case_8(@RequestBody Map<String, Object> objectData) {
        // ok: java-serialization-utils-insecure-deserialization
        Object safeObject = ObjectFactory.createFromMap(objectData);
        
        return ResponseEntity.ok("Created safe object: " + safeObject);
    }
    
    // A simple factory for creating objects safely
    private static class ObjectFactory {
        public static Object createFromMap(Map<String, Object> data) {
            String type = (String) data.get("type");
            if ("user".equals(type)) {
                return new User((String) data.get("name"), (Integer) data.get("age"));
            } else if ("product".equals(type)) {
                return new Product((String) data.get("name"), (Double) data.get("price"));
            }
            throw new IllegalArgumentException("Unknown type: " + type);
        }
    }
    
    private static class User {
        private String name;
        private int age;
        
        public User(String name, int age) {
            this.name = name;
            this.age = age;
        }
        
        @Override
        public String toString() {
            return "User{name='" + name + "', age=" + age + '}';
        }
    }
    
    private static class Product {
        private String name;
        private double price;
        
        public Product(String name, double price) {
            this.name = name;
            this.price = price;
        }
        
        @Override
        public String toString() {
            return "Product{name='" + name + "', price=" + price + '}';
        }
    }
    
    // Example 9: Using protocol buffers instead of Java serialization
    @PostMapping("/good9")
    public ResponseEntity<String> good_case_9(@RequestBody byte[] protoData) {
        try {
            // ok: java-serialization-utils-insecure-deserialization
            // In a real application, this would use the Protocol Buffers library
            // Here we're simulating the concept
            UserProto.User user = parseProtoUser(protoData);
            
            return ResponseEntity.ok("Processed user: " + user.getName());
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Invalid proto data: " + e.getMessage());
        }
    }
    
    // Simulated Protocol Buffers class and parsing
    private static class UserProto {
        public static class User {
            private String name;
            private int id;
            
            public String getName() {
                return name;
            }
            
            public int getId() {
                return id;
            }
        }
    }
    
    private UserProto.User parseProtoUser(byte[] data) {
        // This is a simplified simulation of Protocol Buffers parsing
        // In a real app, you would use the actual protobuf library
        UserProto.User user = new UserProto.User();
        // Parse the binary format safely
        // This is just a placeholder implementation
        return user;
    }
    
    // Example 10: Using a data transfer object with validation
    @PostMapping("/good10")
    public ResponseEntity<String> good_case_10(@RequestBody UserDTO userDto) {
        // ok: java-serialization-utils-insecure-deserialization
        // The framework will deserialize JSON to a specific DTO class with validation
        if (!userDto.isValid()) {
            return ResponseEntity.badRequest().body("Invalid user data");
        }
        
        return ResponseEntity.ok("Processed user: " + userDto.getUsername());
    }
    
    private static class UserDTO {
        private String username;
        private String email;
        private int age;
        
        public String getUsername() {
            return username;
        }
        
        public void setUsername(String username) {
            this.username = username;
        }
        
        public String getEmail() {
            return email;
        }
        
        public void setEmail(String email) {
            this.email = email;
        }
        
        public int getAge() {
            return age;
        }
        
        public void setAge(int age) {
            this.age = age;
        }
        
        public boolean isValid() {
            return username != null && !username.isEmpty() &&
                   email != null && email.contains("@") &&
                   age > 0 && age < 120;
        }
    }
    
    // Example 11: Using XML parsing with schema validation instead of serialization
    @PostMapping("/good11")
    public ResponseEntity<String> good_case_11(@RequestBody String xmlData) {
        try {
            // ok: java-serialization-utils-insecure-deserialization
            // In a real application, this would use proper XML parsing with schema validation
            // Here we're simulating the concept
            Document document = parseAndValidateXml(xmlData);
            String username = document.getElementsByTagName("username").item(0).getTextContent();
            
            return ResponseEntity.ok("Processed XML data for user: " + username);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Invalid XML: " + e.getMessage());
        }
    }
    
    // Simulated XML document class and parsing
    private static class Document {
        public NodeList getElementsByTagName(String tagName) {
            // Simplified simulation
            return new NodeList();
        }
    }
    
    private static class NodeList {
        public Node item(int index) {
            return new Node();
        }
    }
    
    private static class Node {
        public String getTextContent() {
            return "simulated_username";
        }
    }
    
    private Document parseAndValidateXml(String xml) {
        // This would be actual XML parsing with schema validation in a real app
        return new Document();
    }
    
    // Example 12: Using a command pattern with whitelisted commands
    @PostMapping("/good12")
    public ResponseEntity<String> good_case_12(@RequestBody Map<String, Object> commandData) {
        // ok: java-serialization-utils-insecure-deserialization
        String commandType = (String) commandData.get("command");
        Map<String, Object> params = (Map<String, Object>) commandData.get("parameters");
        
        Command command = CommandFactory.createCommand(commandType, params);
        String result = command.execute();
        
        return ResponseEntity.ok("Command result: " + result);
    }
    
    private interface Command {
        String execute();
    }
    
    private static class CommandFactory {
        public static Command createCommand(String type, Map<String, Object> params) {
            // Only allow specific whitelisted commands
            switch (type) {
                case "echo":
                    return new EchoCommand((String) params.get("message"));
                case "add":
                    return new AddCommand((Integer) params.get("a"), (Integer) params.get("b"));
                default:
                    throw new IllegalArgumentException("Unknown command: " + type);
            }
        }
    }
    
    private static class EchoCommand implements Command {
        private final String message;
        
        public EchoCommand(String message) {
            this.message = message;
        }
        
        @Override
        public String execute() {
            return message;
        }
    }
    
    private static class AddCommand implements Command {
        private final int a;
        private final int b;
        
        public AddCommand(int a, int b) {
            this.a = a;
            this.b = b;
        }
        
        @Override
        public String execute() {
            return String.valueOf(a + b);
        }
    }
    
    // Example 13: Using a secure configuration format
    @PostMapping("/good13")
    public ResponseEntity<String> good_case_13(@RequestBody String configData) {
        try {
            // ok: java-serialization-utils-insecure-deserialization
            Properties properties = new Properties();
            properties.load(new StringReader(configData));
            
            String appName = properties.getProperty("app.name");
            String appVersion = properties.getProperty("app.version");
            
            return ResponseEntity.ok("Loaded configuration for " + appName + " v" + appVersion);
        } catch (IOException e) {
            return ResponseEntity.badRequest().body("Invalid configuration format");
        }
    }
    
    // Example 14: Using a builder pattern for safe object construction
    @PostMapping("/good14")
    public ResponseEntity<String> good_case_14(@RequestBody Map<String, Object> userData) {
        // ok: java-serialization-utils-insecure-deserialization
        UserProfile userProfile = new UserProfileBuilder()
            .setUsername((String) userData.get("username"))
            .setEmail((String) userData.get("email"))
            .setAge((Integer) userData.get("age"))
            .build();
        
        return ResponseEntity.ok("Created user profile: " + userProfile);
    }
    
    private static class UserProfile {
        private final String username;
        private final String email;
        private final int age;
        
        private UserProfile(String username, String email, int age) {
            this.username = username;
            this.email = email;
            this.age = age;
        }
        
        @Override
        public String toString() {
            return "UserProfile{username='" + username + "', email='" + email + "', age=" + age + '}';
        }
    }
    
    private static class UserProfileBuilder {
        private String username;
        private String email;
        private int age;
        
        public UserProfileBuilder setUsername(String username) {
            this.username = username;
            return this;
        }
        
        public UserProfileBuilder setEmail(String email) {
            this.email = email;
            return this;
        }
        
        public UserProfileBuilder setAge(Integer age) {
            this.age = age != null ? age : 0;
            return this;
        }
        
        public UserProfile build() {
            // Validate before creating
            if (username == null || username.isEmpty()) {
                throw new IllegalStateException("Username cannot be empty");
            }
            if (email == null || !email.contains("@")) {
                throw new IllegalStateException("Invalid email format");
            }
            if (age < 0 || age > 120) {
                throw new IllegalStateException("Invalid age");
            }
            
            return new UserProfile(username, email, age);
        }
    }
    
    // Example 15: Using immutable data structures with validation
    @PostMapping("/good15")
    public ResponseEntity<String> good_case_15(@RequestBody String jsonData) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        
        // ok: java-serialization-utils-insecure-deserialization
        // Parse JSON into an immutable data structure with validation
        ConfigurationData config = mapper.readValue(jsonData, ConfigurationData.class);
        
        // Validate the configuration
        List<String> validationErrors = config.validate();
        if (!validationErrors.isEmpty()) {
            return ResponseEntity.badRequest().body("Configuration errors: " + String.join(", ", validationErrors));
        }
        
        return ResponseEntity.ok("Valid configuration loaded: " + config.getName());
    }
    
    private static class ConfigurationData {
        private final String name;
        private final Map<String, String> properties;
        private final List<String> enabledFeatures;
        
        @JsonCreator
        public ConfigurationData(
                @JsonProperty("name") String name,
                @JsonProperty("properties") Map<String, String> properties,
                @JsonProperty("enabledFeatures") List<String> enabledFeatures) {
            this.name = name;
            this.properties = properties != null ? Collections.unmodifiableMap(new HashMap<>(properties)) : Collections.emptyMap();
            this.enabledFeatures = enabledFeatures != null ? Collections.unmodifiableList(new ArrayList<>(enabledFeatures)) : Collections.emptyList();
        }
        
        public String getName() {
            return name;
        }
        
        public Map<String, String> getProperties() {
            return properties;
        }
        
        public List<String> getEnabledFeatures() {
            return enabledFeatures;
        }
        
        public List<String> validate() {
            List<String> errors = new ArrayList<>();
            
            if (name == null || name.isEmpty()) {
                errors.add("Name cannot be empty");
            }
            
            // Validate other fields as needed
            
            return errors;
        }
    }
}
// {/fact}