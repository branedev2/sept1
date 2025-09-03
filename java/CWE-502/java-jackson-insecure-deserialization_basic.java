import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator;
import com.fasterxml.jackson.databind.jsontype.PolymorphicTypeValidator;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Map;
import java.util.HashMap;
import java.io.InputStream;
import org.springframework.stereotype.Controller;
import org.springframework.http.ResponseEntity;
import java.util.List;
import java.util.ArrayList;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import org.springframework.http.HttpStatus;

public class JacksonInsecureDeserializationExamples {

    // True Positive Examples (Vulnerable Code)

    @RestController
    public static class VulnerableController1 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
        @PostMapping("/api/data1")
        public ResponseEntity<Object> bad_case_1(HttpServletRequest request) throws IOException {
            String jsonData = readRequestBody(request);
            
            ObjectMapper mapper = new ObjectMapper();
            // ruleid: java-jackson-insecure-deserialization
            mapper.enableDefaultTyping(); // Vulnerable: enables default typing
            
            Object obj = mapper.readValue(jsonData, Object.class);
            return ResponseEntity.ok(obj);
        }
    }
// {/fact}

    @RestController
    public static class VulnerableController2 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
        @PostMapping("/api/data2")
        public ResponseEntity<Object> bad_case_2(HttpServletRequest request) throws IOException {
            String jsonData = readRequestBody(request);
            
            ObjectMapper mapper = new ObjectMapper();
            // ruleid: java-jackson-insecure-deserialization
            mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
            
            Map<String, Object> result = mapper.readValue(jsonData, Map.class);
            return ResponseEntity.ok(result);
        }
    }
// {/fact}

    @RestController
    public static class VulnerableController3 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
        @PostMapping("/api/data3")
        public ResponseEntity<Object> bad_case_3(@RequestBody String jsonData) throws IOException {
            ObjectMapper mapper = new ObjectMapper();
            // ruleid: java-jackson-insecure-deserialization
            mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.OBJECT_AND_NON_CONCRETE);
            
            return ResponseEntity.ok(mapper.readValue(jsonData, Object.class));
        }
    }
// {/fact}

    @Controller
    public static class VulnerableController4 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
        @RequestMapping(value = "/api/data4", method = RequestMethod.POST)
        public void bad_case_4(HttpServletRequest request, HttpServletResponse response) throws IOException {
            BufferedReader reader = request.getReader();
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            String jsonData = sb.toString();
            
            ObjectMapper mapper = new ObjectMapper();
            // ruleid: java-jackson-insecure-deserialization
            mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL, com.fasterxml.jackson.databind.jsontype.impl.As.PROPERTY);
            
            Object obj = mapper.readValue(jsonData, Object.class);
            response.getWriter().write("Processed: " + obj.toString());
        }
    }
// {/fact}

    @RestController
    public static class VulnerableController5 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
        @PostMapping("/api/data5")
        public ResponseEntity<String> bad_case_5(@RequestBody String payload) throws IOException {
            ObjectMapper mapper = new ObjectMapper();
            // ruleid: java-jackson-insecure-deserialization
            mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.EVERYTHING);
            
            Map<String, Object> data = mapper.readValue(payload, Map.class);
            return ResponseEntity.ok("Processed data with " + data.size() + " entries");
        }
    }
// {/fact}

    @RestController
    public static class VulnerableController6 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
        @PostMapping("/api/process")
        public ResponseEntity<Object> bad_case_6(HttpServletRequest request) throws IOException {
            String jsonInput = readRequestBody(request);
            
            ObjectMapper mapper = new ObjectMapper();
            mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
            // ruleid: java-jackson-insecure-deserialization
            mapper.activateDefaultTyping(mapper.getPolymorphicTypeValidator());
            
            return ResponseEntity.ok(mapper.readValue(jsonInput, Object.class));
        }
    }
// {/fact}

    @RestController
    public static class VulnerableController7 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
        @PostMapping("/api/convert")
        public ResponseEntity<String> bad_case_7(@RequestBody String jsonData) throws IOException {
            ObjectMapper mapper = new ObjectMapper();
            // ruleid: java-jackson-insecure-deserialization
            mapper.activateDefaultTyping(mapper.getPolymorphicTypeValidator(), ObjectMapper.DefaultTyping.NON_FINAL);
            
            Object result = mapper.readValue(jsonData, Object.class);
            return ResponseEntity.ok("Converted: " + result.toString());
        }
    }
// {/fact}

    @RestController
    public static class VulnerableController8 {
        private final ObjectMapper mapper;
        
        public VulnerableController8() {
            mapper = new ObjectMapper();
            // ruleid: java-jackson-insecure-deserialization
            mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
        }
        
        @PostMapping("/api/data8")
        public ResponseEntity<Object> bad_case_8(@RequestBody String jsonData) throws IOException {
            return ResponseEntity.ok(mapper.readValue(jsonData, Object.class));
        }
    }

    @RestController
    public static class VulnerableController9 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
        @PostMapping("/api/complex")
        public ResponseEntity<List<Object>> bad_case_9(HttpServletRequest request) throws IOException {
            String jsonData = readRequestBody(request);
            
            ObjectMapper mapper = new ObjectMapper();
            // ruleid: java-jackson-insecure-deserialization
            mapper.activateDefaultTyping(mapper.getPolymorphicTypeValidator(), ObjectMapper.DefaultTyping.EVERYTHING);
            
            List<Object> objects = mapper.readValue(jsonData, List.class);
            return ResponseEntity.ok(objects);
        }
    }
// {/fact}

    @RestController
    public static class VulnerableController10 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
        @PostMapping("/api/data10")
        public ResponseEntity<Object> bad_case_10(@RequestBody InputStream dataStream) throws IOException {
            ObjectMapper mapper = new ObjectMapper();
            // ruleid: java-jackson-insecure-deserialization
            mapper.enableDefaultTyping();
            
            Object result = mapper.readValue(dataStream, Object.class);
            return ResponseEntity.ok(result);
        }
    }
// {/fact}

    @RestController
    public static class VulnerableController11 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
        @PostMapping("/api/nested")
        public ResponseEntity<Map<String, Object>> bad_case_11(@RequestBody String jsonData) throws IOException {
            ObjectMapper outerMapper = new ObjectMapper();
            ObjectMapper innerMapper = new ObjectMapper();
            // ruleid: java-jackson-insecure-deserialization
            innerMapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
            
            Map<String, Object> outerData = outerMapper.readValue(jsonData, Map.class);
            String innerJson = outerData.get("nestedData").toString();
            Map<String, Object> innerData = innerMapper.readValue(innerJson, Map.class);
            
            return ResponseEntity.ok(innerData);
        }
    }
// {/fact}

    @RestController
    public static class VulnerableController12 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
        @PostMapping("/api/conditional")
        public ResponseEntity<Object> bad_case_12(@RequestBody String jsonData, @RequestParam boolean enableTyping) throws IOException {
            ObjectMapper mapper = new ObjectMapper();
            
            if (enableTyping) {
                // ruleid: java-jackson-insecure-deserialization
                mapper.enableDefaultTyping();
            }
            
            Object result = mapper.readValue(jsonData, Object.class);
            return ResponseEntity.ok(result);
        }
    }
// {/fact}

    @RestController
    public static class VulnerableController13 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
        @PostMapping("/api/factory")
        public ResponseEntity<Object> bad_case_13(@RequestBody String jsonData) throws IOException {
            ObjectMapper mapper = createMapperWithDefaultTyping();
            Object result = mapper.readValue(jsonData, Object.class);
            return ResponseEntity.ok(result);
        }
        
        private ObjectMapper createMapperWithDefaultTyping() {
            ObjectMapper mapper = new ObjectMapper();
            // ruleid: java-jackson-insecure-deserialization
            mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
            return mapper;
        }
    }
// {/fact}

    @RestController
    public static class VulnerableController14 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
        @PostMapping("/api/multi-step")
        public ResponseEntity<Object> bad_case_14(@RequestBody String jsonData) throws IOException {
            ObjectMapper mapper = new ObjectMapper();
            configureMapper(mapper);
            
            Object result = mapper.readValue(jsonData, Object.class);
            return ResponseEntity.ok(result);
        }
        
        private void configureMapper(ObjectMapper mapper) {
            mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
            // ruleid: java-jackson-insecure-deserialization
            mapper.enableDefaultTyping();
        }
    }
// {/fact}

    @RestController
    public static class VulnerableController15 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
        @PostMapping("/api/data15")
        public ResponseEntity<Object> bad_case_15(@RequestBody String jsonData) throws IOException {
            ObjectMapper mapper = new ObjectMapper();
            mapper.configure(SerializationFeature.INDENT_OUTPUT, true);
            // ruleid: java-jackson-insecure-deserialization
            mapper.activateDefaultTyping(mapper.getPolymorphicTypeValidator(), ObjectMapper.DefaultTyping.NON_FINAL);
            
            try {
                Object result = mapper.readValue(jsonData, Object.class);
                return ResponseEntity.ok(result);
            } catch (Exception e) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Error processing JSON");
            }
        }
    }
// {/fact}

    // True Negative Examples (Safe Code)

    @RestController
    public static class SafeController1 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
        @PostMapping("/api/safe1")
        public ResponseEntity<Object> good_case_1(@RequestBody String jsonData) throws IOException {
            // ok: java-jackson-insecure-deserialization
            ObjectMapper mapper = new ObjectMapper();
            // No default typing enabled
            
            Object obj = mapper.readValue(jsonData, Object.class);
            return ResponseEntity.ok(obj);
        }
    }
// {/fact}

    @RestController
    public static class SafeController2 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
        @PostMapping("/api/safe2")
        public ResponseEntity<Map<String, Object>> good_case_2(HttpServletRequest request) throws IOException {
            String jsonData = readRequestBody(request);
            
            // ok: java-jackson-insecure-deserialization
            ObjectMapper mapper = new ObjectMapper();
            // Using explicit type information instead of default typing
            
            Map<String, Object> result = mapper.readValue(jsonData, Map.class);
            return ResponseEntity.ok(result);
        }
    }
// {/fact}

    @RestController
    public static class SafeController3 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
        @PostMapping("/api/safe3")
        public ResponseEntity<Object> good_case_3(@RequestBody String jsonData) throws IOException {
            // ok: java-jackson-insecure-deserialization
            PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
                .allowIfBaseType(MyDataClass.class)
                .build();
            
            ObjectMapper mapper = new ObjectMapper();
            mapper.activateDefaultTyping(ptv, ObjectMapper.DefaultTyping.NON_FINAL);
            
            MyDataClass result = mapper.readValue(jsonData, MyDataClass.class);
            return ResponseEntity.ok(result);
        }
    }
// {/fact}

    @RestController
    public static class SafeController4 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
        @PostMapping("/api/safe4")
        public ResponseEntity<Object> good_case_4(HttpServletRequest request) throws IOException {
            String jsonData = readRequestBody(request);
            
            // ok: java-jackson-insecure-deserialization
            ObjectMapper mapper = new ObjectMapper();
            // Using specific classes instead of default typing
            
            if (jsonData.contains("user")) {
                UserData userData = mapper.readValue(jsonData, UserData.class);
                return ResponseEntity.ok(userData);
            } else {
                ProductData productData = mapper.readValue(jsonData, ProductData.class);
                return ResponseEntity.ok(productData);
            }
        }
    }
// {/fact}

    @RestController
    public static class SafeController5 {
        private final ObjectMapper mapper;
        
        public SafeController5() {
            // ok: java-jackson-insecure-deserialization
            mapper = new ObjectMapper();
            // No default typing enabled
        }
        
        @PostMapping("/api/safe5")
        public ResponseEntity<Object> good_case_5(@RequestBody String jsonData) throws IOException {
            Object result = mapper.readValue(jsonData, Object.class);
            return ResponseEntity.ok(result);
        }
    }

    @RestController
    public static class SafeController6 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
        @PostMapping("/api/safe6")
        public ResponseEntity<Object> good_case_6(@RequestBody String jsonData) throws IOException {
            // ok: java-jackson-insecure-deserialization
            ObjectMapper mapper = new ObjectMapper();
            mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
            // No default typing enabled
            
            Map<String, Object> result = mapper.readValue(jsonData, Map.class);
            return ResponseEntity.ok(result);
        }
    }
// {/fact}

    @RestController
    public static class SafeController7 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
        @PostMapping("/api/safe7")
        public ResponseEntity<List<String>> good_case_7(@RequestBody String jsonData) throws IOException {
            // ok: java-jackson-insecure-deserialization
            ObjectMapper mapper = new ObjectMapper();
            // Using specific type instead of default typing
            
            List<String> items = mapper.readValue(jsonData, mapper.getTypeFactory().constructCollectionType(List.class, String.class));
            return ResponseEntity.ok(items);
        }
    }
// {/fact}

    @RestController
    public static class SafeController8 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
        @PostMapping("/api/safe8")
        public ResponseEntity<Object> good_case_8(HttpServletRequest request) throws IOException {
            String jsonData = readRequestBody(request);
            
            // ok: java-jackson-insecure-deserialization
            ObjectMapper mapper = new ObjectMapper();
            // Using custom deserializer instead of default typing
            mapper.registerModule(new CustomDeserializerModule());
            
            Object result = mapper.readValue(jsonData, Object.class);
            return ResponseEntity.ok(result);
        }
    }
// {/fact}

    @RestController
    public static class SafeController9 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
        @PostMapping("/api/safe9")
        public ResponseEntity<Map<String, Object>> good_case_9(@RequestBody InputStream dataStream) throws IOException {
            // ok: java-jackson-insecure-deserialization
            ObjectMapper mapper = new ObjectMapper();
            // No default typing enabled
            
            Map<String, Object> result = mapper.readValue(dataStream, Map.class);
            return ResponseEntity.ok(result);
        }
    }
// {/fact}

    @RestController
    public static class SafeController10 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
        @PostMapping("/api/safe10")
        public ResponseEntity<Object> good_case_10(@RequestBody String jsonData) throws IOException {
            // ok: java-jackson-insecure-deserialization
            PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
                .allowIfSubType("com.example.safe")
                .build();
            
            ObjectMapper mapper = new ObjectMapper();
            mapper.activateDefaultTyping(ptv, ObjectMapper.DefaultTyping.NON_FINAL);
            
            Object result = mapper.readValue(jsonData, Object.class);
            return ResponseEntity.ok(result);
        }
    }
// {/fact}

    @RestController
    public static class SafeController11 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
        @PostMapping("/api/safe11")
        public ResponseEntity<Object> good_case_11(@RequestBody String jsonData) throws IOException {
            // ok: java-jackson-insecure-deserialization
            ObjectMapper mapper = createSafeMapper();
            
            Object result = mapper.readValue(jsonData, Object.class);
            return ResponseEntity.ok(result);
        }
        
        private ObjectMapper createSafeMapper() {
            ObjectMapper mapper = new ObjectMapper();
            // No default typing enabled
            return mapper;
        }
    }
// {/fact}

    @RestController
    public static class SafeController12 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
        @PostMapping("/api/safe12")
        public ResponseEntity<Object> good_case_12(@RequestBody String jsonData) throws IOException {
            // ok: java-jackson-insecure-deserialization
            ObjectMapper mapper = new ObjectMapper();
            configureSafeMapper(mapper);
            
            Object result = mapper.readValue(jsonData, Object.class);
            return ResponseEntity.ok(result);
        }
        
        private void configureSafeMapper(ObjectMapper mapper) {
            mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
            // No default typing enabled
        }
    }
// {/fact}

    @RestController
    public static class SafeController13 {
        @PostMapping("/api/safe13")
        public ResponseEntity<Object> good_case_13(@RequestBody String jsonData) throws IOException {
            // ok: java-jackson-insecure-deserialization
            ObjectMapper mapper = new ObjectMapper();
            // Using explicit class instead of default typing
            
            if (jsonData.startsWith("{\"type\":\"user\"")) {
                UserData userData = mapper.readValue(jsonData, UserData.class);
                return ResponseEntity.ok(userData);
            } else if (jsonData.startsWith("{\"type\":\"product\"")) {
                ProductData productData = mapper.readValue(jsonData, ProductData.class);
                return ResponseEntity.ok(productData);
            } else {
                return ResponseEntity.badRequest().body("Unknown data type");
            }
        }
    }

    @RestController
    public static class SafeController14 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
        @PostMapping("/api/safe14")
        public ResponseEntity<Object> good_case_14(@RequestBody String jsonData) throws IOException {
            // ok: java-jackson-insecure-deserialization
            ObjectMapper mapper = new ObjectMapper();
            // Using custom type resolver instead of default typing
            mapper.setDefaultTyping(null);
            
            Object result = mapper.readValue(jsonData, Object.class);
            return ResponseEntity.ok(result);
        }
    }
// {/fact}

    @RestController
    public static class SafeController15 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
        @PostMapping("/api/safe15")
        public ResponseEntity<Object> good_case_15(@RequestBody String jsonData) throws IOException {
            try {
                // ok: java-jackson-insecure-deserialization
                ObjectMapper mapper = new ObjectMapper();
                // No default typing enabled
                
                Map<String, Object> result = mapper.readValue(jsonData, Map.class);
                return ResponseEntity.ok(result);
            } catch (Exception e) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Error processing JSON");
            }
        }
    }
// {/fact}

    // Helper methods and classes
    private static String readRequestBody(HttpServletRequest request) throws IOException {
        BufferedReader reader = request.getReader();
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            sb.append(line);
        }
        return sb.toString();
    }

    public static class MyDataClass {
        private String name;
        private int value;
        
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public int getValue() { return value; }
        public void setValue(int value) { this.value = value; }
    }
    
    public static class UserData {
        private String username;
        private String email;
        
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        public String getEmail() { return email; }
        public void setEmail(String email) { this.email = email; }
    }
    
    public static class ProductData {
        private String productName;
        private double price;
        
        public String getProductName() { return productName; }
        public void setProductName(String productName) { this.productName = productName; }
        public double getPrice() { return price; }
        public void setPrice(double price) { this.price = price; }
    }
    
    public static class CustomDeserializerModule extends com.fasterxml.jackson.databind.module.SimpleModule {
        // Custom deserializer implementation would go here
    }
}