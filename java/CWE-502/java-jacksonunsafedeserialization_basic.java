import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator;
import com.fasterxml.jackson.databind.jsontype.PolymorphicTypeValidator;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeName;
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;
import java.util.HashMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.stereotype.Controller;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.stream.Collectors;

// Example classes for deserialization
class Animal {
    public String name;
}

class Dog extends Animal {
    public String breed;
}

class Cat extends Animal {
    public boolean likesMilk;
}

@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.PROPERTY, property = "type")
@JsonSubTypes({
    @JsonSubTypes.Type(value = SafeDog.class, name = "dog"),
    @JsonSubTypes.Type(value = SafeCat.class, name = "cat")
})
class SafeAnimal {
    public String name;
}

class SafeDog extends SafeAnimal {
    public String breed;
}

class SafeCat extends SafeAnimal {
    public boolean likesMilk;
}

@RestController
public class JacksonDeserializationExamples {

    // True Positives (Vulnerable Code)
    
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
    @RequestMapping("/bad_case_1")
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String json = request.getParameter("data");
        ObjectMapper mapper = new ObjectMapper();
        // ruleid: java-jacksonunsafedeserialization
        mapper.enableDefaultTyping(); // This is unsafe
        Object obj = mapper.readValue(json, Object.class);
        response.getWriter().write("Processed: " + obj.toString());
    }
    
    @RequestMapping("/bad_case_2")
    public void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(request.getInputStream()));
        String json = reader.lines().collect(Collectors.joining());
        ObjectMapper mapper = new ObjectMapper();
        // ruleid: java-jacksonunsafedeserialization
        mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.OBJECT_AND_NON_CONCRETE);
        Animal animal = mapper.readValue(json, Animal.class);
        response.getWriter().write("Animal name: " + animal.name);
    }
    
    @PostMapping("/bad_case_3")
    public Map<String, Object> bad_case_3(@RequestBody String jsonData) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        // ruleid: java-jacksonunsafedeserialization
        mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_CONCRETE_AND_ARRAYS);
        Map<String, Object> dataMap = mapper.readValue(jsonData, Map.class);
        return dataMap;
    }
    
    @RequestMapping("/bad_case_4")
    public void bad_case_4(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String json = request.getHeader("X-Data");
        ObjectMapper mapper = new ObjectMapper();
        // ruleid: java-jacksonunsafedeserialization
        mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
        Object obj = mapper.readValue(json, Object.class);
        response.getWriter().write("Processed header data");
    }
    
    @RequestMapping("/bad_case_5")
    public void bad_case_5(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String cookie = request.getCookies()[0].getValue();
        ObjectMapper mapper = new ObjectMapper();
        // ruleid: java-jacksonunsafedeserialization
        mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.ALL);
        Map<String, Object> data = mapper.readValue(cookie, Map.class);
        response.getWriter().write("Cookie processed");
    }
    
    @PostMapping("/bad_case_6")
    public void bad_case_6(HttpServletRequest request) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        // Configure some features but still use unsafe typing
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        // ruleid: java-jacksonunsafedeserialization
        mapper.enableDefaultTyping();
        String json = request.getReader().lines().collect(Collectors.joining());
        mapper.readValue(json, Object.class);
    }
    
    @RequestMapping("/bad_case_7")
    public void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(SerializationFeature.INDENT_OUTPUT, true);
        // ruleid: java-jacksonunsafedeserialization
        mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.OBJECT_AND_NON_CONCRETE);
        String json = request.getParameter("payload");
        Object obj = mapper.readValue(json, Object.class);
        response.getWriter().write(mapper.writeValueAsString(obj));
    }
    
    @PostMapping("/bad_case_8")
    public Animal bad_case_8(@RequestBody String jsonInput) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        // ruleid: java-jacksonunsafedeserialization
        mapper.enableDefaultTyping();
        if (jsonInput.contains("dog")) {
            return mapper.readValue(jsonInput, Dog.class);
        } else {
            return mapper.readValue(jsonInput, Cat.class);
        }
    }
    
    @RequestMapping("/bad_case_9")
    public void bad_case_9(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String json = request.getParameter("data");
        ObjectMapper mapper = new ObjectMapper();
        // Multiple configurations with unsafe typing
        mapper.configure(DeserializationFeature.AC_REDACTED_TWILIO_ID_SINGLE_VALUE_AS_ARRAY, true);
        mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
        // ruleid: java-jacksonunsafedeserialization
        mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
        Object obj = mapper.readValue(json, Object.class);
        response.getWriter().write("Processed");
    }
    
    @PostMapping("/bad_case_10")
    public void bad_case_10(HttpServletRequest request) throws IOException {
        // Create mapper in a separate method but still vulnerable
        ObjectMapper mapper = createMapperWithDefaultTyping();
        String json = request.getReader().lines().collect(Collectors.joining());
        mapper.readValue(json, Object.class);
    }
    
    private ObjectMapper createMapperWithDefaultTyping() {
        ObjectMapper mapper = new ObjectMapper();
        // ruleid: java-jacksonunsafedeserialization
        mapper.enableDefaultTyping();
        return mapper;
    }
    
    @RequestMapping("/bad_case_11")
    public void bad_case_11(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Using try-catch but still vulnerable
        try {
            String json = request.getParameter("data");
            ObjectMapper mapper = new ObjectMapper();
            // ruleid: java-jacksonunsafedeserialization
            mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.JAVA_LANG_OBJECT);
            Object obj = mapper.readValue(json, Object.class);
            response.getWriter().write("Success");
        } catch (Exception e) {
            response.getWriter().write("Error: " + e.getMessage());
        }
    }
    
    @PostMapping("/bad_case_12")
    public Map<String, Object> bad_case_12(@RequestBody Map<String, String> input) throws IOException {
        String json = input.get("payload");
        ObjectMapper mapper = new ObjectMapper();
        // ruleid: java-jacksonunsafedeserialization
        mapper.enableDefaultTyping();
        return mapper.readValue(json, Map.class);
    }
    
    @RequestMapping("/bad_case_13")
    public void bad_case_13(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Using a loop but still vulnerable
        String[] jsonInputs = request.getParameterValues("data");
        ObjectMapper mapper = new ObjectMapper();
        // ruleid: java-jacksonunsafedeserialization
        mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_CONCRETE_AND_ARRAYS);
        
        for (String json : jsonInputs) {
            Object obj = mapper.readValue(json, Object.class);
            response.getWriter().write(obj.toString() + "\n");
        }
    }
    
    @PostMapping("/bad_case_14")
    public void bad_case_14(HttpServletRequest request) throws IOException {
        // Using conditional logic but still vulnerable
        String contentType = request.getHeader("Content-Type");
        String json = request.getReader().lines().collect(Collectors.joining());
        
        ObjectMapper mapper = new ObjectMapper();
        if (contentType.contains("application/json")) {
            // ruleid: java-jacksonunsafedeserialization
            mapper.enableDefaultTyping();
        } else {
            // Still vulnerable in else branch
            // ruleid: java-jacksonunsafedeserialization
            mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
        }
        
        mapper.readValue(json, Object.class);
    }
    
    @RequestMapping("/bad_case_15")
    public void bad_case_15(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Complex configuration but still vulnerable
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        mapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
        mapper.configure(DeserializationFeature.AC_REDACTED_TWILIO_ID_EMPTY_STRING_AS_NULL_OBJECT, true);
        
        // ruleid: java-jacksonunsafedeserialization
        mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.OBJECT_AND_NON_CONCRETE);
        
        String json = request.getParameter("data");
        Object obj = mapper.readValue(json, Object.class);
        response.getWriter().write("Processed complex configuration");
    }
    
    // True Negatives (Secure Code)
    
    @RequestMapping("/good_case_1")
    public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String json = request.getParameter("data");
        ObjectMapper mapper = new ObjectMapper();
        // ok: java-jacksonunsafedeserialization
        // Using specific class instead of enabling default typing
        Animal animal = mapper.readValue(json, Animal.class);
        response.getWriter().write("Animal name: " + animal.name);
    }
    
    @PostMapping("/good_case_2")
    public void good_case_2(@RequestBody String jsonData) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        // ok: java-jacksonunsafedeserialization
        // Using PolymorphicTypeValidator for safer deserialization
        PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
            .allowIfSubType("com.example.model")
            .build();
        mapper.activateDefaultTyping(ptv, ObjectMapper.DefaultTyping.NON_FINAL);
        mapper.readValue(jsonData, Object.class);
    }
    
    @RequestMapping("/good_case_3")
    public void good_case_3(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String json = request.getParameter("data");
        ObjectMapper mapper = new ObjectMapper();
        // ok: java-jacksonunsafedeserialization
        // Using annotations for type info instead of enableDefaultTyping
        SafeAnimal animal = mapper.readValue(json, SafeAnimal.class);
        response.getWriter().write("Animal processed safely");
    }
    
    @PostMapping("/good_case_4")
    public Map<String, Object> good_case_4(@RequestBody String jsonData) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        // ok: java-jacksonunsafedeserialization
        // Explicitly using HashMap instead of enabling default typing
        HashMap<String, Object> map = mapper.readValue(jsonData, HashMap.class);
        return map;
    }
    
    @RequestMapping("/good_case_5")
    public void good_case_5(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String json = request.getHeader("X-Data");
        ObjectMapper mapper = new ObjectMapper();
        // ok: java-jacksonunsafedeserialization
        // Disabling default typing explicitly
        mapper.disableDefaultTyping();
        Object obj = mapper.readValue(json, Object.class);
        response.getWriter().write("Processed safely");
    }
    
    @PostMapping("/good_case_6")
    public void good_case_6(HttpServletRequest request) throws IOException {
        String json = request.getReader().lines().collect(Collectors.joining());
        ObjectMapper mapper = new ObjectMapper();
        // ok: java-jacksonunsafedeserialization
        // Using specific class with validation
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);
        Dog dog = mapper.readValue(json, Dog.class);
        validateDog(dog);
    }
    
    private void validateDog(Dog dog) {
        if (dog.name == null || dog.breed == null) {
            throw new IllegalArgumentException("Invalid dog data");
        }
    }
    
    @RequestMapping("/good_case_7")
    public void good_case_7(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String json = request.getParameter("data");
        // ok: java-jacksonunsafedeserialization
        // Using a secure mapper with proper validation
        ObjectMapper mapper = createSecureMapper();
        Animal animal = mapper.readValue(json, Animal.class);
        response.getWriter().write("Processed with secure mapper");
    }
    
    private ObjectMapper createSecureMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);
        return mapper;
    }
    
    @PostMapping("/good_case_8")
    public void good_case_8(@RequestBody String jsonInput) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        // ok: java-jacksonunsafedeserialization
        // Using PolymorphicTypeValidator with specific allowed classes
        PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
            .allowIfBaseType(Animal.class)
            .allowIfSubType(Dog.class)
            .allowIfSubType(Cat.class)
            .build();
        mapper.activateDefaultTyping(ptv);
        mapper.readValue(jsonInput, Animal.class);
    }
    
    @RequestMapping("/good_case_9")
    public void good_case_9(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // ok: java-jacksonunsafedeserialization
        // Using a custom deserializer instead of default typing
        String json = request.getParameter("data");
        ObjectMapper mapper = new ObjectMapper();
        if (json.contains("dog")) {
            Dog dog = mapper.readValue(json, Dog.class);
            response.getWriter().write("Dog: " + dog.name);
        } else {
            Cat cat = mapper.readValue(json, Cat.class);
            response.getWriter().write("Cat: " + cat.name);
        }
    }
    
    @PostMapping("/good_case_10")
    public void good_case_10(HttpServletRequest request) throws IOException {
        String json = request.getReader().lines().collect(Collectors.joining());
        ObjectMapper mapper = new ObjectMapper();
        // ok: java-jacksonunsafedeserialization
        // Using explicit type reference
        Map<String, Animal> animalMap = mapper.readValue(json, 
            mapper.getTypeFactory().constructMapType(Map.class, String.class, Animal.class));
    }
    
    @RequestMapping("/good_case_11")
    public void good_case_11(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            String json = request.getParameter("data");
            ObjectMapper mapper = new ObjectMapper();
            // ok: java-jacksonunsafedeserialization
            // Using safe configuration
            mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);
            mapper.configure(DeserializationFeature.BLOCK_UNSAFE_POLYMORPHIC_BASE_TYPES, true);
            Animal animal = mapper.readValue(json, Animal.class);
            response.getWriter().write("Processed safely with validation");
        } catch (Exception e) {
            response.getWriter().write("Error: " + e.getMessage());
        }
    }
    
    @PostMapping("/good_case_12")
    public Map<String, Object> good_case_12(@RequestBody Map<String, String> input) throws IOException {
        String json = input.get("payload");
        ObjectMapper mapper = new ObjectMapper();
        // ok: java-jacksonunsafedeserialization
        // Using specific class with validation
        Map<String, String> result = mapper.readValue(json, Map.class);
        validateMap(result);
        return new HashMap<>(result);
    }
    
    private void validateMap(Map<String, String> map) {
        for (Map.Entry<String, String> entry : map.entrySet()) {
            if (entry.getValue() == null) {
                throw new IllegalArgumentException("Null values not allowed");
            }
        }
    }
    
    @RequestMapping("/good_case_13")
    public void good_case_13(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String[] jsonInputs = request.getParameterValues("data");
        ObjectMapper mapper = new ObjectMapper();
        // ok: java-jacksonunsafedeserialization
        // Using specific class for each item in the array
        for (String json : jsonInputs) {
            Animal animal = mapper.readValue(json, Animal.class);
            response.getWriter().write(animal.name + "\n");
        }
    }
    
    @PostMapping("/good_case_14")
    public void good_case_14(HttpServletRequest request) throws IOException {
        String contentType = request.getHeader("Content-Type");
        String json = request.getReader().lines().collect(Collectors.joining());
        
        ObjectMapper mapper = new ObjectMapper();
        // ok: java-jacksonunsafedeserialization
        // Using safe configuration in both branches
        if (contentType.contains("application/json")) {
            mapper.configure(DeserializationFeature.BLOCK_UNSAFE_POLYMORPHIC_BASE_TYPES, true);
            Dog dog = mapper.readValue(json, Dog.class);
        } else {
            mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);
            Cat cat = mapper.readValue(json, Cat.class);
        }
    }
    
    @RequestMapping("/good_case_15")
    public void good_case_15(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // ok: java-jacksonunsafedeserialization
        // Using PolymorphicTypeValidator with whitelisted packages
        String json = request.getParameter("data");
        ObjectMapper mapper = new ObjectMapper();
        
        PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
            .allowIfBaseType("com.example")
            .allowIfSubType("com.example.model")
            .allowIfSubType("java.util.ArrayList")
            .allowIfSubType("java.util.HashMap")
            .build();
            
        mapper.activateDefaultTyping(ptv, ObjectMapper.DefaultTyping.NON_FINAL);
        Object obj = mapper.readValue(json, Object.class);
        response.getWriter().write("Processed with secure polymorphic validator");
    }
}
// {/fact}