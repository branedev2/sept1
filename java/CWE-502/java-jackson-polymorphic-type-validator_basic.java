import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator;
import com.fasterxml.jackson.databind.jsontype.PolymorphicTypeValidator;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.fasterxml.jackson.databind.DeserializationFeature;
import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletException;
import java.util.Map;
import java.util.HashMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.stereotype.Controller;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.stream.Collectors;

// Base class for polymorphic deserialization examples
abstract class Animal {
    private String name;
    
    public String getName() {
        return name;
    }
    
    public void setName(String name) {
        this.name = name;
    }
}

@JsonTypeName("dog")
class Dog extends Animal {
    private String breed;
    
    public String getBreed() {
        return breed;
    }
    
    public void setBreed(String breed) {
        this.breed = breed;
    }
}

@JsonTypeName("cat")
class Cat extends Animal {
    private int lives;
    
    public int getLives() {
        return lives;
    }
    
    public void setLives(int lives) {
        this.lives = lives;
    }
}

// Wrapper class with type info
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "type")
@JsonSubTypes({
    @JsonSubTypes.Type(value = Dog.class, name = "dog"),
    @JsonSubTypes.Type(value = Cat.class, name = "cat")
})
abstract class AnimalWithTypeInfo extends Animal {}

class DogWithTypeInfo extends AnimalWithTypeInfo {
    private String breed;
    
    public String getBreed() {
        return breed;
    }
    
    public void setBreed(String breed) {
        this.breed = breed;
    }
}

class CatWithTypeInfo extends AnimalWithTypeInfo {
    private int lives;
    
    public int getLives() {
        return lives;
    }
    
    public void setLives(int lives) {
        this.lives = lives;
    }
}

public class JacksonPolymorphicTypeValidatorExamples extends HttpServlet {

    // TRUE POSITIVES (Vulnerable Code)

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String json = request.getParameter("data");
        ObjectMapper mapper = new ObjectMapper();
        
        // Enable default typing which is unsafe
        // ruleid: java-jackson-polymorphic-type-validator
        mapper.enableDefaultTyping();
        
        Object obj = mapper.readValue(json, Object.class);
        response.getWriter().println("Processed: " + obj.toString());
    }

    public void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String json = request.getReader().lines().collect(Collectors.joining());
        ObjectMapper mapper = new ObjectMapper();
        
        // Enabling polymorphic type handling without validation
        // ruleid: java-jackson-polymorphic-type-validator
        mapper.activateDefaultTyping(mapper.getPolymorphicTypeValidator());
        
        Map<String, Object> result = mapper.readValue(json, Map.class);
        response.getWriter().println("Result: " + result);
    }

    @PostMapping("/api/animals")
    public void bad_case_3(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String json = request.getReader().lines().collect(Collectors.joining());
        ObjectMapper mapper = new ObjectMapper();
        
        // Using enableDefaultTyping with ANY_TYPE is unsafe
        // ruleid: java-jackson-polymorphic-type-validator
        mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
        
        AnimalWithTypeInfo animal = mapper.readValue(json, AnimalWithTypeInfo.class);
        response.getWriter().println("Animal processed: " + animal.getName());
    }

    @RequestMapping("/process")
    public void bad_case_4(HttpServletRequest request, HttpServletResponse response) throws IOException {
        BufferedReader reader = request.getReader();
        String json = reader.lines().collect(Collectors.joining());
        
        ObjectMapper mapper = new ObjectMapper();
        // Unsafe configuration without type validation
        // ruleid: java-jackson-polymorphic-type-validator
        mapper.activateDefaultTyping(mapper.getPolymorphicTypeValidator(), ObjectMapper.DefaultTyping.EVERYTHING);
        
        Object data = mapper.readValue(json, Object.class);
        response.getWriter().println("Processed data: " + data);
    }

    public void bad_case_5(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String jsonData = request.getParameter("jsonData");
        
        ObjectMapper mapper = new ObjectMapper();
        // Using deprecated method without type safety
        // ruleid: java-jackson-polymorphic-type-validator
        mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.OBJECT_AND_NON_CONCRETE);
        
        Map<String, Object> result = mapper.readValue(jsonData, Map.class);
        response.getWriter().println("Result: " + result);
    }

    @PostMapping("/deserialize")
    public void bad_case_6(@RequestBody String jsonInput, HttpServletResponse response) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        
        // Configuring mapper without proper type validation
        // ruleid: java-jackson-polymorphic-type-validator
        mapper.activateDefaultTyping(
            mapper.getPolymorphicTypeValidator(),
            ObjectMapper.DefaultTyping.NON_FINAL
        );
        
        Object obj = mapper.readValue(jsonInput, Object.class);
        response.getWriter().println("Processed object: " + obj);
    }

    public void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String json = request.getHeader("X-Json-Data");
        
        // Creating JsonMapper without proper type validation
        // ruleid: java-jackson-polymorphic-type-validator
        JsonMapper mapper = JsonMapper.builder()
            .activateDefaultTyping(JsonMapper.builder().getPolymorphicTypeValidator())
            .build();
        
        Object result = mapper.readValue(json, Object.class);
        response.getWriter().println("Result: " + result);
    }

    @RequestMapping("/convert")
    public void bad_case_8(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String jsonData = request.getParameter("data");
        
        // Using builder pattern without proper type validation
        // ruleid: java-jackson-polymorphic-type-validator
        ObjectMapper mapper = JsonMapper.builder()
            .activateDefaultTyping(
                JsonMapper.builder().getPolymorphicTypeValidator(),
                ObjectMapper.DefaultTyping.EVERYTHING
            )
            .build();
        
        Object obj = mapper.readValue(jsonData, Object.class);
        response.getWriter().println("Converted: " + obj);
    }

    public void bad_case_9(HttpServletRequest request, HttpServletResponse response) throws IOException {
        InputStream inputStream = request.getInputStream();
        
        ObjectMapper mapper = new ObjectMapper();
        // Using deprecated method with unsafe typing
        // ruleid: java-jackson-polymorphic-type-validator
        mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.USE_STATIC_TYPING);
        
        Object data = mapper.readValue(inputStream, Object.class);
        response.getWriter().println("Data: " + data);
    }

    @PostMapping("/process-json")
    public void bad_case_10(@RequestBody String json, HttpServletResponse response) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        
        // Enabling polymorphic deserialization without restrictions
        // ruleid: java-jackson-polymorphic-type-validator
        mapper.activateDefaultTyping(
            mapper.getPolymorphicTypeValidator(),
            ObjectMapper.DefaultTyping.JAVA_LANG_OBJECT
        );
        
        Map<String, Object> result = mapper.readValue(json, Map.class);
        response.getWriter().println("Processed: " + result);
    }

    public void bad_case_11(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String jsonData = request.getParameter("payload");
        
        // Creating mapper with unsafe default typing
        // ruleid: java-jackson-polymorphic-type-validator
        ObjectMapper mapper = JsonMapper.builder()
            .enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL)
            .build();
        
        Object obj = mapper.readValue(jsonData, Object.class);
        response.getWriter().println("Result: " + obj);
    }

    @RequestMapping("/api/parse")
    public void bad_case_12(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String json = request.getReader().lines().collect(Collectors.joining());
        
        // Using deprecated method with unsafe configuration
        // ruleid: java-jackson-polymorphic-type-validator
        ObjectMapper mapper = new ObjectMapper();
        mapper.enableDefaultTyping();
        
        Object result = mapper.readValue(json, Object.class);
        response.getWriter().println("Parsed: " + result);
    }

    public void bad_case_13(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String jsonInput = request.getParameter("input");
        
        // Using builder with unsafe default typing
        // ruleid: java-jackson-polymorphic-type-validator
        ObjectMapper mapper = JsonMapper.builder()
            .activateDefaultTyping(
                JsonMapper.builder().getPolymorphicTypeValidator(),
                ObjectMapper.DefaultTyping.NON_CONCRETE_AND_ARRAYS
            )
            .build();
        
        Object data = mapper.readValue(jsonInput, Object.class);
        response.getWriter().println("Data: " + data);
    }

    @PostMapping("/api/data")
    public void bad_case_14(@RequestBody String jsonData, HttpServletResponse response) throws IOException {
        // Using unsafe default typing with EVERYTHING setting
        // ruleid: java-jackson-polymorphic-type-validator
        ObjectMapper mapper = new ObjectMapper();
        mapper.activateDefaultTyping(
            mapper.getPolymorphicTypeValidator(),
            ObjectMapper.DefaultTyping.EVERYTHING
        );
        
        Object result = mapper.readValue(jsonData, Object.class);
        response.getWriter().println("Result: " + result);
    }

    public void bad_case_15(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String json = request.getParameter("data");
        
        // Using deprecated method without proper validation
        // ruleid: java-jackson-polymorphic-type-validator
        ObjectMapper mapper = new ObjectMapper();
        mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_CONCRETE_AND_ARRAYS);
        
        Object obj = mapper.readValue(json, Object.class);
        response.getWriter().println("Processed: " + obj);
    }

    // TRUE NEGATIVES (Secure Code)

    public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String json = request.getParameter("data");
        
        // Using a properly configured PolymorphicTypeValidator
        PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
            .allowIfBaseType(Animal.class)
            .build();
        
        // ok: java-jackson-polymorphic-type-validator
        ObjectMapper mapper = JsonMapper.builder()
            .polymorphicTypeValidator(ptv)
            .build();
        
        Animal animal = mapper.readValue(json, Animal.class);
        response.getWriter().println("Animal: " + animal.getName());
    }

    public void good_case_2(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String json = request.getReader().lines().collect(Collectors.joining());
        
        // Using specific class for deserialization instead of polymorphic types
        // ok: java-jackson-polymorphic-type-validator
        ObjectMapper mapper = new ObjectMapper();
        
        // No default typing enabled, using specific type
        Dog dog = mapper.readValue(json, Dog.class);
        response.getWriter().println("Dog: " + dog.getName() + ", Breed: " + dog.getBreed());
    }

    @PostMapping("/api/safe-animals")
    public void good_case_3(@RequestBody String jsonData, HttpServletResponse response) throws IOException {
        // Using BasicPolymorphicTypeValidator with proper restrictions
        PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
            .allowIfSubType("com.example.")
            .allowIfSubType(Animal.class)
            .build();
        
        // ok: java-jackson-polymorphic-type-validator
        ObjectMapper mapper = JsonMapper.builder()
            .activateDefaultTyping(ptv, ObjectMapper.DefaultTyping.NON_FINAL)
            .build();
        
        Animal animal = mapper.readValue(jsonData, Animal.class);
        response.getWriter().println("Processed animal: " + animal.getName());
    }

    @RequestMapping("/safe-process")
    public void good_case_4(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String json = request.getParameter("json");
        
        // Using a specific type without polymorphic deserialization
        // ok: java-jackson-polymorphic-type-validator
        ObjectMapper mapper = new ObjectMapper();
        
        // Disabling default typing explicitly
        mapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
        
        Map<String, String> data = mapper.readValue(json, Map.class);
        response.getWriter().println("Data: " + data);
    }

    public void good_case_5(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String jsonData = request.getParameter("data");
        
        // Using BasicPolymorphicTypeValidator with strict package validation
        PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
            .allowIfBaseType("com.example.models.")
            .allowIfSubType(Animal.class)
            .denyForExactBaseType(Object.class)
            .build();
        
        // ok: java-jackson-polymorphic-type-validator
        ObjectMapper mapper = JsonMapper.builder()
            .polymorphicTypeValidator(ptv)
            .build();
        
        Animal animal = mapper.readValue(jsonData, Animal.class);
        response.getWriter().println("Animal: " + animal.getName());
    }

    @PostMapping("/deserialize-safe")
    public void good_case_6(@RequestBody String jsonInput, HttpServletResponse response) throws IOException {
        // Using a specific class with type annotations instead of default typing
        // ok: java-jackson-polymorphic-type-validator
        ObjectMapper mapper = new ObjectMapper();
        
        // Using specific type with @JsonTypeInfo annotation
        AnimalWithTypeInfo animal = mapper.readValue(jsonInput, AnimalWithTypeInfo.class);
        response.getWriter().println("Animal: " + animal.getName());
    }

    public void good_case_7(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String json = request.getHeader("X-Json-Data");
        
        // Using strict validator that only allows specific packages
        PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
            .allowIfBaseType(Animal.class)
            .denyForExactBaseType(Object.class)
            .denyForExactBaseType(Throwable.class)
            .build();
        
        // ok: java-jackson-polymorphic-type-validator
        ObjectMapper mapper = JsonMapper.builder()
            .polymorphicTypeValidator(ptv)
            .build();
        
        Animal animal = mapper.readValue(json, Animal.class);
        response.getWriter().println("Animal: " + animal.getName());
    }

    @RequestMapping("/convert-safe")
    public void good_case_8(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String jsonData = request.getParameter("data");
        
        // Using specific type without polymorphic deserialization
        // ok: java-jackson-polymorphic-type-validator
        ObjectMapper mapper = new ObjectMapper();
        
        // No default typing, using specific class
        Cat cat = mapper.readValue(jsonData, Cat.class);
        response.getWriter().println("Cat: " + cat.getName() + ", Lives: " + cat.getLives());
    }

    public void good_case_9(HttpServletRequest request, HttpServletResponse response) throws IOException {
        InputStream inputStream = request.getInputStream();
        
        // Using properly configured validator with strict allowlist
        PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
            .allowIfBaseType(Animal.class)
            .allowIfSubType(Dog.class)
            .allowIfSubType(Cat.class)
            .build();
        
        // ok: java-jackson-polymorphic-type-validator
        ObjectMapper mapper = JsonMapper.builder()
            .activateDefaultTyping(ptv, ObjectMapper.DefaultTyping.NON_FINAL)
            .build();
        
        Animal animal = mapper.readValue(inputStream, Animal.class);
        response.getWriter().println("Animal: " + animal.getName());
    }

    @PostMapping("/process-json-safe")
    public void good_case_10(@RequestBody String json, HttpServletResponse response) throws IOException {
        // Using specific class mapping without polymorphic types
        // ok: java-jackson-polymorphic-type-validator
        ObjectMapper mapper = new ObjectMapper();
        
        // Using specific type without default typing
        HashMap<String, String> result = mapper.readValue(json, HashMap.class);
        response.getWriter().println("Processed: " + result);
    }

    public void good_case_11(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String jsonData = request.getParameter("payload");
        
        // Using properly configured validator with strict package validation
        PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
            .allowIfBaseType("com.example.")
            .allowIfSubType(Animal.class)
            .denyForExactBaseType(Object.class)
            .denyForExactBaseType(Throwable.class)
            .build();
        
        // ok: java-jackson-polymorphic-type-validator
        ObjectMapper mapper = JsonMapper.builder()
            .polymorphicTypeValidator(ptv)
            .build();
        
        Animal animal = mapper.readValue(jsonData, Animal.class);
        response.getWriter().println("Animal: " + animal.getName());
    }

    @RequestMapping("/api/parse-safe")
    public void good_case_12(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String json = request.getReader().lines().collect(Collectors.joining());
        
        // Using specific type without polymorphic deserialization
        // ok: java-jackson-polymorphic-type-validator
        ObjectMapper mapper = new ObjectMapper();
        
        // Explicitly disable default typing
        mapper.deactivateDefaultTyping();
        
        Map<String, Object> result = mapper.readValue(json, Map.class);
        response.getWriter().println("Parsed: " + result);
    }

    public void good_case_13(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String jsonInput = request.getParameter("input");
        
        // Using properly configured validator with strict allowlist
        PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
            .allowIfBaseType(Animal.class)
            .allowIfSubType(Dog.class)
            .allowIfSubType(Cat.class)
            .denyForExactBaseType(Object.class)
            .build();
        
        // ok: java-jackson-polymorphic-type-validator
        ObjectMapper mapper = JsonMapper.builder()
            .polymorphicTypeValidator(ptv)
            .build();
        
        Animal animal = mapper.readValue(jsonInput, Animal.class);
        response.getWriter().println("Animal: " + animal.getName());
    }

    @PostMapping("/api/data-safe")
    public void good_case_14(@RequestBody String jsonData, HttpServletResponse response) throws IOException {
        // Using specific class for deserialization
        // ok: java-jackson-polymorphic-type-validator
        ObjectMapper mapper = new ObjectMapper();
        
        // No default typing, using specific type
        Dog dog = mapper.readValue(jsonData, Dog.class);
        response.getWriter().println("Dog: " + dog.getName());
    }

    public void good_case_15(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String json = request.getParameter("data");
        
        // Using properly configured validator with strict package validation
        PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
            .allowIfBaseType(Animal.class)
            .denyForExactBaseType(Object.class)
            .denyForExactBaseType(Throwable.class)
            .build();
        
        // ok: java-jackson-polymorphic-type-validator
        ObjectMapper mapper = JsonMapper.builder()
            .activateDefaultTyping(ptv, ObjectMapper.DefaultTyping.NON_FINAL)
            .build();
        
        Animal animal = mapper.readValue(json, Animal.class);
        response.getWriter().println("Animal: " + animal.getName());
    }
}
// {/fact}