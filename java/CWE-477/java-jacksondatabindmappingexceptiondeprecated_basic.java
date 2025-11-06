import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.core.*;
import com.fasterxml.jackson.annotation.*;
import java.io.IOException;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;

public class JacksonMappingExceptionExamples {

    // True Positive Examples (Vulnerable/Deprecated Code)
    
// {fact rule=deprecated-method@v1.0 defects=1}
    public void bad_case_1() {
        ObjectMapper mapper = new ObjectMapper();
        DeserializationContext ctxt = null;
        JsonParser p = null;
        try {
            // ruleid: java-jacksondatabindmappingexceptiondeprecated
            throw ctxt.mappingException("Failed to deserialize object");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_2() {
        DeserializationContext context = null;
        String message = "Invalid JSON format";
        // ruleid: java-jacksondatabindmappingexceptiondeprecated
        JsonMappingException exception = context.mappingException(message);
        System.out.println(exception.getMessage());
    }
    
    public void bad_case_3() {
        class CustomDeserializer extends JsonDeserializer<Object> {
            @Override
            public Object deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                if (p.getCurrentToken() != JsonToken.VALUE_STRING) {
                    // ruleid: java-jacksondatabindmappingexceptiondeprecated
                    throw ctxt.mappingException("Expected string value");
                }
                return p.getText();
            }
        }
    }
    
    public void bad_case_4() {
        DeserializationContext ctxt = null;
        Class<?> targetType = String.class;
        // ruleid: java-jacksondatabindmappingexceptiondeprecated
        JsonMappingException exception = ctxt.mappingException(targetType);
        throw new RuntimeException(exception);
    }
    
    public void bad_case_5() {
        class DateDeserializer extends JsonDeserializer<java.util.Date> {
            @Override
            public java.util.Date deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                try {
                    return new java.util.Date(Long.parseLong(p.getText()));
                } catch (NumberFormatException e) {
                    // ruleid: java-jacksondatabindmappingexceptiondeprecated
                    throw ctxt.mappingException("Invalid date format");
                }
            }
        }
    }
    
    public void bad_case_6() {
        DeserializationContext ctxt = null;
        JsonParser parser = null;
        String fieldName = "username";
        
        try {
            // ruleid: java-jacksondatabindmappingexceptiondeprecated
            JsonMappingException ex = ctxt.mappingException("Invalid field: " + fieldName);
            throw ex;
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_7() {
        class CustomBeanDeserializer extends BeanDeserializer {
            public CustomBeanDeserializer(BeanDeserializerBase src) {
                super(src);
            }
            
            @Override
            public Object deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                if (p.getCurrentToken() == JsonToken.START_OBJECT) {
                    return super.deserialize(p, ctxt);
                }
                // ruleid: java-jacksondatabindmappingexceptiondeprecated
                throw ctxt.mappingException("Expected object start");
            }
        }
    }
    
    public void bad_case_8() {
        class EnumDeserializer extends JsonDeserializer<Enum<?>> {
            @Override
            public Enum<?> deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                String value = p.getText();
                if (value == null || value.isEmpty()) {
                    // ruleid: java-jacksondatabindmappingexceptiondeprecated
                    throw ctxt.mappingException("Empty enum value");
                }
                return Enum.valueOf(Enum.class, value);
            }
        }
    }
    
    public void bad_case_9() {
        DeserializationContext ctxt = null;
        Class<?> targetClass = Integer.class;
        String message = "Cannot convert to " + targetClass.getSimpleName();
        
        try {
            // ruleid: java-jacksondatabindmappingexceptiondeprecated
            throw ctxt.mappingException(targetClass, message);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_10() {
        class MapDeserializer extends JsonDeserializer<Map<String, Object>> {
            @Override
            public Map<String, Object> deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                if (p.getCurrentToken() != JsonToken.START_OBJECT) {
                    // ruleid: java-jacksondatabindmappingexceptiondeprecated
                    throw ctxt.mappingException(Map.class);
                }
                return new HashMap<>();
            }
        }
    }
    
    public void bad_case_11() {
        DeserializationContext ctxt = null;
        JsonParser p = null;
        
        try {
            Object obj = deserializeValue(p, ctxt);
            if (obj == null) {
                // ruleid: java-jacksondatabindmappingexceptiondeprecated
                throw ctxt.mappingException("Null object returned");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private Object deserializeValue(JsonParser p, DeserializationContext ctxt) {
        return null;
    }
    
    public void bad_case_12() {
        class ListDeserializer extends JsonDeserializer<List<String>> {
            @Override
            public List<String> deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                if (p.getCurrentToken() != JsonToken.START_ARRAY) {
                    // ruleid: java-jacksondatabindmappingexceptiondeprecated
                    throw ctxt.mappingException("Expected array start");
                }
                return new ArrayList<>();
            }
        }
    }
    
    public void bad_case_13() {
        DeserializationContext ctxt = null;
        String message = "Invalid configuration";
        Class<?> targetType = Double.class;
        
        try {
            // ruleid: java-jacksondatabindmappingexceptiondeprecated
            JsonMappingException exception = ctxt.mappingException(targetType, message);
            throw exception;
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_14() {
        class BooleanDeserializer extends JsonDeserializer<Boolean> {
            @Override
            public Boolean deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                String text = p.getText();
                if ("true".equalsIgnoreCase(text)) {
                    return Boolean.TRUE;
                } else if ("false".equalsIgnoreCase(text)) {
                    return Boolean.FALSE;
                }
                // ruleid: java-jacksondatabindmappingexceptiondeprecated
                throw ctxt.mappingException(Boolean.class, "Invalid boolean value: " + text);
            }
        }
    }
    
    public void bad_case_15() {
        DeserializationContext ctxt = null;
        JsonParser p = null;
        
        try {
            if (p.getCurrentToken() == JsonToken.VALUE_NULL) {
                // ruleid: java-jacksondatabindmappingexceptiondeprecated
                throw ctxt.mappingException("Null values not allowed");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // True Negative Examples (Safe/Updated Code)
    
    public void good_case_1() {
        ObjectMapper mapper = new ObjectMapper();
        DeserializationContext ctxt = null;
        JsonParser p = null;
        try {
            // ok: java-jacksondatabindmappingexceptiondeprecated
            throw ctxt.handleUnexpectedToken(Object.class, p);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_2() {
        DeserializationContext context = null;
        JsonParser p = null;
        String message = "Invalid JSON format";
        // ok: java-jacksondatabindmappingexceptiondeprecated
        JsonMappingException exception = JsonMappingException.from(p, message);
        System.out.println(exception.getMessage());
    }
    
    public void good_case_3() {
        class CustomDeserializer extends JsonDeserializer<Object> {
            @Override
            public Object deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                if (p.getCurrentToken() != JsonToken.VALUE_STRING) {
                    // ok: java-jacksondatabindmappingexceptiondeprecated
                    throw ctxt.handleUnexpectedToken(String.class, p);
                }
                return p.getText();
            }
        }
    }
    
    public void good_case_4() {
        DeserializationContext ctxt = null;
        JsonParser p = null;
        Class<?> targetType = String.class;
        // ok: java-jacksondatabindmappingexceptiondeprecated
        JsonMappingException exception = ctxt.handleUnexpectedToken(targetType, p);
        throw new RuntimeException(exception);
    }
    
    public void good_case_5() {
        class DateDeserializer extends JsonDeserializer<java.util.Date> {
            @Override
            public java.util.Date deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                try {
                    return new java.util.Date(Long.parseLong(p.getText()));
                } catch (NumberFormatException e) {
                    // ok: java-jacksondatabindmappingexceptiondeprecated
                    throw JsonMappingException.from(p, "Invalid date format", e);
                }
            }
        }
    }
    
    public void good_case_6() {
        DeserializationContext ctxt = null;
        JsonParser parser = null;
        String fieldName = "username";
        
        try {
            // ok: java-jacksondatabindmappingexceptiondeprecated
            JsonMappingException ex = JsonMappingException.from(parser, "Invalid field: " + fieldName);
            throw ex;
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_7() {
        class CustomBeanDeserializer extends BeanDeserializer {
            public CustomBeanDeserializer(BeanDeserializerBase src) {
                super(src);
            }
            
            @Override
            public Object deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                if (p.getCurrentToken() == JsonToken.START_OBJECT) {
                    return super.deserialize(p, ctxt);
                }
                // ok: java-jacksondatabindmappingexceptiondeprecated
                throw ctxt.handleUnexpectedToken(Object.class, p);
            }
        }
    }
    
    public void good_case_8() {
        class EnumDeserializer extends JsonDeserializer<Enum<?>> {
            @Override
            public Enum<?> deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                String value = p.getText();
                if (value == null || value.isEmpty()) {
                    // ok: java-jacksondatabindmappingexceptiondeprecated
                    throw JsonMappingException.from(p, "Empty enum value");
                }
                return Enum.valueOf(Enum.class, value);
            }
        }
    }
    
    public void good_case_9() {
        DeserializationContext ctxt = null;
        JsonParser p = null;
        Class<?> targetClass = Integer.class;
        String message = "Cannot convert to " + targetClass.getSimpleName();
        
        try {
            // ok: java-jacksondatabindmappingexceptiondeprecated
            throw ctxt.handleUnexpectedToken(targetClass, p.getCurrentToken(), p, message);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_10() {
        class MapDeserializer extends JsonDeserializer<Map<String, Object>> {
            @Override
            public Map<String, Object> deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                if (p.getCurrentToken() != JsonToken.START_OBJECT) {
                    // ok: java-jacksondatabindmappingexceptiondeprecated
                    throw ctxt.handleUnexpectedToken(Map.class, p);
                }
                return new HashMap<>();
            }
        }
    }
    
    public void good_case_11() {
        DeserializationContext ctxt = null;
        JsonParser p = null;
        
        try {
            Object obj = deserializeValue(p, ctxt);
            if (obj == null) {
                // ok: java-jacksondatabindmappingexceptiondeprecated
                throw JsonMappingException.from(p, "Null object returned");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_12() {
        class ListDeserializer extends JsonDeserializer<List<String>> {
            @Override
            public List<String> deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                if (p.getCurrentToken() != JsonToken.START_ARRAY) {
                    // ok: java-jacksondatabindmappingexceptiondeprecated
                    throw ctxt.handleUnexpectedToken(List.class, p);
                }
                return new ArrayList<>();
            }
        }
    }
    
    public void good_case_13() {
        DeserializationContext ctxt = null;
        JsonParser p = null;
        String message = "Invalid configuration";
        Class<?> targetType = Double.class;
        
        try {
            // ok: java-jacksondatabindmappingexceptiondeprecated
            JsonMappingException exception = ctxt.handleUnexpectedToken(targetType, p.getCurrentToken(), p, message);
            throw exception;
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_14() {
        class BooleanDeserializer extends JsonDeserializer<Boolean> {
            @Override
            public Boolean deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                String text = p.getText();
                if ("true".equalsIgnoreCase(text)) {
                    return Boolean.TRUE;
                } else if ("false".equalsIgnoreCase(text)) {
                    return Boolean.FALSE;
                }
                // ok: java-jacksondatabindmappingexceptiondeprecated
                throw ctxt.handleWeirdStringValue(Boolean.class, text, "Invalid boolean value");
            }
        }
    }
    
    public void good_case_15() {
        DeserializationContext ctxt = null;
        JsonParser p = null;
        
        try {
            if (p.getCurrentToken() == JsonToken.VALUE_NULL) {
                // ok: java-jacksondatabindmappingexceptiondeprecated
                throw ctxt.handleUnexpectedToken(Object.class, JsonToken.VALUE_NULL, p, "Null values not allowed");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
// {/fact}