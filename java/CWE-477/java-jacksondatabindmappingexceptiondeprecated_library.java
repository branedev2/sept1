import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.core.*;
import com.fasterxml.jackson.annotation.*;
import com.fasterxml.jackson.databind.deser.*;
import com.fasterxml.jackson.databind.ser.*;
import com.fasterxml.jackson.databind.exc.*;
import com.fasterxml.jackson.databind.module.*;
import com.fasterxml.jackson.databind.node.*;
import com.fasterxml.jackson.databind.type.*;
import com.fasterxml.jackson.databind.util.*;
import com.fasterxml.jackson.databind.jsontype.*;
import com.fasterxml.jackson.databind.cfg.*;
import com.fasterxml.jackson.databind.introspect.*;
import com.fasterxml.jackson.databind.jsonFormatVisitors.*;
import com.fasterxml.jackson.databind.jsonschema.*;
import javax.servlet.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.*;
import org.apache.http.client.methods.*;
import org.apache.http.impl.client.*;
import org.apache.http.HttpResponse;
import java.io.*;
import java.util.*;
import org.springframework.boot.web.servlet.error.*;
import org.springframework.stereotype.*;
import org.springframework.web.*;
import org.springframework.web.context.request.*;
import org.springframework.boot.autoconfigure.web.*;
import org.springframework.boot.web.servlet.*;
import org.springframework.web.servlet.*;
import org.springframework.web.servlet.mvc.*;
import org.springframework.web.servlet.handler.*;
import org.springframework.web.servlet.config.annotation.*;
import org.springframework.web.servlet.view.*;
import org.springframework.web.servlet.view.json.*;
import org.springframework.web.servlet.view.xml.*;
import org.springframework.web.servlet.view.freemarker.*;
import org.springframework.web.servlet.view.velocity.*;
import org.springframework.web.servlet.view.tiles3.*;
import org.springframework.web.servlet.view.document.*;
import org.springframework.web.servlet.view.feed.*;
import org.springframework.web.servlet.view.groovy.*;
import org.springframework.web.servlet.view.script.*;
import org.springframework.web.servlet.view.xslt.*;
import org.springframework.web.servlet.view.jasperreports.*;
import org.springframework.web.servlet.view.mustache.*;
import org.springframework.web.servlet.view.thymeleaf.*;
import org.springframework.web.servlet.view.tiles2.*;
import org.springframework.web.servlet.view.velocity.*;
import org.springframework.web.servlet.view.xml.*;
import org.springframework.web.servlet.view.json.*;

// Security Issue: Using deprecated mappingException() method in Jackson Databind

// True Positive Examples (Vulnerable/Insecure Code)
class BadCases {
    // Basic Jackson Databind deserializer with deprecated mappingException
// {fact rule=deprecated-method@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) {
        try {
            String json = request.getParameter("data");
            ObjectMapper mapper = new ObjectMapper();
            JsonDeserializer<Object> deserializer = new JsonDeserializer<Object>() {
                @Override
                public Object deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                    if (p.getCurrentToken() != JsonToken.VALUE_STRING) {
                        // ruleid: java-jacksondatabindmappingexceptiondeprecated
                        throw ctxt.mappingException("Expected string value");
                    }
                    return p.getText();
                }
            };
            SimpleModule module = new SimpleModule();
            module.addDeserializer(Object.class, deserializer);
            mapper.registerModule(module);
            mapper.readValue(json, Object.class);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Custom deserializer with deprecated mappingException in Spring REST controller
    @RestController
    public class bad_case_2 {
        @PostMapping("/process")
        public ResponseEntity<String> processData(@RequestBody String requestBody) {
            try {
                ObjectMapper mapper = new ObjectMapper();
                JsonDeserializer<Map<String, Object>> deserializer = new JsonDeserializer<Map<String, Object>>() {
                    @Override
                    public Map<String, Object> deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                        if (p.getCurrentToken() != JsonToken.START_OBJECT) {
                            // ruleid: java-jacksondatabindmappingexceptiondeprecated
                            throw ctxt.mappingException(Map.class);
                        }
                        return mapper.readValue(p, new TypeReference<Map<String, Object>>() {});
                    }
                };
                SimpleModule module = new SimpleModule();
                module.addDeserializer(Map.class, deserializer);
                mapper.registerModule(module);
                mapper.readValue(requestBody, Map.class);
                return ResponseEntity.ok("Success");
            } catch (Exception e) {
                return ResponseEntity.badRequest().body(e.getMessage());
            }
        }
    }

    // Jackson deserializer with mappingException in custom error handler
    @ControllerAdvice
    public class bad_case_3 implements ErrorController {
        private final ObjectMapper mapper = new ObjectMapper();
        
        @ExceptionHandler(Exception.class)
        public ResponseEntity<String> handleException(Exception ex, WebRequest request) {
            try {
                String requestBody = ((ServletWebRequest) request).getRequest().getReader().lines()
                        .collect(java.util.stream.Collectors.joining());
                
                JsonDeserializer<ErrorResponse> deserializer = new JsonDeserializer<ErrorResponse>() {
                    @Override
                    public ErrorResponse deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                        if (p.getCurrentToken() != JsonToken.START_OBJECT) {
                            // ruleid: java-jacksondatabindmappingexceptiondeprecated
                            throw ctxt.mappingException("Expected object for error response");
                        }
                        return new ErrorResponse("Error processing request");
                    }
                };
                
                SimpleModule module = new SimpleModule();
                module.addDeserializer(ErrorResponse.class, deserializer);
                mapper.registerModule(module);
                
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error");
            } catch (Exception e) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error");
            }
        }
        
        private static class ErrorResponse {
            private String message;
            public ErrorResponse(String message) {
                this.message = message;
            }
        }
    }

    // Custom Jackson module with deprecated mappingException in Apache HTTP client
    public void bad_case_4() {
        try {
            CloseableHttpClient httpClient = HttpClients.createDefault();
            HttpGet request = new HttpGet("https://api.example.com/data");
            HttpResponse response = httpClient.execute(request);
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
            String json = reader.lines().collect(java.util.stream.Collectors.joining());
            
            ObjectMapper mapper = new ObjectMapper();
            JsonDeserializer<ApiResponse> deserializer = new JsonDeserializer<ApiResponse>() {
                @Override
                public ApiResponse deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                    if (p.getCurrentToken() != JsonToken.START_OBJECT) {
                        // ruleid: java-jacksondatabindmappingexceptiondeprecated
                        throw ctxt.mappingException("Invalid API response format");
                    }
                    return mapper.readValue(p, ApiResponse.class);
                }
            };
            
            SimpleModule module = new SimpleModule();
            module.addDeserializer(ApiResponse.class, deserializer);
            mapper.registerModule(module);
            mapper.readValue(json, ApiResponse.class);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private static class ApiResponse {
        private String status;
        private Object data;
    }

    // Spring MVC controller with deprecated mappingException in custom deserializer
    @Controller
    public class bad_case_5 {
        @RequestMapping("/data/{id}")
        public ModelAndView getData(@PathVariable String id, HttpServletRequest request) {
            try {
                String payload = request.getParameter("payload");
                ObjectMapper mapper = new ObjectMapper();
                
                JsonDeserializer<DataPayload> deserializer = new JsonDeserializer<DataPayload>() {
                    @Override
                    public DataPayload deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                        if (p.getCurrentToken() != JsonToken.START_OBJECT) {
                            // ruleid: java-jacksondatabindmappingexceptiondeprecated
                            throw ctxt.mappingException(DataPayload.class, p.getCurrentToken());
                        }
                        return mapper.readValue(p, DataPayload.class);
                    }
                };
                
                SimpleModule module = new SimpleModule();
                module.addDeserializer(DataPayload.class, deserializer);
                mapper.registerModule(module);
                
                DataPayload data = mapper.readValue(payload, DataPayload.class);
                ModelAndView mav = new ModelAndView("dataView");
                mav.addObject("data", data);
                return mav;
            } catch (Exception e) {
                return new ModelAndView("error");
            }
        }
    }
    
    private static class DataPayload {
        private String name;
        private String value;
    }

    // Custom Jackson deserializer with mappingException in Spring WebFlux
    public void bad_case_6(HttpServletRequest request) {
        try {
            String json = request.getParameter("data");
            ObjectMapper mapper = new ObjectMapper();
            
            JsonDeserializer<WebFluxData> deserializer = new JsonDeserializer<WebFluxData>() {
                @Override
                public WebFluxData deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                    if (p.getCurrentToken() != JsonToken.START_OBJECT) {
                        // ruleid: java-jacksondatabindmappingexceptiondeprecated
                        throw ctxt.mappingException("Expected object start for WebFlux data");
                    }
                    return new WebFluxData();
                }
            };
            
            SimpleModule module = new SimpleModule();
            module.addDeserializer(WebFluxData.class, deserializer);
            mapper.registerModule(module);
            
            mapper.readValue(json, WebFluxData.class);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private static class WebFluxData {
        private String route;
        private Map<String, Object> parameters;
    }

    // Spring Boot error handler with deprecated mappingException
    @Component
    public class bad_case_7 implements ErrorAttributes {
        private final ObjectMapper mapper = new ObjectMapper();
        
        @Override
        public Map<String, Object> getErrorAttributes(WebRequest webRequest, boolean includeStackTrace) {
            try {
                String requestBody = ((ServletWebRequest) webRequest).getRequest().getReader().lines()
                        .collect(java.util.stream.Collectors.joining());
                
                JsonDeserializer<Map<String, Object>> deserializer = new JsonDeserializer<Map<String, Object>>() {
                    @Override
                    public Map<String, Object> deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                        if (p.getCurrentToken() != JsonToken.START_OBJECT) {
                            // ruleid: java-jacksondatabindmappingexceptiondeprecated
                            throw ctxt.mappingException("Expected object for error attributes");
                        }
                        return mapper.readValue(p, new TypeReference<Map<String, Object>>() {});
                    }
                };
                
                SimpleModule module = new SimpleModule();
                module.addDeserializer(Map.class, deserializer);
                mapper.registerModule(module);
                
                return new HashMap<>();
            } catch (Exception e) {
                return new HashMap<>();
            }
        }
    }

    // Custom Jackson deserializer with mappingException in Spring MVC interceptor
    public class bad_case_8 extends HandlerInterceptorAdapter {
        private final ObjectMapper mapper = new ObjectMapper();
        
        @Override
        public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
            try {
                String json = request.getParameter("config");
                
                JsonDeserializer<InterceptorConfig> deserializer = new JsonDeserializer<InterceptorConfig>() {
                    @Override
                    public InterceptorConfig deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                        if (p.getCurrentToken() != JsonToken.START_OBJECT) {
                            // ruleid: java-jacksondatabindmappingexceptiondeprecated
                            throw ctxt.mappingException(InterceptorConfig.class);
                        }
                        return new InterceptorConfig();
                    }
                };
                
                SimpleModule module = new SimpleModule();
                module.addDeserializer(InterceptorConfig.class, deserializer);
                mapper.registerModule(module);
                
                mapper.readValue(json, InterceptorConfig.class);
                return true;
            } catch (Exception e) {
                return false;
            }
        }
    }
    
    private static class InterceptorConfig {
        private List<String> excludePaths;
        private boolean enabled;
    }

    // Spring view resolver with deprecated mappingException
    @Configuration
    public class bad_case_9 implements WebMvcConfigurer {
        @Bean
        public ViewResolver jsonViewResolver() {
            return new AbstractCachingViewResolver() {
                private final ObjectMapper mapper = new ObjectMapper();
                
                @Override
                protected View loadView(String viewName, Locale locale) throws Exception {
                    JsonDeserializer<ViewConfig> deserializer = new JsonDeserializer<ViewConfig>() {
                        @Override
                        public ViewConfig deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                            if (p.getCurrentToken() != JsonToken.START_OBJECT) {
                                // ruleid: java-jacksondatabindmappingexceptiondeprecated
                                throw ctxt.mappingException("Expected object for view config");
                            }
                            return new ViewConfig();
                        }
                    };
                    
                    SimpleModule module = new SimpleModule();
                    module.addDeserializer(ViewConfig.class, deserializer);
                    mapper.registerModule(module);
                    
                    return new MappingJackson2JsonView();
                }
            };
        }
    }
    
    private static class ViewConfig {
        private String template;
        private Map<String, Object> attributes;
    }

    // Spring Boot filter with deprecated mappingException
    @Component
    public class bad_case_10 implements Filter {
        private final ObjectMapper mapper = new ObjectMapper();
        
        @Override
        public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
                throws IOException, ServletException {
            try {
                String json = request.getParameter("filterConfig");
                
                JsonDeserializer<FilterConfig> deserializer = new JsonDeserializer<FilterConfig>() {
                    @Override
                    public FilterConfig deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                        if (p.getCurrentToken() != JsonToken.START_OBJECT) {
                            // ruleid: java-jacksondatabindmappingexceptiondeprecated
                            throw ctxt.mappingException("Expected object for filter config");
                        }
                        return new FilterConfig();
                    }
                };
                
                SimpleModule module = new SimpleModule();
                module.addDeserializer(FilterConfig.class, deserializer);
                mapper.registerModule(module);
                
                mapper.readValue(json, FilterConfig.class);
                chain.doFilter(request, response);
            } catch (Exception e) {
                ((HttpServletResponse) response).sendError(HttpServletResponse.SC_BAD_REQUEST);
            }
        }
    }
    
    private static class FilterConfig {
        private List<String> allowedPaths;
        private List<String> blockedIps;
    }

    // Spring exception handler with deprecated mappingException
    @ControllerAdvice
    public class bad_case_11 {
        private final ObjectMapper mapper = new ObjectMapper();
        
        @ExceptionHandler(Exception.class)
        public ResponseEntity<String> handleException(Exception ex, HttpServletRequest request) {
            try {
                String json = request.getParameter("errorFormat");
                
                JsonDeserializer<ErrorFormat> deserializer = new JsonDeserializer<ErrorFormat>() {
                    @Override
                    public ErrorFormat deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                        if (p.getCurrentToken() != JsonToken.START_OBJECT) {
                            // ruleid: java-jacksondatabindmappingexceptiondeprecated
                            throw ctxt.mappingException("Expected object for error format");
                        }
                        return new ErrorFormat();
                    }
                };
                
                SimpleModule module = new SimpleModule();
                module.addDeserializer(ErrorFormat.class, deserializer);
                mapper.registerModule(module);
                
                mapper.readValue(json, ErrorFormat.class);
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error");
            } catch (Exception e) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error");
            }
        }
    }
    
    private static class ErrorFormat {
        private boolean includeStackTrace;
        private String format;
    }

    // Spring MVC argument resolver with deprecated mappingException
    public class bad_case_12 implements HandlerMethodArgumentResolver {
        private final ObjectMapper mapper = new ObjectMapper();
        
        @Override
        public boolean supportsParameter(MethodParameter parameter) {
            return true;
        }
        
        @Override
        public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer,
                NativeWebRequest webRequest, WebDataBinderFactory binderFactory) throws Exception {
            String json = webRequest.getParameter("arg");
            
            JsonDeserializer<CustomArgument> deserializer = new JsonDeserializer<CustomArgument>() {
                @Override
                public CustomArgument deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                    if (p.getCurrentToken() != JsonToken.START_OBJECT) {
                        // ruleid: java-jacksondatabindmappingexceptiondeprecated
                        throw ctxt.mappingException("Expected object for custom argument");
                    }
                    return new CustomArgument();
                }
            };
            
            SimpleModule module = new SimpleModule();
            module.addDeserializer(CustomArgument.class, deserializer);
            mapper.registerModule(module);
            
            return mapper.readValue(json, CustomArgument.class);
        }
    }
    
    private static class CustomArgument {
        private String type;
        private Object value;
    }

    // Spring MVC message converter with deprecated mappingException
    public class bad_case_13 extends AbstractHttpMessageConverter<CustomMessage> {
        private final ObjectMapper mapper = new ObjectMapper();
        
        @Override
        protected boolean supports(Class<?> clazz) {
            return CustomMessage.class.isAssignableFrom(clazz);
        }
        
        @Override
        protected CustomMessage readInternal(Class<? extends CustomMessage> clazz, HttpInputMessage inputMessage)
                throws IOException, HttpMessageNotReadableException {
            JsonDeserializer<CustomMessage> deserializer = new JsonDeserializer<CustomMessage>() {
                @Override
                public CustomMessage deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                    if (p.getCurrentToken() != JsonToken.START_OBJECT) {
                        // ruleid: java-jacksondatabindmappingexceptiondeprecated
                        throw ctxt.mappingException("Expected object for custom message");
                    }
                    return new CustomMessage();
                }
            };
            
            SimpleModule module = new SimpleModule();
            module.addDeserializer(CustomMessage.class, deserializer);
            mapper.registerModule(module);
            
            return mapper.readValue(inputMessage.getBody(), CustomMessage.class);
        }
        
        @Override
        protected void writeInternal(CustomMessage t, HttpOutputMessage outputMessage)
                throws IOException, HttpMessageNotWritableException {
            mapper.writeValue(outputMessage.getBody(), t);
        }
    }
    
    private static class CustomMessage {
        private String content;
        private String sender;
    }

    // Spring WebSocket handler with deprecated mappingException
    public class bad_case_14 {
        public void handleWebSocketMessage(String message, HttpServletRequest request) {
            try {
                ObjectMapper mapper = new ObjectMapper();
                
                JsonDeserializer<WebSocketMessage> deserializer = new JsonDeserializer<WebSocketMessage>() {
                    @Override
                    public WebSocketMessage deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                        if (p.getCurrentToken() != JsonToken.START_OBJECT) {
                            // ruleid: java-jacksondatabindmappingexceptiondeprecated
                            throw ctxt.mappingException("Expected object for WebSocket message");
                        }
                        return new WebSocketMessage();
                    }
                };
                
                SimpleModule module = new SimpleModule();
                module.addDeserializer(WebSocketMessage.class, deserializer);
                mapper.registerModule(module);
                
                mapper.readValue(message, WebSocketMessage.class);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
    
    private static class WebSocketMessage {
        private String type;
        private Object payload;
    }

    // Spring REST template with deprecated mappingException
    public class bad_case_15 {
        public void processRestResponse(HttpServletRequest request) {
            try {
                String json = request.getParameter("response");
                ObjectMapper mapper = new ObjectMapper();
                
                JsonDeserializer<RestResponse> deserializer = new JsonDeserializer<RestResponse>() {
                    @Override
                    public RestResponse deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                        if (p.getCurrentToken() != JsonToken.START_OBJECT) {
                            // ruleid: java-jacksondatabindmappingexceptiondeprecated
                            throw ctxt.mappingException("Expected object for REST response");
                        }
                        return new RestResponse();
                    }
                };
                
                SimpleModule module = new SimpleModule();
                module.addDeserializer(RestResponse.class, deserializer);
                mapper.registerModule(module);
                
                mapper.readValue(json, RestResponse.class);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
    
    private static class RestResponse {
        private int status;
        private Object body;
    }
}
// {/fact}

// True Negative Examples (Safe/Secure Code)
class GoodCases {
    // Basic Jackson Databind deserializer with non-deprecated method
// {fact rule=deprecated-method@v1.0 defects=0}
    public void good_case_1(HttpServletRequest request) {
        try {
            String json = request.getParameter("data");
            ObjectMapper mapper = new ObjectMapper();
            JsonDeserializer<Object> deserializer = new JsonDeserializer<Object>() {
                @Override
                public Object deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                    if (p.getCurrentToken() != JsonToken.VALUE_STRING) {
                        // ok: java-jacksondatabindmappingexceptiondeprecated
                        throw MismatchedInputException.from(p, Object.class, "Expected string value");
                    }
                    return p.getText();
                }
            };
            SimpleModule module = new SimpleModule();
            module.addDeserializer(Object.class, deserializer);
            mapper.registerModule(module);
            mapper.readValue(json, Object.class);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Custom deserializer with non-deprecated method in Spring REST controller
    @RestController
    public class good_case_2 {
        @PostMapping("/process")
        public ResponseEntity<String> processData(@RequestBody String requestBody) {
            try {
                ObjectMapper mapper = new ObjectMapper();
                JsonDeserializer<Map<String, Object>> deserializer = new JsonDeserializer<Map<String, Object>>() {
                    @Override
                    public Map<String, Object> deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                        if (p.getCurrentToken() != JsonToken.START_OBJECT) {
                            // ok: java-jacksondatabindmappingexceptiondeprecated
                            throw MismatchedInputException.from(p, Map.class, "Expected object start");
                        }
                        return mapper.readValue(p, new TypeReference<Map<String, Object>>() {});
                    }
                };
                SimpleModule module = new SimpleModule();
                module.addDeserializer(Map.class, deserializer);
                mapper.registerModule(module);
                mapper.readValue(requestBody, Map.class);
                return ResponseEntity.ok("Success");
            } catch (Exception e) {
                return ResponseEntity.badRequest().body(e.getMessage());
            }
        }
    }

    // Jackson deserializer with non-deprecated method in custom error handler
    @ControllerAdvice
    public class good_case_3 implements ErrorController {
        private final ObjectMapper mapper = new ObjectMapper();
        
        @ExceptionHandler(Exception.class)
        public ResponseEntity<String> handleException(Exception ex, WebRequest request) {
            try {
                String requestBody = ((ServletWebRequest) request).getRequest().getReader().lines()
                        .collect(java.util.stream.Collectors.joining());
                
                JsonDeserializer<ErrorResponse> deserializer = new JsonDeserializer<ErrorResponse>() {
                    @Override
                    public ErrorResponse deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                        if (p.getCurrentToken() != JsonToken.START_OBJECT) {
                            // ok: java-jacksondatabindmappingexceptiondeprecated
                            throw InvalidFormatException.from(p, "Expected object for error response", p.getCurrentValue(), ErrorResponse.class);
                        }
                        return new ErrorResponse("Error processing request");
                    }
                };
                
                SimpleModule module = new SimpleModule();
                module.addDeserializer(ErrorResponse.class, deserializer);
                mapper.registerModule(module);
                
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error");
            } catch (Exception e) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error");
            }
        }
        
        private static class ErrorResponse {
            private String message;
            public ErrorResponse(String message) {
                this.message = message;
            }
        }
    }

    // Custom Jackson module with non-deprecated method in Apache HTTP client
    public void good_case_4() {
        try {
            CloseableHttpClient httpClient = HttpClients.createDefault();
            HttpGet request = new HttpGet("https://api.example.com/data");
            HttpResponse response = httpClient.execute(request);
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
            String json = reader.lines().collect(java.util.stream.Collectors.joining());
            
            ObjectMapper mapper = new ObjectMapper();
            JsonDeserializer<ApiResponse> deserializer = new JsonDeserializer<ApiResponse>() {
                @Override
                public ApiResponse deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                    if (p.getCurrentToken() != JsonToken.START_OBJECT) {
                        // ok: java-jacksondatabindmappingexceptiondeprecated
                        throw JsonMappingException.from(p, "Invalid API response format");
                    }
                    return mapper.readValue(p, ApiResponse.class);
                }
            };
            
            SimpleModule module = new SimpleModule();
            module.addDeserializer(ApiResponse.class, deserializer);
            mapper.registerModule(module);
            mapper.readValue(json, ApiResponse.class);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private static class ApiResponse {
        private String status;
        private Object data;
    }

    // Spring MVC controller with non-deprecated method in custom deserializer
    @Controller
    public class good_case_5 {
        @RequestMapping("/data/{id}")
        public ModelAndView getData(@PathVariable String id, HttpServletRequest request) {
            try {
                String payload = request.getParameter("payload");
                ObjectMapper mapper = new ObjectMapper();
                
                JsonDeserializer<DataPayload> deserializer = new JsonDeserializer<DataPayload>() {
                    @Override
                    public DataPayload deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                        if (p.getCurrentToken() != JsonToken.START_OBJECT) {
                            // ok: java-jacksondatabindmappingexceptiondeprecated
                            throw MismatchedInputException.from(p, DataPayload.class, "Expected object start");
                        }
                        return mapper.readValue(p, DataPayload.class);
                    }
                };
                
                SimpleModule module = new SimpleModule();
                module.addDeserializer(DataPayload.class, deserializer);
                mapper.registerModule(module);
                
                DataPayload data = mapper.readValue(payload, DataPayload.class);
                ModelAndView mav = new ModelAndView("dataView");
                mav.addObject("data", data);
                return mav;
            } catch (Exception e) {
                return new ModelAndView("error");
            }
        }
    }
    
    private static class DataPayload {
        private String name;
        private String value;
    }

    // Custom Jackson deserializer with non-deprecated method in Spring WebFlux
    public void good_case_6(HttpServletRequest request) {
        try {
            String json = request.getParameter("data");
            ObjectMapper mapper = new ObjectMapper();
            
            JsonDeserializer<WebFluxData> deserializer = new JsonDeserializer<WebFluxData>() {
                @Override
                public WebFluxData deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                    if (p.getCurrentToken() != JsonToken.START_OBJECT) {
                        // ok: java-jacksondatabindmappingexceptiondeprecated
                        throw JsonMappingException.from(p, "Expected object start for WebFlux data");
                    }
                    return new WebFluxData();
                }
            };
            
            SimpleModule module = new SimpleModule();
            module.addDeserializer(WebFluxData.class, deserializer);
            mapper.registerModule(module);
            
            mapper.readValue(json, WebFluxData.class);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private static class WebFluxData {
        private String route;
        private Map<String, Object> parameters;
    }

    // Spring Boot error handler with non-deprecated method
    @Component
    public class good_case_7 implements ErrorAttributes {
        private final ObjectMapper mapper = new ObjectMapper();
        
        @Override
        public Map<String, Object> getErrorAttributes(WebRequest webRequest, boolean includeStackTrace) {
            try {
                String requestBody = ((ServletWebRequest) webRequest).getRequest().getReader().lines()
                        .collect(java.util.stream.Collectors.joining());
                
                JsonDeserializer<Map<String, Object>> deserializer = new JsonDeserializer<Map<String, Object>>() {
                    @Override
                    public Map<String, Object> deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                        if (p.getCurrentToken() != JsonToken.START_OBJECT) {
                            // ok: java-jacksondatabindmappingexceptiondeprecated
                            throw InvalidFormatException.from(p, "Expected object for error attributes", p.getCurrentValue(), Map.class);
                        }
                        return mapper.readValue(p, new TypeReference<Map<String, Object>>() {});
                    }
                };
                
                SimpleModule module = new SimpleModule();
                module.addDeserializer(Map.class, deserializer);
                mapper.registerModule(module);
                
                return new HashMap<>();
            } catch (Exception e) {
                return new HashMap<>();
            }
        }
    }

    // Custom Jackson deserializer with non-deprecated method in Spring MVC interceptor
    public class good_case_8 extends HandlerInterceptorAdapter {
        private final ObjectMapper mapper = new ObjectMapper();
        
        @Override
        public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
            try {
                String json = request.getParameter("config");
                
                JsonDeserializer<InterceptorConfig> deserializer = new JsonDeserializer<InterceptorConfig>() {
                    @Override
                    public InterceptorConfig deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                        if (p.getCurrentToken() != JsonToken.START_OBJECT) {
                            // ok: java-jacksondatabindmappingexceptiondeprecated
                            throw MismatchedInputException.from(p, InterceptorConfig.class, "Expected object start");
                        }
                        return new InterceptorConfig();
                    }
                };
                
                SimpleModule module = new SimpleModule();
                module.addDeserializer(InterceptorConfig.class, deserializer);
                mapper.registerModule(module);
                
                mapper.readValue(json, InterceptorConfig.class);
                return true;
            } catch (Exception e) {
                return false;
            }
        }
    }
    
    private static class InterceptorConfig {
        private List<String> excludePaths;
        private boolean enabled;
    }

    // Spring view resolver with non-deprecated method
    @Configuration
    public class good_case_9 implements WebMvcConfigurer {
        @Bean
        public ViewResolver jsonViewResolver() {
            return new AbstractCachingViewResolver() {
                private final ObjectMapper mapper = new ObjectMapper();
                
                @Override
                protected View loadView(String viewName, Locale locale) throws Exception {
                    JsonDeserializer<ViewConfig> deserializer = new JsonDeserializer<ViewConfig>() {
                        @Override
                        public ViewConfig deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                            if (p.getCurrentToken() != JsonToken.START_OBJECT) {
                                // ok: java-jacksondatabindmappingexceptiondeprecated
                                throw JsonMappingException.from(p, "Expected object for view config");
                            }
                            return new ViewConfig();
                        }
                    };
                    
                    SimpleModule module = new SimpleModule();
                    module.addDeserializer(ViewConfig.class, deserializer);
                    mapper.registerModule(module);
                    
                    return new MappingJackson2JsonView();
                }
            };
        }
    }
    
    private static class ViewConfig {
        private String template;
        private Map<String, Object> attributes;
    }

    // Spring Boot filter with non-deprecated method
    @Component
    public class good_case_10 implements Filter {
        private final ObjectMapper mapper = new ObjectMapper();
        
        @Override
        public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
                throws IOException, ServletException {
            try {
                String json = request.getParameter("filterConfig");
                
                JsonDeserializer<FilterConfig> deserializer = new JsonDeserializer<FilterConfig>() {
                    @Override
                    public FilterConfig deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                        if (p.getCurrentToken() != JsonToken.START_OBJECT) {
                            // ok: java-jacksondatabindmappingexceptiondeprecated
                            throw InvalidFormatException.from(p, "Expected object for filter config", p.getCurrentValue(), FilterConfig.class);
                        }
                        return new FilterConfig();
                    }
                };
                
                SimpleModule module = new SimpleModule();
                module.addDeserializer(FilterConfig.class, deserializer);
                mapper.registerModule(module);
                
                mapper.readValue(json, FilterConfig.class);
                chain.doFilter(request, response);
            } catch (Exception e) {
                ((HttpServletResponse) response).sendError(HttpServletResponse.SC_BAD_REQUEST);
            }
        }
    }
    
    private static class FilterConfig {
        private List<String> allowedPaths;
        private List<String> blockedIps;
    }

    // Spring exception handler with non-deprecated method
    @ControllerAdvice
    public class good_case_11 {
        private final ObjectMapper mapper = new ObjectMapper();
        
        @ExceptionHandler(Exception.class)
        public ResponseEntity<String> handleException(Exception ex, HttpServletRequest request) {
            try {
                String json = request.getParameter("errorFormat");
                
                JsonDeserializer<ErrorFormat> deserializer = new JsonDeserializer<ErrorFormat>() {
                    @Override
                    public ErrorFormat deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                        if (p.getCurrentToken() != JsonToken.START_OBJECT) {
                            // ok: java-jacksondatabindmappingexceptiondeprecated
                            throw MismatchedInputException.from(p, ErrorFormat.class, "Expected object start");
                        }
                        return new ErrorFormat();
                    }
                };
                
                SimpleModule module = new SimpleModule();
                module.addDeserializer(ErrorFormat.class, deserializer);
                mapper.registerModule(module);
                
                mapper.readValue(json, ErrorFormat.class);
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error");
            } catch (Exception e) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error");
            }
        }
    }
    
    private static class ErrorFormat {
        private boolean includeStackTrace;
        private String format;
    }

    // Spring MVC argument resolver with non-deprecated method
    public class good_case_12 implements HandlerMethodArgumentResolver {
        private final ObjectMapper mapper = new ObjectMapper();
        
        @Override
        public boolean supportsParameter(MethodParameter parameter) {
            return true;
        }
        
        @Override
        public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer,
                NativeWebRequest webRequest, WebDataBinderFactory binderFactory) throws Exception {
            String json = webRequest.getParameter("arg");
            
            JsonDeserializer<CustomArgument> deserializer = new JsonDeserializer<CustomArgument>() {
                @Override
                public CustomArgument deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                    if (p.getCurrentToken() != JsonToken.START_OBJECT) {
                        // ok: java-jacksondatabindmappingexceptiondeprecated
                        throw JsonMappingException.from(p, "Expected object for custom argument");
                    }
                    return new CustomArgument();
                }
            };
            
            SimpleModule module = new SimpleModule();
            module.addDeserializer(CustomArgument.class, deserializer);
            mapper.registerModule(module);
            
            return mapper.readValue(json, CustomArgument.class);
        }
    }
    
    private static class CustomArgument {
        private String type;
        private Object value;
    }

    // Spring MVC message converter with non-deprecated method
    public class good_case_13 extends AbstractHttpMessageConverter<CustomMessage> {
        private final ObjectMapper mapper = new ObjectMapper();
        
        @Override
        protected boolean supports(Class<?> clazz) {
            return CustomMessage.class.isAssignableFrom(clazz);
        }
        
        @Override
        protected CustomMessage readInternal(Class<? extends CustomMessage> clazz, HttpInputMessage inputMessage)
                throws IOException, HttpMessageNotReadableException {
            JsonDeserializer<CustomMessage> deserializer = new JsonDeserializer<CustomMessage>() {
                @Override
                public CustomMessage deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                    if (p.getCurrentToken() != JsonToken.START_OBJECT) {
                        // ok: java-jacksondatabindmappingexceptiondeprecated
                        throw MismatchedInputException.from(p, CustomMessage.class, "Expected object start");
                    }
                    return new CustomMessage();
                }
            };
            
            SimpleModule module = new SimpleModule();
            module.addDeserializer(CustomMessage.class, deserializer);
            mapper.registerModule(module);
            
            return mapper.readValue(inputMessage.getBody(), CustomMessage.class);
        }
        
        @Override
        protected void writeInternal(CustomMessage t, HttpOutputMessage outputMessage)
                throws IOException, HttpMessageNotWritableException {
            mapper.writeValue(outputMessage.getBody(), t);
        }
    }
    
    private static class CustomMessage {
        private String content;
        private String sender;
    }

    // Spring WebSocket handler with non-deprecated method
    public class good_case_14 {
        public void handleWebSocketMessage(String message, HttpServletRequest request) {
            try {
                ObjectMapper mapper = new ObjectMapper();
                
                JsonDeserializer<WebSocketMessage> deserializer = new JsonDeserializer<WebSocketMessage>() {
                    @Override
                    public WebSocketMessage deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                        if (p.getCurrentToken() != JsonToken.START_OBJECT) {
                            // ok: java-jacksondatabindmappingexceptiondeprecated
                            throw InvalidFormatException.from(p, "Expected object for WebSocket message", p.getCurrentValue(), WebSocketMessage.class);
                        }
                        return new WebSocketMessage();
                    }
                };
                
                SimpleModule module = new SimpleModule();
                module.addDeserializer(WebSocketMessage.class, deserializer);
                mapper.registerModule(module);
                
                mapper.readValue(message, WebSocketMessage.class);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
    
    private static class WebSocketMessage {
        private String type;
        private Object payload;
    }

    // Spring REST template with non-deprecated method
    public class good_case_15 {
        public void processRestResponse(HttpServletRequest request) {
            try {
                String json = request.getParameter("response");
                ObjectMapper mapper = new ObjectMapper();
                
                JsonDeserializer<RestResponse> deserializer = new JsonDeserializer<RestResponse>() {
                    @Override
                    public RestResponse deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                        if (p.getCurrentToken() != JsonToken.START_OBJECT) {
                            // ok: java-jacksondatabindmappingexceptiondeprecated
                            throw JsonMappingException.from(p, "Expected object for REST response");
                        }
                        return new RestResponse();
                    }
                };
                
                SimpleModule module = new SimpleModule();
                module.addDeserializer(RestResponse.class, deserializer);
                mapper.registerModule(module);
                
                mapper.readValue(json, RestResponse.class);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
    
    private static class RestResponse {
        private int status;
        private Object body;
    }
}
// {/fact}