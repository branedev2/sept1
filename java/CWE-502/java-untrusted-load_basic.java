import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Base64;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import java.util.Properties;
import java.nio.file.Files;
import java.nio.file.Paths;
import javax.crypto.Cipher;
import javax.crypto.SealedObject;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.SerializationUtils;
import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.security.AnyTypePermission;
import com.thoughtworks.xstream.security.TypePermission;
import com.thoughtworks.xstream.security.ExplicitTypePermission;
import java.util.HashMap;
import java.util.Map;
import java.util.ArrayList;
import java.util.List;
import java.util.Collections;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

// True Positive Examples (Vulnerable Code)

@WebServlet("/deserialize1")
public class UntrustedDeserializationExamples extends HttpServlet {
    
    // True Positive Examples (Vulnerable Code)
    
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String serializedData = request.getParameter("data");
        byte[] data = Base64.getDecoder().decode(serializedData);
        
        try (ByteArrayInputStream bis = new ByteArrayInputStream(data);
             ObjectInputStream ois = new ObjectInputStream(bis)) {
            // ruleid: java-untrusted-load
            Object obj = ois.readObject(); // Deserializing untrusted data directly
            response.getWriter().println("Deserialized object: " + obj.toString());
        } catch (ClassNotFoundException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }
    
    public void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws IOException {
        InputStream inputStream = request.getInputStream();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int len;
        while ((len = inputStream.read(buffer)) != -1) {
            baos.write(buffer, 0, len);
        }
        
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(baos.toByteArray()))) {
            // ruleid: java-untrusted-load
            Object obj = ois.readObject(); // Deserializing directly from HTTP request body
            response.getWriter().println("Processed: " + obj);
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_3(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("serializedObject".equals(cookie.getName())) {
                    byte[] data = Base64.getDecoder().decode(cookie.getValue());
                    try (ByteArrayInputStream bis = new ByteArrayInputStream(data);
                         ObjectInputStream ois = new ObjectInputStream(bis)) {
                        // ruleid: java-untrusted-load
                        Object obj = ois.readObject(); // Deserializing from cookie
                        response.getWriter().println("Cookie object: " + obj);
                    } catch (ClassNotFoundException e) {
                        e.printStackTrace();
                    }
                    break;
                }
            }
        }
    }
    
    public void bad_case_4(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String url = request.getParameter("url");
        try {
            URL dataUrl = new URL(url);
            HttpURLConnection conn = (HttpURLConnection) dataUrl.openConnection();
            InputStream is = conn.getInputStream();
            
            ObjectInputStream ois = new ObjectInputStream(is);
            // ruleid: java-untrusted-load
            Object obj = ois.readObject(); // Deserializing from user-provided URL
            response.getWriter().println("Remote object: " + obj);
            ois.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_5(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String filePath = request.getParameter("file");
        try {
            FileInputStream fis = new FileInputStream(filePath);
            ObjectInputStream ois = new ObjectInputStream(fis);
            // ruleid: java-untrusted-load
            Object obj = ois.readObject(); // Deserializing from user-provided file path
            response.getWriter().println("File object: " + obj);
            ois.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_6(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String serializedData = request.getHeader("X-Serialized-Object");
        if (serializedData != null) {
            byte[] data = Base64.getDecoder().decode(serializedData);
            try (ByteArrayInputStream bis = new ByteArrayInputStream(data)) {
                ObjectInputStream ois = new ObjectInputStream(bis);
                // ruleid: java-untrusted-load
                Object obj = ois.readObject(); // Deserializing from HTTP header
                response.getWriter().println("Header object: " + obj);
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
            }
        }
    }
    
    public void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String base64Data = request.getParameter("data");
        byte[] encryptedData = Base64.getDecoder().decode(base64Data);
        
        try {
            // Even with encryption, still deserializing untrusted data
            SecretKeySpec sks = new SecretKeySpec("ThisIsASecretKey".getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, sks);
            
            SealedObject so = new SealedObject(new ByteArrayInputStream(encryptedData), cipher);
            // ruleid: java-untrusted-load
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(encryptedData));
            Object obj = ois.readObject();
            response.getWriter().println("Decrypted object: " + obj);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_8(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            // Using Apache Commons SerializationUtils with untrusted data
            String serializedData = request.getParameter("data");
            byte[] data = Base64.getDecoder().decode(serializedData);
            
            // ruleid: java-untrusted-load
            Object obj = SerializationUtils.deserialize(data); // Unsafe deserialization
            response.getWriter().println("Deserialized with SerializationUtils: " + obj);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_9(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Using XStream without proper security configuration
        XStream xstream = new XStream();
        xstream.addPermission(AnyTypePermission.ANY); // Dangerous permission
        
        String xml = request.getParameter("xml");
        // ruleid: java-untrusted-load
        Object obj = xstream.fromXML(xml); // Unsafe XML deserialization
        response.getWriter().println("XStream deserialized: " + obj);
    }
    
    public void bad_case_10(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        // Deserializing from session attribute that was previously set from untrusted input
        String serializedData = request.getParameter("data");
        if (serializedData != null) {
            request.getSession().setAttribute("storedObject", serializedData);
        }
        
        String storedData = (String) request.getSession().getAttribute("storedObject");
        if (storedData != null) {
            byte[] data = Base64.getDecoder().decode(storedData);
            try (ByteArrayInputStream bis = new ByteArrayInputStream(data);
                 ObjectInputStream ois = new ObjectInputStream(bis)) {
                // ruleid: java-untrusted-load
                Object obj = ois.readObject(); // Still untrusted even though from session
                response.getWriter().println("Session object: " + obj);
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
            }
        }
    }
    
    public void bad_case_11(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Deserializing with custom ObjectInputStream but still unsafe
        String serializedData = request.getParameter("data");
        byte[] data = Base64.getDecoder().decode(serializedData);
        
        try (ByteArrayInputStream bis = new ByteArrayInputStream(data)) {
            ObjectInputStream ois = new ObjectInputStream(bis) {
                @Override
                protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
                    // No effective security checks
                    return super.resolveClass(desc);
                }
            };
            // ruleid: java-untrusted-load
            Object obj = ois.readObject();
            response.getWriter().println("Custom deserialized: " + obj);
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_12(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Using SnakeYAML to deserialize untrusted YAML
        String yamlData = request.getParameter("yaml");
        Yaml yaml = new Yaml();
        // ruleid: java-untrusted-load
        Object obj = yaml.load(yamlData); // Unsafe YAML deserialization
        response.getWriter().println("YAML deserialized: " + obj);
    }
    
    public void bad_case_13(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Deserializing from a file uploaded by the user
        Part filePart = null;
        try {
            filePart = request.getPart("file");
            InputStream fileContent = filePart.getInputStream();
            ObjectInputStream ois = new ObjectInputStream(fileContent);
            // ruleid: java-untrusted-load
            Object obj = ois.readObject(); // Unsafe deserialization from uploaded file
            response.getWriter().println("Uploaded file object: " + obj);
            ois.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_14(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Deserializing in a loop, processing multiple serialized objects
        String[] serializedItems = request.getParameterValues("items");
        if (serializedItems != null) {
            for (String item : serializedItems) {
                byte[] data = Base64.getDecoder().decode(item);
                try (ByteArrayInputStream bis = new ByteArrayInputStream(data);
                     ObjectInputStream ois = new ObjectInputStream(bis)) {
                    // ruleid: java-untrusted-load
                    Object obj = ois.readObject(); // Multiple unsafe deserializations
                    response.getWriter().println("Item: " + obj);
                } catch (ClassNotFoundException e) {
                    e.printStackTrace();
                }
            }
        }
    }
    
    public void bad_case_15(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Deserializing with try-with-resources but still unsafe
        String serializedData = request.getParameter("data");
        byte[] data = Base64.getDecoder().decode(serializedData);
        
        try (ByteArrayInputStream bis = new ByteArrayInputStream(data);
             ObjectInputStream ois = new ObjectInputStream(bis)) {
            // ruleid: java-untrusted-load
            Map<String, Object> map = (Map<String, Object>) ois.readObject();
            for (Map.Entry<String, Object> entry : map.entrySet()) {
                response.getWriter().println(entry.getKey() + ": " + entry.getValue());
            }
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
    
    // True Negative Examples (Secure Code)
    
    public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Using a whitelist of allowed classes
        String serializedData = request.getParameter("data");
        byte[] data = Base64.getDecoder().decode(serializedData);
        
        try (ByteArrayInputStream bis = new ByteArrayInputStream(data)) {
            // ok: java-untrusted-load
            ObjectInputStream ois = new ValidatingObjectInputStream(bis)
                .accept(String.class, Integer.class, ArrayList.class);
            Object obj = ois.readObject();
            response.getWriter().println("Validated object: " + obj);
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_2(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Using a secure alternative - JSON deserialization instead of Java serialization
        String jsonData = request.getParameter("data");
        
        // ok: java-untrusted-load
        ObjectMapper mapper = new ObjectMapper();
        mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NONE); // Disables polymorphic type handling
        UserData userData = mapper.readValue(jsonData, UserData.class);
        response.getWriter().println("User: " + userData.getName());
    }
    
    public void good_case_3(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Using XStream with proper security configuration
        XStream xstream = new XStream();
        
        // ok: java-untrusted-load
        // Configure XStream with a whitelist of allowed types
        xstream.allowTypes(new Class[] {String.class, Integer.class, ArrayList.class});
        // Alternatively: xstream.addPermission(new ExplicitTypePermission(new Class[] {String.class, Integer.class}));
        
        String xml = request.getParameter("xml");
        Object obj = xstream.fromXML(xml);
        response.getWriter().println("Secure XStream: " + obj);
    }
    
    public void good_case_4(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Using SnakeYAML with SafeConstructor
        String yamlData = request.getParameter("yaml");
        
        // ok: java-untrusted-load
        Yaml yaml = new Yaml(new SafeConstructor());
        Object obj = yaml.load(yamlData);
        response.getWriter().println("Safe YAML: " + obj);
    }
    
    public void good_case_5(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Using a custom filter for allowed classes
        String serializedData = request.getParameter("data");
        byte[] data = Base64.getDecoder().decode(serializedData);
        
        try (ByteArrayInputStream bis = new ByteArrayInputStream(data)) {
            // ok: java-untrusted-load
            ObjectInputStream ois = new FilteredObjectInputStream(bis);
            Object obj = ois.readObject();
            response.getWriter().println("Filtered object: " + obj);
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_6(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Using a secure alternative - manual parsing of data
        String data = request.getParameter("data");
        
        // ok: java-untrusted-load
        // Parse the data manually instead of deserializing
        String[] parts = data.split(",");
        Map<String, String> parsedData = new HashMap<>();
        for (String part : parts) {
            String[] keyValue = part.split("=");
            if (keyValue.length == 2) {
                parsedData.put(keyValue[0], keyValue[1]);
            }
        }
        response.getWriter().println("Parsed data: " + parsedData);
    }
    
    public void good_case_7(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Using serialization only for trusted data from a secure source
        try {
            // ok: java-untrusted-load
            // Reading from a trusted file controlled by the application, not user input
            FileInputStream fis = new FileInputStream("/secure/trusted_data.ser");
            ObjectInputStream ois = new ObjectInputStream(fis);
            Object obj = ois.readObject();
            response.getWriter().println("Trusted object: " + obj);
            ois.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_8(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Using a secure serialization library
        String data = request.getParameter("data");
        
        // ok: java-untrusted-load
        // Using a hypothetical secure serialization library
        SecureDeserializer deserializer = new SecureDeserializer();
        deserializer.setAllowedClasses(String.class, Integer.class, ArrayList.class);
        Object obj = deserializer.deserialize(data);
        response.getWriter().println("Securely deserialized: " + obj);
    }
    
    public void good_case_9(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Using lookup mechanism instead of deserialization
        String id = request.getParameter("id");
        
        // ok: java-untrusted-load
        // Instead of deserializing, look up the object by ID in a database or cache
        UserService userService = new UserService();
        User user = userService.getUserById(Integer.parseInt(id));
        response.getWriter().println("User: " + user.getName());
    }
    
    public void good_case_10(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Using a secure protocol buffer implementation
        String data = request.getParameter("data");
        byte[] protoData = Base64.getDecoder().decode(data);
        
        // ok: java-untrusted-load
        // Protocol buffers are safer than Java serialization
        UserProto.User user = UserProto.User.parseFrom(protoData);
        response.getWriter().println("Proto user: " + user.getName());
    }
    
    public void good_case_11(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Using serialization with signature verification
        String data = request.getParameter("data");
        String signature = request.getParameter("signature");
        
        // ok: java-untrusted-load
        // Verify the signature before deserializing
        if (SecurityUtils.verifySignature(data, signature)) {
            byte[] bytes = Base64.getDecoder().decode(data);
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes));
            Object obj = ois.readObject();
            response.getWriter().println("Verified object: " + obj);
        } else {
            response.getWriter().println("Invalid signature");
        }
    }
    
    public void good_case_12(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Using a custom ObjectInputStream with blacklist
        String serializedData = request.getParameter("data");
        byte[] data = Base64.getDecoder().decode(serializedData);
        
        try (ByteArrayInputStream bis = new ByteArrayInputStream(data)) {
            // ok: java-untrusted-load
            ObjectInputStream ois = new BlacklistObjectInputStream(bis);
            Object obj = ois.readObject();
            response.getWriter().println("Blacklisted classes protected: " + obj);
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_13(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Using a data transfer object pattern
        String jsonData = request.getParameter("data");
        
        // ok: java-untrusted-load
        // Parse JSON into a simple DTO with no methods
        Gson gson = new Gson();
        UserDTO userDto = gson.fromJson(jsonData, UserDTO.class);
        
        // Validate the DTO
        if (userDto.isValid()) {
            // Convert to domain object
            User user = new User(userDto.getName(), userDto.getEmail());
            response.getWriter().println("Valid user: " + user.getName());
        } else {
            response.getWriter().println("Invalid data");
        }
    }
    
    public void good_case_14(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Using immutable objects and validation
        String jsonData = request.getParameter("data");
        
        // ok: java-untrusted-load
        // Parse JSON into immutable objects
        ObjectMapper mapper = new ObjectMapper();
        ImmutableUser user = mapper.readValue(jsonData, ImmutableUser.class);
        
        // Validate the immutable object
        if (user.isValid()) {
            response.getWriter().println("Valid immutable user: " + user.getName());
        } else {
            response.getWriter().println("Invalid data");
        }
    }
    
    public void good_case_15(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Using a secure serialization format with schema validation
        String data = request.getParameter("data");
        
        // ok: java-untrusted-load
        // Avro with schema validation is safer than Java serialization
        Schema schema = new Schema.Parser().parse(new File("user.avsc"));
        DatumReader<GenericRecord> reader = new GenericDatumReader<>(schema);
        Decoder decoder = DecoderFactory.get().jsonDecoder(schema, data);
        GenericRecord user = reader.read(null, decoder);
        response.getWriter().println("Avro user: " + user.get("name"));
    }
    
    // Helper classes for examples
    
    // Custom ObjectInputStream that validates classes
    private static class ValidatingObjectInputStream extends ObjectInputStream {
        private final List<Class<?>> acceptedClasses = new ArrayList<>();
        
        public ValidatingObjectInputStream(InputStream in) throws IOException {
            super(in);
        }
        
        public ValidatingObjectInputStream accept(Class<?>... classes) {
            Collections.addAll(acceptedClasses, classes);
            return this;
        }
        
        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
            Class<?> clazz = super.resolveClass(desc);
            if (!acceptedClasses.contains(clazz)) {
                throw new InvalidClassException("Unauthorized deserialization attempt", clazz.getName());
            }
            return clazz;
        }
    }
    
    // Custom ObjectInputStream with blacklist
    private static class BlacklistObjectInputStream extends ObjectInputStream {
        private static final List<String> BLAC_REDACTED_TWILIO_ID = Arrays.asList(
            "java.lang.ProcessBuilder",
            "java.lang.Runtime",
            "java.net.Socket"
        );
        
        public BlacklistObjectInputStream(InputStream in) throws IOException {
            super(in);
        }
        
        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
            String className = desc.getName();
            if (BLAC_REDACTED_TWILIO_ID.contains(className)) {
                throw new InvalidClassException("Unauthorized deserialization attempt", className);
            }
            return super.resolveClass(desc);
        }
    }
    
    // Custom ObjectInputStream with filtering
    private static class FilteredObjectInputStream extends ObjectInputStream {
        public FilteredObjectInputStream(InputStream in) throws IOException {
            super(in);
            enableResolveObject(true);
        }
        
        @Override
        protected Object resolveObject(Object obj) {
            // Filter out dangerous objects
            if (obj instanceof ProcessBuilder || obj instanceof Runtime) {
                return null;
            }
            return obj;
        }
    }
    
    // Mock classes for examples
    private static class ObjectMapper {
        public void enableDefaultTyping(Object type) {}
        public <T> T readValue(String content, Class<T> valueType) { return null; }
    }
    
    private static class UserData {
        private String name;
        public String getName() { return name; }
    }
    
    private static class UserService {
        public User getUserById(int id) { return new User("Test", "test@example.com"); }
    }
    
    private static class User {
        private String name;
        private String email;
        public User(String name, String email) {
            this.name = name;
            this.email = email;
        }
        public String getName() { return name; }
    }
    
    private static class UserDTO {
        private String name;
        private String email;
        public String getName() { return name; }
        public String getEmail() { return email; }
        public boolean isValid() { return name != null && email != null; }
    }
    
    private static class ImmutableUser {
        private final String name;
        private final String email;
        public ImmutableUser(String name, String email) {
            this.name = name;
            this.email = email;
        }
        public String getName() { return name; }
        public boolean isValid() { return name != null && email != null; }
    }
    
    private static class SecurityUtils {
        public static boolean verifySignature(String data, String signature) { return true; }
    }
    
    private static class SecureDeserializer {
        public void setAllowedClasses(Class<?>... classes) {}
        public Object deserialize(String data) { return null; }
    }
    
    // Mock classes for protocol buffers
    private static class UserProto {
        public static class User {
            public static User parseFrom(byte[] data) { return new User(); }
            public String getName() { return "Test"; }
        }
    }
    
    // Mock classes for Avro
    private static class Schema {
        public static class Parser {
            public Schema parse(File file) { return new Schema(); }
        }
    }
    
    private static class GenericRecord {
        public Object get(String field) { return "Test"; }
    }
    
    private static class GenericDatumReader<T> {
        public GenericDatumReader(Schema schema) {}
        public T read(T reuse, Decoder decoder) { return null; }
    }
    
    private static class DecoderFactory {
        public static DecoderFactory get() { return new DecoderFactory(); }
        public Decoder jsonDecoder(Schema schema, String data) { return null; }
    }
    
    private static class Decoder {}
    
    private static class Gson {
        public <T> T fromJson(String json, Class<T> classOfT) { return null; }
    }
}
// {/fact}