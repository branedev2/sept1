import java.io.*;
import java.net.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.io.IOUtils;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import org.apache.commons.lang3.SerializationUtils;
import javax.xml.bind.DatatypeConverter;

public class DeserializationExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException, ClassNotFoundException {
        // Directly deserializing data from HTTP request
        byte[] serializedData = Base64.getDecoder().decode(request.getParameter("data"));
        ByteArrayInputStream bais = new ByteArrayInputStream(serializedData);
        ObjectInputStream ois = new ObjectInputStream(bais);
        // ruleid: java-untrusted-load-exp
        Object obj = ois.readObject(); // Vulnerable: Deserializing untrusted data
        ois.close();
    }

    public void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws IOException, ClassNotFoundException {
        // Deserializing data from HTTP request with minimal processing
        String serializedBase64 = request.getParameter("serializedObject");
        byte[] serializedData = Base64.getDecoder().decode(serializedBase64);
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(serializedData));
        // ruleid: java-untrusted-load-exp
        Map<String, Object> map = (Map<String, Object>) ois.readObject(); // Vulnerable
        ois.close();
    }

    public void bad_case_3(HttpServletRequest request, HttpServletResponse response) throws IOException, ClassNotFoundException {
        // Deserializing from a cookie
        Cookie[] cookies = request.getCookies();
        for (Cookie cookie : cookies) {
            if (cookie.getName().equals("userdata")) {
                byte[] data = Base64.getDecoder().decode(cookie.getValue());
                ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
                // ruleid: java-untrusted-load-exp
                UserProfile profile = (UserProfile) ois.readObject(); // Vulnerable
                ois.close();
                break;
            }
        }
    }

    public void bad_case_4(HttpServletRequest request, HttpServletResponse response) throws IOException, ClassNotFoundException {
        // Deserializing from request header
        String serializedHeader = request.getHeader("X-User-Data");
        if (serializedHeader != null) {
            byte[] data = Base64.getDecoder().decode(serializedHeader);
            ByteArrayInputStream bais = new ByteArrayInputStream(data);
            ObjectInputStream ois = new ObjectInputStream(bais);
            // ruleid: java-untrusted-load-exp
            UserPreferences prefs = (UserPreferences) ois.readObject(); // Vulnerable
            ois.close();
        }
    }

    public void bad_case_5(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Deserializing from uploaded file
        Part filePart = request.getPart("userFile");
        InputStream fileContent = filePart.getInputStream();
        ObjectInputStream ois = new ObjectInputStream(fileContent);
        // ruleid: java-untrusted-load-exp
        Configuration config = (Configuration) ois.readObject(); // Vulnerable
        ois.close();
    }

    public void bad_case_6(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Deserializing with Apache Commons SerializationUtils
        String serializedData = request.getParameter("objectData");
        byte[] data = Base64.getDecoder().decode(serializedData);
        // ruleid: java-untrusted-load-exp
        Object obj = SerializationUtils.deserialize(data); // Vulnerable
    }

    public void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Deserializing in a loop
        String[] serializedItems = request.getParameterValues("items");
        if (serializedItems != null) {
            for (String item : serializedItems) {
                byte[] data = Base64.getDecoder().decode(item);
                ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
                // ruleid: java-untrusted-load-exp
                Object obj = ois.readObject(); // Vulnerable
                ois.close();
            }
        }
    }

    public void bad_case_8(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Deserializing with try-with-resources
        String serializedData = request.getParameter("data");
        byte[] bytes = Base64.getDecoder().decode(serializedData);
        
        try (ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
             ObjectInputStream ois = new ObjectInputStream(bais)) {
            // ruleid: java-untrusted-load-exp
            Object obj = ois.readObject(); // Vulnerable
        }
    }

    public void bad_case_9(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Deserializing with conditional logic
        String type = request.getParameter("type");
        String serializedData = request.getParameter("data");
        
        if ("user".equals(type)) {
            byte[] bytes = Base64.getDecoder().decode(serializedData);
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes));
            // ruleid: java-untrusted-load-exp
            User user = (User) ois.readObject(); // Vulnerable
            ois.close();
        }
    }

    public void bad_case_10(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Deserializing from URL parameter with minimal validation
        String serializedData = request.getParameter("userData");
        if (serializedData != null && serializedData.length() > 0) {
            byte[] data = Base64.getDecoder().decode(serializedData);
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
            // ruleid: java-untrusted-load-exp
            UserData userData = (UserData) ois.readObject(); // Vulnerable
            ois.close();
        }
    }

    public void bad_case_11(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Deserializing with error handling
        try {
            String serializedData = request.getParameter("config");
            byte[] data = Base64.getDecoder().decode(serializedData);
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
            // ruleid: java-untrusted-load-exp
            AppConfig config = (AppConfig) ois.readObject(); // Vulnerable
            ois.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_12(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Deserializing from POST body
        ServletInputStream inputStream = request.getInputStream();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            baos.write(buffer, 0, bytesRead);
        }
        
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(baos.toByteArray()));
        // ruleid: java-untrusted-load-exp
        Object obj = ois.readObject(); // Vulnerable
        ois.close();
    }

    public void bad_case_13(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Deserializing with custom ObjectInputStream
        String serializedData = request.getParameter("data");
        byte[] data = Base64.getDecoder().decode(serializedData);
        
        class CustomObjectInputStream extends ObjectInputStream {
            public CustomObjectInputStream(InputStream in) throws IOException {
                super(in);
            }
            
            @Override
            protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
                // Still vulnerable as it doesn't restrict classes
                return super.resolveClass(desc);
            }
        }
        
        CustomObjectInputStream cois = new CustomObjectInputStream(new ByteArrayInputStream(data));
        // ruleid: java-untrusted-load-exp
        Object obj = cois.readObject(); // Vulnerable
        cois.close();
    }

    public void bad_case_14(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Deserializing with hex encoding
        String hexData = request.getParameter("hexData");
        byte[] data = DatatypeConverter.parseHexBinary(hexData);
        
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        // ruleid: java-untrusted-load-exp
        Object obj = ois.readObject(); // Vulnerable
        ois.close();
    }

    public void bad_case_15(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Deserializing with simple encryption
        String encryptedData = request.getParameter("encryptedData");
        String key = "ThisIsASecretKey"; // Hard-coded key is another issue
        
        // Simple XOR decryption (not secure)
        byte[] encData = Base64.getDecoder().decode(encryptedData);
        byte[] keyBytes = key.getBytes();
        byte[] decrypted = new byte[encData.length];
        
        for (int i = 0; i < encData.length; i++) {
            decrypted[i] = (byte) (encData[i] ^ keyBytes[i % keyBytes.length]);
        }
        
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(decrypted));
        // ruleid: java-untrusted-load-exp
        Object obj = ois.readObject(); // Vulnerable
        ois.close();
    }

    // True Negative Examples (Safe Code)

    public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Using JSON deserialization instead of Java serialization
        String jsonData = request.getParameter("data");
        // ok: java-untrusted-load-exp
        Map<String, Object> map = new com.fasterxml.jackson.databind.ObjectMapper().readValue(jsonData, Map.class);
    }

    public void good_case_2(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using a whitelist filter for deserialization
        String serializedData = request.getParameter("data");
        byte[] data = Base64.getDecoder().decode(serializedData);
        
        class SafeObjectInputStream extends ObjectInputStream {
            private static final Set<String> ALLOWED_CLASSES = new HashSet<>(Arrays.asList(
                "java.util.ArrayList",
                "java.util.HashMap",
                "com.example.SafeClass"
            ));
            
            public SafeObjectInputStream(InputStream in) throws IOException {
                super(in);
            }
            
            @Override
            protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
                String className = desc.getName();
                // ok: java-untrusted-load-exp
                if (!ALLOWED_CLASSES.contains(className)) {
                    throw new ClassNotFoundException("Unauthorized deserialization attempt: " + className);
                }
                return super.resolveClass(desc);
            }
        }
        
        SafeObjectInputStream sois = new SafeObjectInputStream(new ByteArrayInputStream(data));
        Object obj = sois.readObject(); // Safe due to whitelist
        sois.close();
    }

    public void good_case_3(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using XML deserialization with security features enabled
        String xmlData = request.getParameter("xmlData");
        
        // ok: java-untrusted-load-exp
        javax.xml.parsers.DocumentBuilderFactory dbf = javax.xml.parsers.DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        
        javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
        org.w3c.dom.Document doc = db.parse(new java.io.ByteArrayInputStream(xmlData.getBytes()));
    }

    public void good_case_4(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using a secure serialization alternative (Protocol Buffers)
        String base64Data = request.getParameter("protoData");
        byte[] protoBytes = Base64.getDecoder().decode(base64Data);
        
        // ok: java-untrusted-load-exp
        // Using Protocol Buffers for safe deserialization
        MyProto.Message message = MyProto.Message.parseFrom(protoBytes);
    }

    public void good_case_5(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using a secure serialization library (GSON)
        String jsonData = request.getParameter("jsonData");
        
        // ok: java-untrusted-load-exp
        com.google.gson.Gson gson = new com.google.gson.Gson();
        UserData userData = gson.fromJson(jsonData, UserData.class);
    }

    public void good_case_6(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using a secure serialization library (Jackson) with additional security
        String jsonData = request.getParameter("jsonData");
        
        // ok: java-untrusted-load-exp
        com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        // Disable polymorphic type handling
        mapper.disableDefaultTyping();
        // Disable auto-detection of fields and methods
        mapper.disable(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
        
        UserData userData = mapper.readValue(jsonData, UserData.class);
    }

    public void good_case_7(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using a custom data transfer format
        String data = request.getParameter("userData");
        
        // ok: java-untrusted-load-exp
        // Manual parsing of a simple custom format
        String[] parts = data.split("\\|");
        UserData userData = new UserData();
        if (parts.length >= 3) {
            userData.setId(Integer.parseInt(parts[0]));
            userData.setName(parts[1]);
            userData.setEmail(parts[2]);
        }
    }

    public void good_case_8(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using a secure serialization library (YAML)
        String yamlData = request.getParameter("yamlData");
        
        // ok: java-untrusted-load-exp
        org.yaml.snakeyaml.LoaderOptions options = new org.yaml.snakeyaml.LoaderOptions();
        options.setCodePointLimit(5 * 1024 * 1024); // 5MB limit
        options.setMaxAliasesForCollections(50);
        org.yaml.snakeyaml.Yaml yaml = new org.yaml.snakeyaml.Yaml(
            new org.yaml.snakeyaml.constructor.SafeConstructor(options));
        
        Map<String, Object> data = yaml.load(yamlData);
    }

    public void good_case_9(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using a secure serialization library (XML) with validation
        String xmlData = request.getParameter("xmlData");
        
        // ok: java-untrusted-load-exp
        javax.xml.bind.JAXBContext context = javax.xml.bind.JAXBContext.newInstance(SafeConfig.class);
        javax.xml.bind.Unmarshaller unmarshaller = context.createUnmarshaller();
        
        // Add schema validation
        javax.xml.validation.SchemaFactory sf = javax.xml.validation.SchemaFactory.newInstance(javax.xml.XMLConstants.W3C_XML_SCHEMA_NS_URI);
        unmarshaller.setSchema(sf.newSchema(new java.io.File("schema.xsd")));
        
        // Disable external entities
        unmarshaller.setProperty(javax.xml.XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        unmarshaller.setProperty(javax.xml.XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
        
        SafeConfig config = (SafeConfig) unmarshaller.unmarshal(new java.io.StringReader(xmlData));
    }

    public void good_case_10(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using a secure serialization library (MessagePack)
        byte[] msgpackData = Base64.getDecoder().decode(request.getParameter("msgpackData"));
        
        // ok: java-untrusted-load-exp
        org.msgpack.MessagePack msgpack = new org.msgpack.MessagePack();
        msgpack.register(UserData.class);
        UserData userData = msgpack.read(msgpackData, UserData.class);
    }

    public void good_case_11(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using a secure serialization library (Kryo) with security features
        String base64Data = request.getParameter("kryoData");
        byte[] kryoData = Base64.getDecoder().decode(base64Data);
        
        // ok: java-untrusted-load-exp
        com.esotericsoftware.kryo.Kryo kryo = new com.esotericsoftware.kryo.Kryo();
        kryo.setRegistrationRequired(true); // Only deserialize registered classes
        kryo.register(UserData.class);
        
        com.esotericsoftware.kryo.io.Input input = new com.esotericsoftware.kryo.io.Input(kryoData);
        UserData userData = kryo.readObject(input, UserData.class);
        input.close();
    }

    public void good_case_12(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using a secure serialization library (Avro)
        byte[] avroData = Base64.getDecoder().decode(request.getParameter("avroData"));
        
        // ok: java-untrusted-load-exp
        org.apache.avro.Schema schema = new org.apache.avro.Schema.Parser().parse(
            new java.io.File("user_schema.avsc"));
        
        org.apache.avro.io.DatumReader<Object> datumReader = 
            new org.apache.avro.specific.SpecificDatumReader<>(schema);
        org.apache.avro.io.Decoder decoder = 
            org.apache.avro.io.DecoderFactory.get().binaryDecoder(avroData, null);
        
        Object userData = datumReader.read(null, decoder);
    }

    public void good_case_13(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using a secure serialization library (FlatBuffers)
        byte[] fbData = Base64.getDecoder().decode(request.getParameter("fbData"));
        
        // ok: java-untrusted-load-exp
        java.nio.ByteBuffer buffer = java.nio.ByteBuffer.wrap(fbData);
        com.example.flatbuffers.User user = com.example.flatbuffers.User.getRootAsUser(buffer);
    }

    public void good_case_14(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using a secure serialization library (Thrift)
        byte[] thriftData = Base64.getDecoder().decode(request.getParameter("thriftData"));
        
        // ok: java-untrusted-load-exp
        org.apache.thrift.transport.TMemoryInputTransport transport = 
            new org.apache.thrift.transport.TMemoryInputTransport(thriftData);
        org.apache.thrift.protocol.TBinaryProtocol protocol = 
            new org.apache.thrift.protocol.TBinaryProtocol(transport);
        
        com.example.thrift.User user = new com.example.thrift.User();
        user.read(protocol);
    }

    public void good_case_15(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using a secure serialization library (JSON-B)
        String jsonData = request.getParameter("jsonData");
        
        // ok: java-untrusted-load-exp
        javax.json.bind.Jsonb jsonb = javax.json.bind.JsonbBuilder.create();
        UserData userData = jsonb.fromJson(jsonData, UserData.class);
    }

    // Helper classes
    static class UserProfile implements Serializable {
        private String username;
        private String email;
    }

    static class UserPreferences implements Serializable {
        private Map<String, String> preferences;
    }

    static class Configuration implements Serializable {
        private Map<String, Object> settings;
    }

    static class User implements Serializable {
        private int id;
        private String name;
    }

    static class UserData implements Serializable {
        private int id;
        private String name;
        private String email;
        
        public void setId(int id) { this.id = id; }
        public void setName(String name) { this.name = name; }
        public void setEmail(String email) { this.email = email; }
    }

    static class AppConfig implements Serializable {
        private Map<String, String> properties;
    }

    static class SafeConfig {
        private String name;
        private String value;
    }

    // Mock class to represent Protocol Buffers
    static class MyProto {
        static class Message {
            public static Message parseFrom(byte[] data) {
                return new Message();
            }
        }
    }
}
// {/fact}