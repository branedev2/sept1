import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Base64;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.SerializationUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.thoughtworks.xstream.XStream;
import org.yaml.snakeyaml.Yaml;
import org.springframework.web.bind.annotation.*;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import javax.xml.parsers.DocumentBuilderFactory;
import org.jboss.resteasy.plugins.providers.SerializableProvider;
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import com.esotericsoftware.kryo.Kryo;
import com.esotericsoftware.kryo.io.Input;
import com.esotericsoftware.kryo.io.Output;
import org.springframework.remoting.httpinvoker.HttpInvokerServiceExporter;
import org.springframework.remoting.rmi.RmiServiceExporter;
import org.springframework.web.client.RestTemplate;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import redis.clients.jedis.Jedis;
import com.google.gson.Gson;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.text.StringEscapeUtils;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.codecs.Base64Codec;
import org.owasp.esapi.crypto.CipherText;
import org.owasp.esapi.crypto.PlainText;
import org.owasp.esapi.reference.crypto.JavaEncryptor;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

// Security Issue: Deserialization of untrusted data can lead to denial of service attacks or remote code execution

// True Positive Examples (Vulnerable/Insecure Code)
public class DeserializationVulnerabilities {

    // Standard Java ObjectInputStream deserialization
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) {
        try {
            byte[] serializedData = Base64.getDecoder().decode(request.getParameter("data"));
            ByteArrayInputStream bais = new ByteArrayInputStream(serializedData);
            
            // ruleid: java-untrusted-load-exp
            ObjectInputStream ois = new ObjectInputStream(bais);
            Object obj = ois.readObject();
            ois.close();
            
            System.out.println("Deserialized object: " + obj.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Apache Commons SerializationUtils
    public void bad_case_2(HttpServletRequest request) {
        try {
            byte[] serializedData = Base64.getDecoder().decode(request.getParameter("data"));
            
            // ruleid: java-untrusted-load-exp
            Object obj = SerializationUtils.deserialize(serializedData);
            
            System.out.println("Deserialized object: " + obj.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // XStream XML deserialization
    public void bad_case_3(HttpServletRequest request) {
        try {
            String xml = request.getParameter("xml");
            XStream xstream = new XStream();
            
            // ruleid: java-untrusted-load-exp
            Object obj = xstream.fromXML(xml);
            
            System.out.println("Deserialized object: " + obj.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // SnakeYAML deserialization
    public void bad_case_4(HttpServletRequest request) {
        try {
            String yamlStr = request.getParameter("yaml");
            Yaml yaml = new Yaml();
            
            // ruleid: java-untrusted-load-exp
            Object obj = yaml.load(yamlStr);
            
            System.out.println("Deserialized object: " + obj.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Jackson ObjectMapper with polymorphic deserialization
    public void bad_case_5(HttpServletRequest request) {
        try {
            String json = request.getParameter("json");
            ObjectMapper mapper = new ObjectMapper();
            mapper.enableDefaultTyping(); // Enables polymorphic type handling
            
            // ruleid: java-untrusted-load-exp
            Object obj = mapper.readValue(json, Object.class);
            
            System.out.println("Deserialized object: " + obj.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Kryo deserialization library
    public void bad_case_6(HttpServletRequest request) {
        try {
            byte[] serializedData = Base64.getDecoder().decode(request.getParameter("data"));
            Kryo kryo = new Kryo();
            kryo.setRegistrationRequired(false); // Allows any class to be deserialized
            Input input = new Input(serializedData);
            
            // ruleid: java-untrusted-load-exp
            Object obj = kryo.readClassAndObject(input);
            input.close();
            
            System.out.println("Deserialized object: " + obj.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Spring HttpInvokerServiceExporter
    @RestController
    public void bad_case_7(HttpServletRequest request, HttpServletResponse response) {
        try {
            HttpInvokerServiceExporter exporter = new HttpInvokerServiceExporter();
            exporter.setServiceInterface(Runnable.class);
            exporter.setService(new Runnable() {
                public void run() {
                    System.out.println("Service running");
                }
            });
            exporter.afterPropertiesSet();
            
            // ruleid: java-untrusted-load-exp
            exporter.handleRequest(request, response);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // JBoss RESTEasy SerializableProvider
    public void bad_case_8(HttpServletRequest request) {
        try {
            byte[] serializedData = IOUtils.toByteArray(request.getInputStream());
            SerializableProvider provider = new SerializableProvider();
            ByteArrayInputStream bais = new ByteArrayInputStream(serializedData);
            
            // ruleid: java-untrusted-load-exp
            Object obj = provider.readFrom(Object.class, null, null, null, null, bais);
            
            System.out.println("Deserialized object: " + obj.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Spring RMI Service Exporter with HTTP input
    public void bad_case_9(HttpServletRequest request) {
        try {
            // Get serialized data from HTTP request
            byte[] serializedData = Base64.getDecoder().decode(request.getParameter("rmiData"));
            
            // Set up RMI service with data from HTTP
            RmiServiceExporter exporter = new RmiServiceExporter();
            ByteArrayInputStream bais = new ByteArrayInputStream(serializedData);
            ObjectInputStream ois = new ObjectInputStream(bais);
            
            // ruleid: java-untrusted-load-exp
            Object service = ois.readObject();
            exporter.setService(service);
            
            exporter.afterPropertiesSet();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Custom ObjectInputStream without validation
    public void bad_case_10(HttpServletRequest request) {
        try {
            byte[] serializedData = Base64.getDecoder().decode(request.getParameter("data"));
            ByteArrayInputStream bais = new ByteArrayInputStream(serializedData);
            
            // Custom ObjectInputStream without proper validation
            class CustomObjectInputStream extends ObjectInputStream {
                public CustomObjectInputStream(InputStream in) throws IOException {
                    super(in);
                }
                
                @Override
                protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
                    return super.resolveClass(desc);
                }
            }
            
            // ruleid: java-untrusted-load-exp
            CustomObjectInputStream cois = new CustomObjectInputStream(bais);
            Object obj = cois.readObject();
            cois.close();
            
            System.out.println("Deserialized object: " + obj.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Redis Jedis with deserialization
    public void bad_case_11(HttpServletRequest request) {
        try {
            String key = request.getParameter("key");
            Jedis jedis = new Jedis("localhost");
            byte[] serializedData = jedis.get(key.getBytes());
            
            // ruleid: java-untrusted-load-exp
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(serializedData));
            Object obj = ois.readObject();
            ois.close();
            
            System.out.println("Deserialized object from Redis: " + obj.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Apache HTTP Client with deserialization
    public void bad_case_12(HttpServletRequest request) {
        try {
            String url = request.getParameter("url");
            CloseableHttpClient httpClient = HttpClients.createDefault();
            HttpPost httpPost = new HttpPost(url);
            
            org.apache.http.HttpResponse response = httpClient.execute(httpPost);
            byte[] serializedData = IOUtils.toByteArray(response.getEntity().getContent());
            
            // ruleid: java-untrusted-load-exp
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(serializedData));
            Object obj = ois.readObject();
            ois.close();
            
            System.out.println("Deserialized object from HTTP response: " + obj.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Spring RestTemplate with deserialization
    public void bad_case_13(HttpServletRequest request) {
        try {
            String url = request.getParameter("url");
            RestTemplate restTemplate = new RestTemplate();
            
            // Get serialized data from external URL based on user input
            byte[] serializedData = restTemplate.getForObject(url, byte[].class);
            
            // ruleid: java-untrusted-load-exp
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(serializedData));
            Object obj = ois.readObject();
            ois.close();
            
            System.out.println("Deserialized object from RestTemplate: " + obj.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Gson with unsafe type adapter
    public void bad_case_14(HttpServletRequest request) {
        try {
            String json = request.getParameter("json");
            Gson gson = new Gson();
            
            // Custom type adapter that uses deserialization
            class UnsafeDeserializer {
                public Object fromJson(String json) throws Exception {
                    byte[] data = Base64.getDecoder().decode(json);
                    ByteArrayInputStream bais = new ByteArrayInputStream(data);
                    // ruleid: java-untrusted-load-exp
                    ObjectInputStream ois = new ObjectInputStream(bais);
                    Object obj = ois.readObject();
                    ois.close();
                    return obj;
                }
            }
            
            UnsafeDeserializer deserializer = new UnsafeDeserializer();
            Object obj = deserializer.fromJson(json);
            
            System.out.println("Deserialized object: " + obj.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // JAXB with external entities enabled
    public void bad_case_15(HttpServletRequest request) {
        try {
            String xml = request.getParameter("xml");
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            
            // ruleid: java-untrusted-load-exp
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", true);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", true);
            
            factory.newDocumentBuilder().parse(new ByteArrayInputStream(xml.getBytes()));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // True Negative Examples (Safe/Secure Code)
    
    // Standard Java ObjectInputStream with validation
    public void good_case_1(HttpServletRequest request) {
        try {
            byte[] serializedData = Base64.getDecoder().decode(request.getParameter("data"));
            ByteArrayInputStream bais = new ByteArrayInputStream(serializedData);
            
            // Custom ObjectInputStream with whitelist validation
            class ValidatingObjectInputStream extends ObjectInputStream {
                private static final String[] ALLOWED_CLASSES = {
                    "java.util.ArrayList",
                    "java.util.HashMap",
                    "java.lang.String"
                };
                
                public ValidatingObjectInputStream(InputStream in) throws IOException {
                    super(in);
                }
                
                @Override
                protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
                    String className = desc.getName();
                    for (String allowed : ALLOWED_CLASSES) {
                        if (className.equals(allowed)) {
                            // ok: java-untrusted-load-exp
                            return super.resolveClass(desc);
                        }
                    }
                    throw new ClassNotFoundException("Class not allowed: " + className);
                }
            }
            
            ValidatingObjectInputStream vois = new ValidatingObjectInputStream(bais);
            Object obj = vois.readObject();
            vois.close();
            
            System.out.println("Safely deserialized object: " + obj.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Apache Commons SerializationUtils with validation
    public void good_case_2(HttpServletRequest request) {
        try {
            byte[] serializedData = Base64.getDecoder().decode(request.getParameter("data"));
            
            // Validate before deserializing
            if (isValidSerializedData(serializedData)) {
                // ok: java-untrusted-load-exp
                Object obj = SerializationUtils.deserialize(serializedData);
                System.out.println("Safely deserialized object: " + obj.toString());
            } else {
                System.out.println("Invalid serialized data detected");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private boolean isValidSerializedData(byte[] data) {
        // Implement validation logic here
        // This could check for magic bytes, length, etc.
        return data.length > 8 && data[0] == (byte)0xac && data[1] == (byte)0xed;
    }

    // XStream with security framework
    public void good_case_3(HttpServletRequest request) {
        try {
            String xml = request.getParameter("xml");
            XStream xstream = new XStream();
            
            // Configure XStream security framework
            // ok: java-untrusted-load-exp
            xstream.allowTypesByWildcard(new String[] {
                "com.mycompany.app.model.**"
            });
            xstream.denyTypes(new String[] {
                "java.lang.Process",
                "java.lang.ProcessBuilder",
                "java.lang.Runtime"
            });
            
            Object obj = xstream.fromXML(xml);
            System.out.println("Safely deserialized object: " + obj.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // SnakeYAML with SafeConstructor
    public void good_case_4(HttpServletRequest request) {
        try {
            String yamlStr = request.getParameter("yaml");
            
            // ok: java-untrusted-load-exp
            Yaml yaml = new Yaml(new org.yaml.snakeyaml.constructor.SafeConstructor());
            Object obj = yaml.load(yamlStr);
            
            System.out.println("Safely deserialized object: " + obj.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Jackson ObjectMapper with security features
    public void good_case_5(HttpServletRequest request) {
        try {
            String json = request.getParameter("json");
            ObjectMapper mapper = new ObjectMapper();
            
            // Disable polymorphic type handling
            // ok: java-untrusted-load-exp
            mapper.disableDefaultTyping();
            mapper.activateDefaultTyping(mapper.getPolymorphicTypeValidator(), 
                                        ObjectMapper.DefaultTyping.NONE);
            
            Object obj = mapper.readValue(json, SafeDataClass.class);
            System.out.println("Safely deserialized object: " + obj.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    static class SafeDataClass {
        private String data;
        public String getData() { return data; }
        public void setData(String data) { this.data = data; }
    }

    // Kryo with registration required
    public void good_case_6(HttpServletRequest request) {
        try {
            byte[] serializedData = Base64.getDecoder().decode(request.getParameter("data"));
            Kryo kryo = new Kryo();
            
            // Require explicit class registration for security
            // ok: java-untrusted-load-exp
            kryo.setRegistrationRequired(true);
            kryo.register(String.class);
            kryo.register(Integer.class);
            kryo.register(java.util.ArrayList.class);
            
            Input input = new Input(serializedData);
            Object obj = kryo.readClassAndObject(input);
            input.close();
            
            System.out.println("Safely deserialized object: " + obj.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Spring HttpInvokerServiceExporter with custom ClassLoader
    public void good_case_7(HttpServletRequest request, HttpServletResponse response) {
        try {
            HttpInvokerServiceExporter exporter = new HttpInvokerServiceExporter() {
                // Override to use a secure ClassLoader
                @Override
                protected ClassLoader getBeanClassLoader() {
                    // ok: java-untrusted-load-exp
                    return new RestrictedClassLoader();
                }
            };
            
            exporter.setServiceInterface(Runnable.class);
            exporter.setService(new Runnable() {
                public void run() {
                    System.out.println("Service running");
                }
            });
            exporter.afterPropertiesSet();
            exporter.handleRequest(request, response);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    static class RestrictedClassLoader extends ClassLoader {
        @Override
        public Class<?> loadClass(String name) throws ClassNotFoundException {
            if (name.startsWith("java.util.") || name.startsWith("java.lang.String")) {
                return super.loadClass(name);
            }
            throw new ClassNotFoundException("Restricted class: " + name);
        }
    }

    // JBoss RESTEasy with validation
    public void good_case_8(HttpServletRequest request) {
        try {
            byte[] serializedData = IOUtils.toByteArray(request.getInputStream());
            
            // Validate serialized data before processing
            if (isSerializedObjectSafe(serializedData)) {
                SerializableProvider provider = new SerializableProvider();
                ByteArrayInputStream bais = new ByteArrayInputStream(serializedData);
                
                // ok: java-untrusted-load-exp
                Object obj = provider.readFrom(SafeDataClass.class, null, null, null, null, bais);
                System.out.println("Safely deserialized object: " + obj.toString());
            } else {
                System.out.println("Potentially malicious serialized data detected");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private boolean isSerializedObjectSafe(byte[] data) {
        // Implement validation logic
        try {
            ByteArrayInputStream bais = new ByteArrayInputStream(data);
            ObjectStreamClass osc = ObjectStreamClass.lookup(SafeDataClass.class);
            return data.length < 10000 && data[0] == (byte)0xac && data[1] == (byte)0xed;
        } catch (Exception e) {
            return false;
        }
    }

    // Spring RMI Service Exporter with safe alternative
    public void good_case_9(HttpServletRequest request) {
        try {
            // Instead of deserializing from request, use a factory to create a safe instance
            String serviceType = request.getParameter("serviceType");
            
            // ok: java-untrusted-load-exp
            Object service = createSafeService(serviceType);
            
            RmiServiceExporter exporter = new RmiServiceExporter();
            exporter.setService(service);
            exporter.afterPropertiesSet();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private Object createSafeService(String type) {
        // Factory method that creates safe service instances based on a string identifier
        if ("calculator".equals(type)) {
            return new CalculatorService();
        } else if ("printer".equals(type)) {
            return new PrinterService();
        }
        return new DefaultService();
    }
    
    static class CalculatorService {}
    static class PrinterService {}
    static class DefaultService {}

    // Custom ObjectInputStream with strict validation
    public void good_case_10(HttpServletRequest request) {
        try {
            byte[] serializedData = Base64.getDecoder().decode(request.getParameter("data"));
            ByteArrayInputStream bais = new ByteArrayInputStream(serializedData);
            
            // Custom ObjectInputStream with strict validation
            class StrictObjectInputStream extends ObjectInputStream {
                private static final String[] BLOCKED_CLASSES = {
                    "java.lang.ProcessBuilder",
                    "java.lang.Runtime",
                    "java.lang.System",
                    "java.net.Socket",
                    "org.apache.commons.collections.functors",
                    "org.apache.commons.collections4.functors",
                    "com.sun.jndi.rmi"
                };
                
                public StrictObjectInputStream(InputStream in) throws IOException {
                    super(in);
                }
                
                @Override
                protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
                    String className = desc.getName();
                    
                    // Check against blocklist
                    for (String blocked : BLOCKED_CLASSES) {
                        if (className.startsWith(blocked)) {
                            throw new ClassNotFoundException("Security violation: " + className);
                        }
                    }
                    
                    // ok: java-untrusted-load-exp
                    return super.resolveClass(desc);
                }
            }
            
            StrictObjectInputStream sois = new StrictObjectInputStream(bais);
            Object obj = sois.readObject();
            sois.close();
            
            System.out.println("Safely deserialized object: " + obj.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Redis Jedis with JSON alternative
    public void good_case_11(HttpServletRequest request) {
        try {
            String key = request.getParameter("key");
            Jedis jedis = new Jedis("localhost");
            String jsonData = jedis.get(key);
            
            // Use JSON parsing instead of Java deserialization
            ObjectMapper mapper = new ObjectMapper();
            // ok: java-untrusted-load-exp
            SafeDataClass obj = mapper.readValue(jsonData, SafeDataClass.class);
            
            System.out.println("Safely parsed object from Redis: " + obj.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Apache HTTP Client with JSON parsing
    public void good_case_12(HttpServletRequest request) {
        try {
            String url = request.getParameter("url");
            CloseableHttpClient httpClient = HttpClients.createDefault();
            HttpPost httpPost = new HttpPost(url);
            
            org.apache.http.HttpResponse response = httpClient.execute(httpPost);
            String jsonData = IOUtils.toString(response.getEntity().getContent(), "UTF-8");
            
            // Use JSON parsing instead of Java deserialization
            ObjectMapper mapper = new ObjectMapper();
            // ok: java-untrusted-load-exp
            SafeDataClass obj = mapper.readValue(jsonData, SafeDataClass.class);
            
            System.out.println("Safely parsed object from HTTP response: " + obj.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Spring RestTemplate with safe deserialization
    public void good_case_13(HttpServletRequest request) {
        try {
            String url = request.getParameter("url");
            RestTemplate restTemplate = new RestTemplate();
            
            // Use RestTemplate's built-in JSON deserialization to a specific class
            // ok: java-untrusted-load-exp
            SafeDataClass obj = restTemplate.getForObject(url, SafeDataClass.class);
            
            System.out.println("Safely deserialized object from RestTemplate: " + obj.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Gson with type safety
    public void good_case_14(HttpServletRequest request) {
        try {
            String json = request.getParameter("json");
            Gson gson = new Gson();
            
            // Use type-safe deserialization to a specific class
            // ok: java-untrusted-load-exp
            SafeDataClass obj = gson.fromJson(json, SafeDataClass.class);
            
            System.out.println("Safely deserialized object: " + obj.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // JAXB with secure configuration
    public void good_case_15(HttpServletRequest request) {
        try {
            String xml = request.getParameter("xml");
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            
            // Configure factory with secure settings
            // ok: java-untrusted-load-exp
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setXIncludeAware(false);
            factory.setExpandEntityReferences(false);
            
            factory.newDocumentBuilder().parse(new ByteArrayInputStream(xml.getBytes()));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
// {/fact}