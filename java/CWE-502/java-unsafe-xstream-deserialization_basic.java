import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.io.xml.DomDriver;
import com.thoughtworks.xstream.security.AnyTypePermission;
import com.thoughtworks.xstream.security.NoTypePermission;
import com.thoughtworks.xstream.security.TypePermission;
import com.thoughtworks.xstream.security.WildcardTypePermission;
import com.thoughtworks.xstream.security.ExplicitTypePermission;
import com.thoughtworks.xstream.converters.reflection.PureJavaReflectionProvider;
import com.thoughtworks.xstream.mapper.MapperWrapper;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.HashMap;

class Person {
    private String name;
    private int age;
    
    public Person() {}
    
    public Person(String name, int age) {
        this.name = name;
        this.age = age;
    }
    
    public String getName() {
        return name;
    }
    
    public int getAge() {
        return age;
    }
}

public class XStreamVulnerabilityExamples extends HttpServlet {

    // True Positive Examples (Vulnerable Code)
    
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String xmlData = request.getParameter("xml");
        XStream xstream = new XStream();
        // ruleid: java-unsafe-xstream-deserialization
        Object obj = xstream.fromXML(xmlData);
        response.getWriter().println("Deserialized object: " + obj);
    }
    
    public void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String xmlData = request.getHeader("X-XML-Data");
        XStream xstream = new XStream(new DomDriver());
        // ruleid: java-unsafe-xstream-deserialization
        Person person = (Person) xstream.fromXML(xmlData);
        response.getWriter().println("Hello, " + person.getName());
    }
    
    public void bad_case_3(HttpServletRequest request, HttpServletResponse response) throws IOException {
        InputStream inputStream = request.getInputStream();
        XStream xstream = new XStream();
        xstream.alias("person", Person.class);
        // ruleid: java-unsafe-xstream-deserialization
        Person person = (Person) xstream.fromXML(inputStream);
        response.getWriter().println("Person age: " + person.getAge());
    }
    
    public void bad_case_4(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String xmlData = request.getParameter("data");
        XStream xstream = new XStream();
        xstream.setMode(XStream.NO_REFERENCES);
        // ruleid: java-unsafe-xstream-deserialization
        List<Person> people = (List<Person>) xstream.fromXML(xmlData);
        response.getWriter().println("Number of people: " + people.size());
    }
    
    public void bad_case_5(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String xmlUrl = request.getParameter("xmlUrl");
        URL url = new URL(xmlUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        InputStream inputStream = connection.getInputStream();
        
        XStream xstream = new XStream();
        // ruleid: java-unsafe-xstream-deserialization
        Object result = xstream.fromXML(inputStream);
        response.getWriter().println("Result: " + result);
    }
    
    public void bad_case_6(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String xmlData = request.getParameter("config");
        XStream xstream = new XStream(new PureJavaReflectionProvider());
        // ruleid: java-unsafe-xstream-deserialization
        HashMap<String, Object> config = (HashMap<String, Object>) xstream.fromXML(xmlData);
        response.getWriter().println("Config loaded with " + config.size() + " entries");
    }
    
    public void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String xmlData = request.getReader().readLine();
        XStream xstream = new XStream();
        xstream.allowTypesByWildcard(new String[]{"com.example.*"});
        // ruleid: java-unsafe-xstream-deserialization
        Object obj = xstream.fromXML(xmlData);
        response.getWriter().println("Processed: " + obj);
    }
    
    public void bad_case_8(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String xmlData = request.getParameter("userProfile");
        XStream xstream = new XStream();
        xstream.addPermission(AnyTypePermission.ANY);
        // ruleid: java-unsafe-xstream-deserialization
        Object userProfile = xstream.fromXML(xmlData);
        response.getWriter().println("User profile loaded");
    }
    
    public void bad_case_9(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String xmlData = request.getParameter("settings");
        XStream xstream = new XStream() {
            @Override
            protected MapperWrapper wrapMapper(MapperWrapper next) {
                return new MapperWrapper(next) {
                    @Override
                    public boolean shouldSerializeMember(Class definedIn, String fieldName) {
                        return definedIn != Object.class || super.shouldSerializeMember(definedIn, fieldName);
                    }
                };
            }
        };
        // ruleid: java-unsafe-xstream-deserialization
        Object settings = xstream.fromXML(xmlData);
        response.getWriter().println("Settings applied");
    }
    
    public void bad_case_10(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String xmlData = request.getParameter("data");
        StringReader reader = new StringReader(xmlData);
        XStream xstream = new XStream();
        // ruleid: java-unsafe-xstream-deserialization
        Object obj = xstream.fromXML(reader);
        response.getWriter().println("Object loaded: " + obj.getClass().getName());
    }
    
    public void bad_case_11(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String xmlData = request.getParameter("backup");
        XStream xstream = new XStream();
        xstream.ignoreUnknownElements();
        // ruleid: java-unsafe-xstream-deserialization
        Collection<?> items = (Collection<?>) xstream.fromXML(xmlData);
        response.getWriter().println("Restored " + items.size() + " items");
    }
    
    public void bad_case_12(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String xmlData = request.getParameter("template");
        XStream xstream = new XStream();
        xstream.registerConverter(new CustomConverter());
        // ruleid: java-unsafe-xstream-deserialization
        Object template = xstream.fromXML(xmlData);
        response.getWriter().println("Template loaded");
    }
    
    public void bad_case_13(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String xmlData = request.getParameter("importData");
        XStream xstream = new XStream();
        xstream.autodetectAnnotations(true);
        // ruleid: java-unsafe-xstream-deserialization
        Object importedData = xstream.fromXML(xmlData);
        response.getWriter().println("Data imported successfully");
    }
    
    public void bad_case_14(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String xmlData = request.getParameter("document");
        XStream xstream = new XStream();
        xstream.allowTypeHierarchy(Collection.class);
        // ruleid: java-unsafe-xstream-deserialization
        Object document = xstream.fromXML(xmlData);
        response.getWriter().println("Document processed");
    }
    
    public void bad_case_15(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String xmlData = request.getParameter("state");
        XStream xstream = new XStream();
        xstream.setClassLoader(Thread.currentThread().getContextClassLoader());
        // ruleid: java-unsafe-xstream-deserialization
        Object state = xstream.fromXML(xmlData);
        response.getWriter().println("State restored");
    }
    
    // True Negative Examples (Safe Code)
    
    public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String xmlData = request.getParameter("xml");
        XStream xstream = new XStream();
        xstream.addPermission(NoTypePermission.NONE);
        // ok: java-unsafe-xstream-deserialization
        xstream.allowTypesByWildcard(new String[] {"com.example.safe.*"});
        Object obj = xstream.fromXML(xmlData);
        response.getWriter().println("Deserialized object: " + obj);
    }
    
    public void good_case_2(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String xmlData = request.getHeader("X-XML-Data");
        XStream xstream = new XStream(new DomDriver());
        xstream.addPermission(NoTypePermission.NONE);
        // ok: java-unsafe-xstream-deserialization
        xstream.allowTypes(new Class[] {Person.class});
        Person person = (Person) xstream.fromXML(xmlData);
        response.getWriter().println("Hello, " + person.getName());
    }
    
    public void good_case_3(HttpServletRequest request, HttpServletResponse response) throws IOException {
        InputStream inputStream = request.getInputStream();
        XStream xstream = new XStream();
        xstream.addPermission(NoTypePermission.NONE);
        // ok: java-unsafe-xstream-deserialization
        xstream.allowTypesByWildcard(new String[] {"java.util.*"});
        xstream.allowTypes(new Class[] {Person.class});
        Person person = (Person) xstream.fromXML(inputStream);
        response.getWriter().println("Person age: " + person.getAge());
    }
    
    public void good_case_4(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String xmlData = request.getParameter("data");
        XStream xstream = new XStream();
        xstream.setMode(XStream.NO_REFERENCES);
        // ok: java-unsafe-xstream-deserialization
        xstream.addPermission(NoTypePermission.NONE);
        xstream.allowTypes(new Class[] {ArrayList.class, Person.class});
        List<Person> people = (List<Person>) xstream.fromXML(xmlData);
        response.getWriter().println("Number of people: " + people.size());
    }
    
    public void good_case_5(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String xmlUrl = request.getParameter("xmlUrl");
        URL url = new URL(xmlUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        InputStream inputStream = connection.getInputStream();
        
        XStream xstream = new XStream();
        // ok: java-unsafe-xstream-deserialization
        xstream.addPermission(NoTypePermission.NONE);
        xstream.addPermission(new ExplicitTypePermission(new Class[] {HashMap.class, String.class, Integer.class}));
        Object result = xstream.fromXML(inputStream);
        response.getWriter().println("Result: " + result);
    }
    
    public void good_case_6(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String xmlData = request.getParameter("config");
        XStream xstream = new XStream(new PureJavaReflectionProvider());
        // ok: java-unsafe-xstream-deserialization
        xstream.addPermission(NoTypePermission.NONE);
        xstream.allowTypeHierarchy(HashMap.class);
        xstream.allowTypeHierarchy(String.class);
        xstream.allowTypeHierarchy(Number.class);
        HashMap<String, Object> config = (HashMap<String, Object>) xstream.fromXML(xmlData);
        response.getWriter().println("Config loaded with " + config.size() + " entries");
    }
    
    public void good_case_7(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String xmlData = request.getReader().readLine();
        XStream xstream = new XStream();
        // ok: java-unsafe-xstream-deserialization
        xstream.addPermission(NoTypePermission.NONE);
        xstream.addPermission(new WildcardTypePermission(new String[] {"com.example.safe.**"}));
        Object obj = xstream.fromXML(xmlData);
        response.getWriter().println("Processed: " + obj);
    }
    
    public void good_case_8(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String xmlData = request.getParameter("userProfile");
        XStream xstream = new XStream();
        // ok: java-unsafe-xstream-deserialization
        xstream.addPermission(NoTypePermission.NONE);
        xstream.allowTypes(new Class[] {
            Person.class,
            ArrayList.class,
            HashMap.class,
            String.class
        });
        Object userProfile = xstream.fromXML(xmlData);
        response.getWriter().println("User profile loaded");
    }
    
    public void good_case_9(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String xmlData = request.getParameter("settings");
        XStream xstream = new XStream() {
            @Override
            protected MapperWrapper wrapMapper(MapperWrapper next) {
                return new MapperWrapper(next) {
                    @Override
                    public boolean shouldSerializeMember(Class definedIn, String fieldName) {
                        return definedIn != Object.class || super.shouldSerializeMember(definedIn, fieldName);
                    }
                };
            }
        };
        // ok: java-unsafe-xstream-deserialization
        xstream.addPermission(NoTypePermission.NONE);
        xstream.allowTypesByWildcard(new String[] {
            "java.lang.*",
            "java.util.*"
        });
        Object settings = xstream.fromXML(xmlData);
        response.getWriter().println("Settings applied");
    }
    
    public void good_case_10(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String xmlData = request.getParameter("data");
        StringReader reader = new StringReader(xmlData);
        XStream xstream = new XStream();
        // ok: java-unsafe-xstream-deserialization
        xstream.addPermission(NoTypePermission.NONE);
        xstream.allowTypeHierarchy(Collection.class);
        xstream.allowTypeHierarchy(String.class);
        xstream.allowTypeHierarchy(Number.class);
        xstream.allowTypeHierarchy(Boolean.class);
        Object obj = xstream.fromXML(reader);
        response.getWriter().println("Object loaded: " + obj.getClass().getName());
    }
    
    public void good_case_11(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String xmlData = request.getParameter("backup");
        XStream xstream = new XStream();
        xstream.ignoreUnknownElements();
        // ok: java-unsafe-xstream-deserialization
        xstream.addPermission(NoTypePermission.NONE);
        xstream.allowTypes(new Class[] {
            ArrayList.class,
            HashMap.class,
            String.class,
            Integer.class,
            Boolean.class
        });
        Collection<?> items = (Collection<?>) xstream.fromXML(xmlData);
        response.getWriter().println("Restored " + items.size() + " items");
    }
    
    public void good_case_12(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String xmlData = request.getParameter("template");
        XStream xstream = new XStream();
        // ok: java-unsafe-xstream-deserialization
        xstream.addPermission(NoTypePermission.NONE);
        xstream.allowTypesByRegExp(new String[] {
            "java\\.lang\\..*",
            "java\\.util\\..*"
        });
        xstream.registerConverter(new CustomConverter());
        Object template = xstream.fromXML(xmlData);
        response.getWriter().println("Template loaded");
    }
    
    public void good_case_13(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String xmlData = request.getParameter("importData");
        XStream xstream = new XStream();
        xstream.autodetectAnnotations(true);
        // ok: java-unsafe-xstream-deserialization
        xstream.addPermission(NoTypePermission.NONE);
        xstream.allowTypeHierarchy(Person.class);
        xstream.allowTypeHierarchy(ArrayList.class);
        Object importedData = xstream.fromXML(xmlData);
        response.getWriter().println("Data imported successfully");
    }
    
    public void good_case_14(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Instead of using XStream for untrusted data, use a safer alternative
        String jsonData = request.getParameter("document");
        // ok: java-unsafe-xstream-deserialization
        // Using a safer alternative like Jackson for untrusted data
        ObjectMapper mapper = new ObjectMapper();
        Object document = mapper.readValue(jsonData, Object.class);
        response.getWriter().println("Document processed safely");
    }
    
    public void good_case_15(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String xmlData = request.getParameter("state");
        XStream xstream = new XStream();
        // ok: java-unsafe-xstream-deserialization
        // Using XStream's security framework properly
        xstream.addPermission(NoTypePermission.NONE);
        xstream.allowTypesByWildcard(new String[] {
            "com.example.model.**"
        });
        xstream.denyTypesByWildcard(new String[] {
            "java.lang.Process",
            "java.lang.Runtime",
            "javax.script.**"
        });
        Object state = xstream.fromXML(xmlData);
        response.getWriter().println("State restored safely");
    }
    
    // Helper class for examples
    private static class CustomConverter implements Converter {
        // Implementation omitted for brevity
        public boolean canConvert(Class type) {
            return false;
        }
        
        public void marshal(Object source, HierarchicalStreamWriter writer, MarshallingContext context) {
            // Implementation omitted
        }
        
        public Object unmarshal(HierarchicalStreamReader reader, UnmarshallingContext context) {
            return null;
        }
    }
}
// {/fact}