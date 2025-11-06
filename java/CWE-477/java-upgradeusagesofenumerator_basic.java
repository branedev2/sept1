import java.util.*;
import java.io.*;
import java.sql.*;
import java.net.*;

public class EnumeratorUsageExamples {

    // True Positives (Vulnerable/Insecure Code)
    
// {fact rule=deprecated-method@v1.0 defects=1}
    public void bad_case_1() {
        Vector<String> v = new Vector<>();
        v.add("one");
        v.add("two");
        v.add("three");
        
        // ruleid: java-upgradeusagesofenumerator
        Enumeration<String> e = v.elements();
        while (e.hasMoreElements()) {
            System.out.println(e.nextElement());
        }
    }
    
    public void bad_case_2() {
        Hashtable<String, Integer> scores = new Hashtable<>();
        scores.put("Alice", 95);
        scores.put("Bob", 87);
        scores.put("Charlie", 92);
        
        // ruleid: java-upgradeusagesofenumerator
        Enumeration<String> keys = scores.keys();
        while (keys.hasMoreElements()) {
            String key = keys.nextElement();
            System.out.println(key + ": " + scores.get(key));
        }
    }
    
    public void bad_case_3() {
        Properties props = System.getProperties();
        
        // ruleid: java-upgradeusagesofenumerator
        Enumeration<?> propertyNames = props.propertyNames();
        while (propertyNames.hasMoreElements()) {
            String name = (String) propertyNames.nextElement();
            System.out.println(name + " = " + props.getProperty(name));
        }
    }
    
    public void bad_case_4() {
        try {
            URL url = new URL("https://example.com");
            URLConnection conn = url.openConnection();
            
            // ruleid: java-upgradeusagesofenumerator
            Enumeration<String> headerFields = Collections.enumeration(conn.getHeaderFields().keySet());
            while (headerFields.hasMoreElements()) {
                String headerName = headerFields.nextElement();
                System.out.println(headerName + ": " + conn.getHeaderField(headerName));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_5() {
        Vector<Integer> numbers = new Vector<>();
        for (int i = 1; i <= 10; i++) {
            numbers.add(i);
        }
        
        // ruleid: java-upgradeusagesofenumerator
        Enumeration<Integer> enumeration = numbers.elements();
        int sum = 0;
        while (enumeration.hasMoreElements()) {
            sum += enumeration.nextElement();
        }
        System.out.println("Sum: " + sum);
    }
    
    public void bad_case_6() {
        try {
            ServletContext context = getServletContext(); // Assume this is available
            
            // ruleid: java-upgradeusagesofenumerator
            Enumeration<String> initParams = context.getInitParameterNames();
            while (initParams.hasMoreElements()) {
                String param = initParams.nextElement();
                System.out.println(param + " = " + context.getInitParameter(param));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_7() {
        try {
            HttpServletRequest request = getRequest(); // Assume this is available
            
            // ruleid: java-upgradeusagesofenumerator
            Enumeration<String> headerNames = request.getHeaderNames();
            while (headerNames.hasMoreElements()) {
                String header = headerNames.nextElement();
                System.out.println(header + ": " + request.getHeader(header));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_8() {
        Dictionary<String, Double> prices = new Hashtable<>();
        prices.put("Apple", 1.99);
        prices.put("Banana", 0.99);
        prices.put("Orange", 2.49);
        
        // ruleid: java-upgradeusagesofenumerator
        Enumeration<String> keys = prices.keys();
        double total = 0;
        while (keys.hasMoreElements()) {
            String fruit = keys.nextElement();
            total += prices.get(fruit);
        }
        System.out.println("Total price: " + total);
    }
    
    public void bad_case_9() {
        StringTokenizer tokenizer = new StringTokenizer("Java,Python,C++,JavaScript", ",");
        
        // ruleid: java-upgradeusagesofenumerator
        Enumeration<?> tokens = tokenizer;
        while (tokens.hasMoreElements()) {
            System.out.println(tokens.nextElement());
        }
    }
    
    public void bad_case_10() {
        try {
            HttpSession session = getSession(); // Assume this is available
            
            // ruleid: java-upgradeusagesofenumerator
            Enumeration<String> attributeNames = session.getAttributeNames();
            while (attributeNames.hasMoreElements()) {
                String name = attributeNames.nextElement();
                System.out.println(name + ": " + session.getAttribute(name));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_11() {
        Vector<String> languages = new Vector<>();
        languages.add("Java");
        languages.add("Python");
        languages.add("C++");
        
        // Custom method that uses Enumeration
        processLanguages(languages);
    }
    
    private void processLanguages(Vector<String> langs) {
        // ruleid: java-upgradeusagesofenumerator
        Enumeration<String> enumeration = langs.elements();
        while (enumeration.hasMoreElements()) {
            String lang = enumeration.nextElement();
            System.out.println("Processing: " + lang);
        }
    }
    
    public void bad_case_12() {
        Hashtable<Integer, String> employees = new Hashtable<>();
        employees.put(101, "John");
        employees.put(102, "Mary");
        employees.put(103, "Steve");
        
        // ruleid: java-upgradeusagesofenumerator
        for (Enumeration<Integer> e = employees.keys(); e.hasMoreElements();) {
            Integer id = e.nextElement();
            System.out.println("ID: " + id + ", Name: " + employees.get(id));
        }
    }
    
    public void bad_case_13() {
        try {
            Class<?> cls = Class.forName("java.util.Vector");
            ClassLoader loader = cls.getClassLoader();
            
            // ruleid: java-upgradeusagesofenumerator
            Enumeration<URL> resources = loader.getResources("META-INF/MANIFEST.MF");
            while (resources.hasMoreElements()) {
                URL url = resources.nextElement();
                System.out.println("Resource: " + url);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_14() {
        Vector<Double> measurements = new Vector<>();
        measurements.add(10.5);
        measurements.add(11.2);
        measurements.add(9.8);
        
        // ruleid: java-upgradeusagesofenumerator
        Enumeration<Double> enumeration = measurements.elements();
        double min = Double.MAX_VALUE;
        while (enumeration.hasMoreElements()) {
            double value = enumeration.nextElement();
            if (value < min) {
                min = value;
            }
        }
        System.out.println("Minimum value: " + min);
    }
    
    public void bad_case_15() {
        try {
            Properties systemProps = System.getProperties();
            FileOutputStream out = new FileOutputStream("system.properties");
            
            // ruleid: java-upgradeusagesofenumerator
            Enumeration<?> names = systemProps.propertyNames();
            Properties filteredProps = new Properties();
            while (names.hasMoreElements()) {
                String name = (String) names.nextElement();
                if (name.startsWith("java.")) {
                    filteredProps.setProperty(name, systemProps.getProperty(name));
                }
            }
            filteredProps.store(out, "Java Properties");
            out.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // True Negatives (Safe/Secure Code)
    
    public void good_case_1() {
        Vector<String> v = new Vector<>();
        v.add("one");
        v.add("two");
        v.add("three");
        
        // ok: java-upgradeusagesofenumerator
        Iterator<String> iterator = v.iterator();
        while (iterator.hasNext()) {
            System.out.println(iterator.next());
        }
    }
    
    public void good_case_2() {
        Hashtable<String, Integer> scores = new Hashtable<>();
        scores.put("Alice", 95);
        scores.put("Bob", 87);
        scores.put("Charlie", 92);
        
        // ok: java-upgradeusagesofenumerator
        for (Map.Entry<String, Integer> entry : scores.entrySet()) {
            System.out.println(entry.getKey() + ": " + entry.getValue());
        }
    }
    
    public void good_case_3() {
        Properties props = System.getProperties();
        
        // ok: java-upgradeusagesofenumerator
        for (String name : props.stringPropertyNames()) {
            System.out.println(name + " = " + props.getProperty(name));
        }
    }
    
    public void good_case_4() {
        try {
            URL url = new URL("https://example.com");
            URLConnection conn = url.openConnection();
            
            // ok: java-upgradeusagesofenumerator
            for (String headerName : conn.getHeaderFields().keySet()) {
                if (headerName != null) {
                    System.out.println(headerName + ": " + conn.getHeaderField(headerName));
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_5() {
        Vector<Integer> numbers = new Vector<>();
        for (int i = 1; i <= 10; i++) {
            numbers.add(i);
        }
        
        // ok: java-upgradeusagesofenumerator
        int sum = 0;
        for (Integer num : numbers) {
            sum += num;
        }
        System.out.println("Sum: " + sum);
    }
    
    public void good_case_6() {
        try {
            ServletContext context = getServletContext(); // Assume this is available
            
            // ok: java-upgradeusagesofenumerator
            List<String> paramNames = Collections.list(context.getInitParameterNames());
            for (String param : paramNames) {
                System.out.println(param + " = " + context.getInitParameter(param));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_7() {
        try {
            HttpServletRequest request = getRequest(); // Assume this is available
            
            // ok: java-upgradeusagesofenumerator
            List<String> headerNames = Collections.list(request.getHeaderNames());
            for (String header : headerNames) {
                System.out.println(header + ": " + request.getHeader(header));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_8() {
        Map<String, Double> prices = new HashMap<>();
        prices.put("Apple", 1.99);
        prices.put("Banana", 0.99);
        prices.put("Orange", 2.49);
        
        // ok: java-upgradeusagesofenumerator
        double total = 0;
        for (Map.Entry<String, Double> entry : prices.entrySet()) {
            total += entry.getValue();
        }
        System.out.println("Total price: " + total);
    }
    
    public void good_case_9() {
        String text = "Java,Python,C++,JavaScript";
        
        // ok: java-upgradeusagesofenumerator
        String[] tokens = text.split(",");
        for (String token : tokens) {
            System.out.println(token);
        }
    }
    
    public void good_case_10() {
        try {
            HttpSession session = getSession(); // Assume this is available
            
            // ok: java-upgradeusagesofenumerator
            List<String> attributeNames = Collections.list(session.getAttributeNames());
            for (String name : attributeNames) {
                System.out.println(name + ": " + session.getAttribute(name));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_11() {
        List<String> languages = new ArrayList<>();
        languages.add("Java");
        languages.add("Python");
        languages.add("C++");
        
        // Custom method that uses Iterator
        processLanguagesModern(languages);
    }
    
    private void processLanguagesModern(List<String> langs) {
        // ok: java-upgradeusagesofenumerator
        for (String lang : langs) {
            System.out.println("Processing: " + lang);
        }
    }
    
    public void good_case_12() {
        Map<Integer, String> employees = new HashMap<>();
        employees.put(101, "John");
        employees.put(102, "Mary");
        employees.put(103, "Steve");
        
        // ok: java-upgradeusagesofenumerator
        for (Integer id : employees.keySet()) {
            System.out.println("ID: " + id + ", Name: " + employees.get(id));
        }
    }
    
    public void good_case_13() {
        try {
            Class<?> cls = Class.forName("java.util.Vector");
            ClassLoader loader = cls.getClassLoader();
            
            // ok: java-upgradeusagesofenumerator
            List<URL> resourceList = Collections.list(loader.getResources("META-INF/MANIFEST.MF"));
            for (URL url : resourceList) {
                System.out.println("Resource: " + url);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_14() {
        List<Double> measurements = new ArrayList<>();
        measurements.add(10.5);
        measurements.add(11.2);
        measurements.add(9.8);
        
        // ok: java-upgradeusagesofenumerator
        double min = Collections.min(measurements);
        System.out.println("Minimum value: " + min);
    }
    
    public void good_case_15() {
        try {
            Properties systemProps = System.getProperties();
            FileOutputStream out = new FileOutputStream("system.properties");
            
            // ok: java-upgradeusagesofenumerator
            Properties filteredProps = new Properties();
            for (String name : systemProps.stringPropertyNames()) {
                if (name.startsWith("java.")) {
                    filteredProps.setProperty(name, systemProps.getProperty(name));
                }
            }
            filteredProps.store(out, "Java Properties");
            out.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Helper methods to avoid compilation errors
    private ServletContext getServletContext() { return null; }
    private HttpServletRequest getRequest() { return null; }
    private HttpSession getSession() { return null; }
}
// {/fact}

// Interfaces to avoid compilation errors
interface ServletContext {
    Enumeration<String> getInitParameterNames();
    String getInitParameter(String name);
}

interface HttpServletRequest {
    Enumeration<String> getHeaderNames();
    String getHeader(String name);
}

interface HttpSession {
    Enumeration<String> getAttributeNames();
    Object getAttribute(String name);
}