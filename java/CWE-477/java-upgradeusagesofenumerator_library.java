import java.util.*;
import java.util.concurrent.*;
import java.io.*;
import javax.servlet.http.*;
import javax.servlet.*;
import java.sql.*;
import org.apache.commons.collections.*;
import org.apache.commons.collections4.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.*;
import com.google.common.collect.*;
import java.awt.*;
import javax.swing.*;
import javax.jms.*;
import org.hibernate.*;
import javax.persistence.*;
import java.net.*;
import org.apache.http.client.*;
import org.apache.http.impl.client.*;
import org.apache.http.*;
import org.apache.http.client.methods.*;
import org.apache.commons.io.*;
import org.apache.commons.lang3.*;
import javax.xml.parsers.*;
import org.w3c.dom.*;
import org.xml.sax.*;
import java.nio.file.*;

// Security Issue: Using deprecated Enumeration class instead of modern alternatives like Iterator

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) {
    // Using Enumeration with Servlet API
    // ruleid: java-upgradeusagesofenumerator
    Enumeration<String> headerNames = request.getHeaderNames();
    while (headerNames.hasMoreElements()) {
        String headerName = headerNames.nextElement();
        System.out.println(headerName + ": " + request.getHeader(headerName));
    }
}

public void bad_case_2(HttpServletRequest request) {
    // Using Enumeration with Servlet API for parameters
    String queryParam = request.getParameter("query");
    // ruleid: java-upgradeusagesofenumerator
    Enumeration<String> paramNames = request.getParameterNames();
    while (paramNames.hasMoreElements()) {
        String paramName = paramNames.nextElement();
        System.out.println(paramName + ": " + request.getParameter(paramName));
    }
}

public void bad_case_3() {
    // Using Enumeration with Vector (legacy collection)
    Vector<String> vector = new Vector<>();
    vector.add("item1");
    vector.add("item2");
    
    // ruleid: java-upgradeusagesofenumerator
    Enumeration<String> elements = vector.elements();
    while (elements.hasMoreElements()) {
        System.out.println(elements.nextElement());
    }
}

public void bad_case_4() {
    // Using Enumeration with Hashtable (legacy collection)
    Hashtable<String, String> hashtable = new Hashtable<>();
    hashtable.put("key1", "value1");
    hashtable.put("key2", "value2");
    
    // ruleid: java-upgradeusagesofenumerator
    Enumeration<String> keys = hashtable.keys();
    while (keys.hasMoreElements()) {
        String key = keys.nextElement();
        System.out.println(key + ": " + hashtable.get(key));
    }
}

public void bad_case_5(ServletContext servletContext) {
    // Using Enumeration with ServletContext
    String initParam = servletContext.getInitParameter("config");
    
    // ruleid: java-upgradeusagesofenumerator
    Enumeration<String> initParamNames = servletContext.getInitParameterNames();
    while (initParamNames.hasMoreElements()) {
        String paramName = initParamNames.nextElement();
        System.out.println(paramName + ": " + servletContext.getInitParameter(paramName));
    }
}

public void bad_case_6(HttpSession session) {
    // Using Enumeration with HttpSession
    // ruleid: java-upgradeusagesofenumerator
    Enumeration<String> attributeNames = session.getAttributeNames();
    while (attributeNames.hasMoreElements()) {
        String attributeName = attributeNames.nextElement();
        System.out.println(attributeName + ": " + session.getAttribute(attributeName));
    }
}

public void bad_case_7() {
    // Using Enumeration with StringTokenizer
    StringTokenizer tokenizer = new StringTokenizer("This is a test string", " ");
    
    // ruleid: java-upgradeusagesofenumerator
    Enumeration<?> tokens = tokenizer.asEnumeration();
    while (tokens.hasMoreElements()) {
        System.out.println(tokens.nextElement());
    }
}

public void bad_case_8() {
    // Using Enumeration with Properties
    Properties properties = System.getProperties();
    
    // ruleid: java-upgradeusagesofenumerator
    Enumeration<?> propertyNames = properties.propertyNames();
    while (propertyNames.hasMoreElements()) {
        String propertyName = (String) propertyNames.nextElement();
        System.out.println(propertyName + ": " + properties.getProperty(propertyName));
    }
}

public void bad_case_9() {
    try {
        // Using Enumeration with NetworkInterface
        // ruleid: java-upgradeusagesofenumerator
        Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();
        while (networkInterfaces.hasMoreElements()) {
            NetworkInterface networkInterface = networkInterfaces.nextElement();
            System.out.println("Interface: " + networkInterface.getName());
        }
    } catch (SocketException e) {
        e.printStackTrace();
    }
}

public void bad_case_10(JarFile jarFile) {
    try {
        // Using Enumeration with JarFile entries
        // ruleid: java-upgradeusagesofenumerator
        Enumeration<JarEntry> entries = jarFile.entries();
        while (entries.hasMoreElements()) {
            JarEntry entry = entries.nextElement();
            System.out.println("JAR entry: " + entry.getName());
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_11() {
    // Using Enumeration with Dictionary
    Dictionary<String, Integer> dictionary = new Hashtable<>();
    dictionary.put("one", 1);
    dictionary.put("two", 2);
    
    // ruleid: java-upgradeusagesofenumerator
    Enumeration<String> keys = dictionary.keys();
    while (keys.hasMoreElements()) {
        String key = keys.nextElement();
        System.out.println(key + ": " + dictionary.get(key));
    }
}

public void bad_case_12(ZipFile zipFile) {
    try {
        // Using Enumeration with ZipFile entries
        // ruleid: java-upgradeusagesofenumerator
        Enumeration<? extends ZipEntry> entries = zipFile.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            System.out.println("ZIP entry: " + entry.getName());
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_13() {
    // Using Collections.enumeration() method
    List<String> list = Arrays.asList("item1", "item2", "item3");
    
    // ruleid: java-upgradeusagesofenumerator
    Enumeration<String> enumeration = Collections.enumeration(list);
    while (enumeration.hasMoreElements()) {
        System.out.println(enumeration.nextElement());
    }
}

public void bad_case_14(HttpServletRequest request) {
    // Using Enumeration with ServletRequest
    // ruleid: java-upgradeusagesofenumerator
    Enumeration<String> attributeNames = request.getAttributeNames();
    while (attributeNames.hasMoreElements()) {
        String attributeName = attributeNames.nextElement();
        System.out.println(attributeName + ": " + request.getAttribute(attributeName));
    }
}

public void bad_case_15() {
    // Using Enumeration with custom implementation
    Vector<Integer> numbers = new Vector<>();
    numbers.add(1);
    numbers.add(2);
    numbers.add(3);
    
    // ruleid: java-upgradeusagesofenumerator
    Enumeration<Integer> enumeration = new Enumeration<Integer>() {
        private final Iterator<Integer> iterator = numbers.iterator();
        
        @Override
        public boolean hasMoreElements() {
            return iterator.hasNext();
        }
        
        @Override
        public Integer nextElement() {
            return iterator.next();
        }
    };
    
    while (enumeration.hasMoreElements()) {
        System.out.println(enumeration.nextElement());
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) {
    // Using Iterator with Servlet API instead of Enumeration
    // ok: java-upgradeusagesofenumerator
    Iterator<String> headerNames = Collections.list(request.getHeaderNames()).iterator();
    while (headerNames.hasNext()) {
        String headerName = headerNames.next();
        System.out.println(headerName + ": " + request.getHeader(headerName));
    }
}

public void good_case_2(HttpServletRequest request) {
    // Using modern for-each loop with Servlet API parameters
    // ok: java-upgradeusagesofenumerator
    List<String> paramNames = Collections.list(request.getParameterNames());
    for (String paramName : paramNames) {
        System.out.println(paramName + ": " + request.getParameter(paramName));
    }
}

public void good_case_3() {
    // Using Iterator with ArrayList instead of Vector+Enumeration
    // ok: java-upgradeusagesofenumerator
    List<String> list = new ArrayList<>();
    list.add("item1");
    list.add("item2");
    
    Iterator<String> iterator = list.iterator();
    while (iterator.hasNext()) {
        System.out.println(iterator.next());
    }
}

public void good_case_4() {
    // Using HashMap and Iterator instead of Hashtable+Enumeration
    // ok: java-upgradeusagesofenumerator
    Map<String, String> map = new HashMap<>();
    map.put("key1", "value1");
    map.put("key2", "value2");
    
    for (Map.Entry<String, String> entry : map.entrySet()) {
        System.out.println(entry.getKey() + ": " + entry.getValue());
    }
}

public void good_case_5(ServletContext servletContext) {
    // Using modern for-each loop with ServletContext parameters
    // ok: java-upgradeusagesofenumerator
    List<String> initParamNames = Collections.list(servletContext.getInitParameterNames());
    for (String paramName : initParamNames) {
        System.out.println(paramName + ": " + servletContext.getInitParameter(paramName));
    }
}

public void good_case_6(HttpSession session) {
    // Using modern for-each loop with HttpSession attributes
    // ok: java-upgradeusagesofenumerator
    List<String> attributeNames = Collections.list(session.getAttributeNames());
    for (String attributeName : attributeNames) {
        System.out.println(attributeName + ": " + session.getAttribute(attributeName));
    }
}

public void good_case_7() {
    // Using Stream API instead of StringTokenizer+Enumeration
    // ok: java-upgradeusagesofenumerator
    String text = "This is a test string";
    Arrays.stream(text.split(" "))
          .forEach(System.out::println);
}

public void good_case_8() {
    // Using modern for-each loop with Properties
    // ok: java-upgradeusagesofenumerator
    Properties properties = System.getProperties();
    for (String propertyName : properties.stringPropertyNames()) {
        System.out.println(propertyName + ": " + properties.getProperty(propertyName));
    }
}

public void good_case_9() {
    try {
        // Using Stream API with NetworkInterface
        // ok: java-upgradeusagesofenumerator
        NetworkInterface.getNetworkInterfaces()
                        .asIterator()
                        .forEachRemaining(networkInterface -> 
                            System.out.println("Interface: " + networkInterface.getName()));
    } catch (SocketException e) {
        e.printStackTrace();
    }
}

public void good_case_10(JarFile jarFile) {
    try {
        // Using Stream API with JarFile entries
        // ok: java-upgradeusagesofenumerator
        jarFile.stream()
               .forEach(entry -> System.out.println("JAR entry: " + entry.getName()));
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_11() {
    // Using HashMap instead of Dictionary/Hashtable
    // ok: java-upgradeusagesofenumerator
    Map<String, Integer> map = new HashMap<>();
    map.put("one", 1);
    map.put("two", 2);
    
    for (String key : map.keySet()) {
        System.out.println(key + ": " + map.get(key));
    }
}

public void good_case_12(ZipFile zipFile) {
    try {
        // Using Stream API with ZipFile entries
        // ok: java-upgradeusagesofenumerator
        zipFile.stream()
               .forEach(entry -> System.out.println("ZIP entry: " + entry.getName()));
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_13() {
    // Using List directly instead of Collections.enumeration()
    // ok: java-upgradeusagesofenumerator
    List<String> list = Arrays.asList("item1", "item2", "item3");
    
    for (String item : list) {
        System.out.println(item);
    }
}

public void good_case_14(HttpServletRequest request) {
    // Using modern for-each loop with ServletRequest attributes
    // ok: java-upgradeusagesofenumerator
    List<String> attributeNames = Collections.list(request.getAttributeNames());
    for (String attributeName : attributeNames) {
        System.out.println(attributeName + ": " + request.getAttribute(attributeName));
    }
}

public void good_case_15() {
    // Using Iterator directly instead of custom Enumeration implementation
    // ok: java-upgradeusagesofenumerator
    List<Integer> numbers = new ArrayList<>();
    numbers.add(1);
    numbers.add(2);
    numbers.add(3);
    
    Iterator<Integer> iterator = numbers.iterator();
    while (iterator.hasNext()) {
        System.out.println(iterator.next());
    }
}