import java.io.*;
import java.net.*;
import java.sql.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.nio.file.*;
import java.security.*;
import org.apache.http.client.*;
import org.apache.http.client.methods.*;
import org.apache.http.impl.client.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.*;
import com.amazonaws.services.lambda.*;
import com.amazonaws.services.lambda.model.*;
import com.google.cloud.functions.*;
import org.apache.commons.exec.*;
import org.apache.commons.io.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import okhttp3.*;
import retrofit2.*;
import retrofit2.http.*;
import org.hibernate.*;
import org.hibernate.query.*;
import javax.persistence.*;
import com.azure.storage.blob.*;
import com.azure.storage.blob.models.*;
import software.amazon.awssdk.services.s3.*;
import software.amazon.awssdk.services.s3.model.*;
import com.fasterxml.jackson.databind.*;
import com.google.gson.*;
import org.apache.commons.lang3.reflect.*;
import java.lang.reflect.*;

// Security Issue: Using low-level functionality bypasses the framework's security mechanisms

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) {
    try {
        String command = request.getParameter("cmd");
        // ruleid: java-avoid-use-of-unsafe-api
        Runtime.getRuntime().exec(command); // Using Runtime.exec with user input directly
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_2(HttpServletRequest request) {
    try {
        String filePath = request.getParameter("file");
        // ruleid: java-avoid-use-of-unsafe-api
        FileInputStream fis = new FileInputStream(filePath); // Direct file access with user input
        byte[] data = new byte[1024];
        fis.read(data);
        fis.close();
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_3(HttpServletRequest request) {
    try {
        String className = request.getParameter("class");
        // ruleid: java-avoid-use-of-unsafe-api
        Class<?> dynamicClass = Class.forName(className); // Dynamic class loading with user input
        Object instance = dynamicClass.newInstance();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_4(HttpServletRequest request) {
    try {
        String query = "SELECT * FROM users WHERE username='" + request.getParameter("username") + "'";
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "pass");
        // ruleid: java-avoid-use-of-unsafe-api
        Statement stmt = conn.createStatement(); // Using raw JDBC Statement with concatenated query
        ResultSet rs = stmt.executeQuery(query);
    } catch (SQLException e) {
        e.printStackTrace();
    }
}

public void bad_case_5(HttpServletRequest request, HttpServletResponse response) {
    try {
        String redirectUrl = request.getParameter("url");
        // ruleid: java-avoid-use-of-unsafe-api
        response.sendRedirect(redirectUrl); // Direct redirect with user input
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_6(HttpServletRequest request) {
    try {
        String xml = request.getParameter("data");
        // ruleid: java-avoid-use-of-unsafe-api
        javax.xml.parsers.DocumentBuilderFactory factory = javax.xml.parsers.DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
        factory.parse(new java.io.ByteArrayInputStream(xml.getBytes())); // Unsafe XML parsing
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_7(HttpServletRequest request) {
    try {
        String serializedObj = request.getParameter("object");
        byte[] data = Base64.getDecoder().decode(serializedObj);
        // ruleid: java-avoid-use-of-unsafe-api
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data)); // Unsafe deserialization
        Object obj = ois.readObject();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_8(HttpServletRequest request) {
    try {
        String methodName = request.getParameter("method");
        String className = request.getParameter("class");
        Class<?> clazz = Class.forName(className);
        // ruleid: java-avoid-use-of-unsafe-api
        Method method = clazz.getMethod(methodName); // Unsafe reflection
        method.invoke(clazz.newInstance());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_9(HttpServletRequest request) {
    try {
        String command = request.getParameter("cmd");
        // ruleid: java-avoid-use-of-unsafe-api
        ProcessBuilder pb = new ProcessBuilder(command.split(" ")); // Unsafe process execution
        pb.start();
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_10(HttpServletRequest request) {
    try {
        String script = request.getParameter("script");
        // ruleid: java-avoid-use-of-unsafe-api
        ScriptEngineManager manager = new ScriptEngineManager();
        ScriptEngine engine = manager.getEngineByName("JavaScript");
        engine.eval(script); // Unsafe script evaluation
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_11(HttpServletRequest request) {
    try {
        String command = request.getParameter("cmd");
        // ruleid: java-avoid-use-of-unsafe-api
        CommandLine cmdLine = CommandLine.parse(command); // Apache Commons Exec with user input
        DefaultExecutor executor = new DefaultExecutor();
        executor.execute(cmdLine);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_12(HttpServletRequest request) {
    try {
        String json = request.getParameter("data");
        // ruleid: java-avoid-use-of-unsafe-api
        ObjectMapper mapper = new ObjectMapper();
        mapper.enableDefaultTyping(); // Unsafe Jackson configuration
        Object obj = mapper.readValue(json, Object.class);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_13(HttpServletRequest request) {
    try {
        String functionName = request.getParameter("function");
        // ruleid: java-avoid-use-of-unsafe-api
        AWSLambdaClient lambdaClient = new AWSLambdaClient();
        InvokeRequest invokeRequest = new InvokeRequest()
            .withFunctionName(functionName) // Unsafe AWS Lambda invocation
            .withPayload("{}");
        lambdaClient.invoke(invokeRequest);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_14(HttpServletRequest request) {
    try {
        String password = request.getParameter("password");
        String salt = "fixed-salt";
        // ruleid: java-avoid-use-of-unsafe-api
        MessageDigest md = MessageDigest.getInstance("MD5"); // Weak hashing algorithm
        md.update(salt.getBytes());
        byte[] bytes = md.digest(password.getBytes());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_15(HttpServletRequest request) {
    try {
        String hql = "FROM User WHERE username = '" + request.getParameter("username") + "'";
        Session session = HibernateUtil.getSessionFactory().openSession();
        // ruleid: java-avoid-use-of-unsafe-api
        Query query = session.createQuery(hql); // Raw HQL query with string concatenation
        List results = query.list();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) {
    try {
        List<String> command = new ArrayList<>();
        command.add("ls");
        command.add("-l");
        command.add(request.getParameter("dir")); // Input is just a parameter, not the command itself
        
        // ok: java-avoid-use-of-unsafe-api
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);
        Process process = pb.start();
        
        // Process output safely
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                // Process output
            }
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_2(HttpServletRequest request) {
    try {
        String filePath = request.getParameter("file");
        File file = new File(filePath);
        
        // Validate path is within allowed directory
        String canonicalPath = file.getCanonicalPath();
        String allowedDir = new File("/safe/directory").getCanonicalPath();
        
        if (!canonicalPath.startsWith(allowedDir)) {
            throw new SecurityException("Access denied");
        }
        
        // ok: java-avoid-use-of-unsafe-api
        Path path = Paths.get(canonicalPath);
        byte[] data = Files.readAllBytes(path);
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_3(HttpServletRequest request) {
    try {
        String className = request.getParameter("class");
        // Whitelist of allowed classes
        Map<String, Class<?>> allowedClasses = new HashMap<>();
        allowedClasses.put("java.util.ArrayList", ArrayList.class);
        allowedClasses.put("java.util.HashMap", HashMap.class);
        
        // ok: java-avoid-use-of-unsafe-api
        Class<?> clazz = allowedClasses.get(className);
        if (clazz != null) {
            Object instance = clazz.newInstance();
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_4(HttpServletRequest request) {
    try {
        String username = request.getParameter("username");
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "pass");
        
        // ok: java-avoid-use-of-unsafe-api
        PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE username = ?");
        pstmt.setString(1, username);
        ResultSet rs = pstmt.executeQuery();
    } catch (SQLException e) {
        e.printStackTrace();
    }
}

public void good_case_5(HttpServletRequest request, HttpServletResponse response) {
    try {
        String redirectUrl = request.getParameter("url");
        // Whitelist of allowed domains
        List<String> allowedDomains = Arrays.asList("example.com", "trusted-site.org");
        
        URL url = new URL(redirectUrl);
        String host = url.getHost();
        
        boolean allowed = false;
        for (String domain : allowedDomains) {
            if (host.endsWith(domain)) {
                allowed = true;
                break;
            }
        }
        
        if (allowed) {
            // ok: java-avoid-use-of-unsafe-api
            response.sendRedirect(redirectUrl);
        } else {
            response.sendRedirect("/default");
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_6(HttpServletRequest request) {
    try {
        String xml = request.getParameter("data");
        
        // ok: java-avoid-use-of-unsafe-api
        javax.xml.parsers.DocumentBuilderFactory factory = javax.xml.parsers.DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.parse(new java.io.ByteArrayInputStream(xml.getBytes()));
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_7(HttpServletRequest request) {
    try {
        String jsonData = request.getParameter("data");
        
        // ok: java-avoid-use-of-unsafe-api
        ObjectMapper mapper = new ObjectMapper();
        mapper.activateDefaultTyping(
            mapper.getPolymorphicTypeValidator(),
            ObjectMapper.DefaultTyping.NONE
        );
        MyDataClass data = mapper.readValue(jsonData, MyDataClass.class);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_8(HttpServletRequest request) {
    try {
        String methodName = request.getParameter("method");
        // Whitelist of allowed methods
        Set<String> allowedMethods = new HashSet<>(Arrays.asList("toString", "hashCode"));
        
        if (allowedMethods.contains(methodName)) {
            // ok: java-avoid-use-of-unsafe-api
            Method method = String.class.getMethod(methodName);
            method.invoke("test");
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_9(HttpServletRequest request) {
    try {
        String command = request.getParameter("cmd");
        // Whitelist of allowed commands
        Map<String, String[]> allowedCommands = new HashMap<>();
        allowedCommands.put("list", new String[]{"ls", "-l"});
        allowedCommands.put("disk", new String[]{"df", "-h"});
        
        String[] cmdArray = allowedCommands.get(command);
        if (cmdArray != null) {
            // ok: java-avoid-use-of-unsafe-api
            ProcessBuilder pb = new ProcessBuilder(cmdArray);
            pb.start();
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_10(HttpServletRequest request) {
    try {
        String password = request.getParameter("password");
        byte[] salt = SecureRandom.getInstanceStrong().generateSeed(16);
        
        // ok: java-avoid-use-of-unsafe-api
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] hash = factory.generateSecret(spec).getEncoded();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_11(HttpServletRequest request) {
    try {
        String functionName = request.getParameter("function");
        // Whitelist of allowed functions
        Set<String> allowedFunctions = new HashSet<>(Arrays.asList(
            "myFunction1", "myFunction2"
        ));
        
        if (allowedFunctions.contains(functionName)) {
            // ok: java-avoid-use-of-unsafe-api
            AWSLambdaClient lambdaClient = new AWSLambdaClient();
            InvokeRequest invokeRequest = new InvokeRequest()
                .withFunctionName(functionName)
                .withPayload("{}");
            lambdaClient.invoke(invokeRequest);
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_12(HttpServletRequest request) {
    try {
        String username = request.getParameter("username");
        Session session = HibernateUtil.getSessionFactory().openSession();
        
        // ok: java-avoid-use-of-unsafe-api
        Query<User> query = session.createQuery("FROM User WHERE username = :username", User.class);
        query.setParameter("username", username);
        List<User> results = query.list();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_13(HttpServletRequest request) {
    try {
        String script = request.getParameter("script");
        // Validate script against whitelist of allowed operations
        if (isScriptSafe(script)) {
            // ok: java-avoid-use-of-unsafe-api
            ScriptEngineManager manager = new ScriptEngineManager();
            ScriptEngine engine = manager.getEngineByName("JavaScript");
            
            // Set up a sandbox with restricted permissions
            engine.getContext().setWriter(new StringWriter());
            engine.eval(script);
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
    
    // Helper method to validate script
    private boolean isScriptSafe(String script) {
        // Implementation of script validation logic
        return !script.contains("java.") && !script.contains("System.");
    }
}

public void good_case_14(HttpServletRequest request) {
    try {
        String command = request.getParameter("cmd");
        // Validate command against whitelist
        if (isCommandSafe(command)) {
            // ok: java-avoid-use-of-unsafe-api
            CommandLine cmdLine = CommandLine.parse("echo " + command);
            DefaultExecutor executor = new DefaultExecutor();
            // Set up restrictions
            executor.setWorkingDirectory(new File("/safe/directory"));
            executor.execute(cmdLine);
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
    
    // Helper method to validate command
    private boolean isCommandSafe(String command) {
        // Implementation of command validation logic
        return command.matches("[a-zA-Z0-9 ]+");
    }
}

public void good_case_15(HttpServletRequest request) {
    try {
        String blobName = request.getParameter("blob");
        // Validate blob name
        if (blobName.matches("[a-zA-Z0-9-_]+")) {
            // ok: java-avoid-use-of-unsafe-api
            BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
                .connectionString("connection-string")
                .buildClient();
            
            BlobContainerClient containerClient = blobServiceClient.getBlobContainerClient("container");
            BlobClient blobClient = containerClient.getBlobClient(blobName);
            
            // Download blob content safely
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            blobClient.download(outputStream);
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}