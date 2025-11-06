import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.channels.*;
import java.nio.file.*;
import java.security.*;
import java.sql.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.servlet.http.*;
import javax.xml.parsers.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.xml.sax.*;
import sun.misc.Unsafe;
import java.lang.reflect.Field;

public class UnsafeApiExamples {

    // True Positives (Vulnerable/Insecure Code)

// {fact rule=low-level-functionality-misuse@v1.0 defects=1}
    public void bad_case_1() throws Exception {
        // Direct use of Unsafe API
        Field f = Unsafe.class.getDeclaredField("theUnsafe");
        f.setAccessible(true);
        // ruleid: java-avoid-use-of-unsafe-api
        Unsafe unsafe = (Unsafe) f.get(null);
        long address = unsafe.allocateMemory(4);
        unsafe.putInt(address, 42);
    }

    public void bad_case_2() {
        try {
            // Direct use of JNI
            System.loadLibrary("native_library");
            // ruleid: java-avoid-use-of-unsafe-api
            native void unsafeNativeMethod();
            unsafeNativeMethod();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_3() throws Exception {
        // Direct memory manipulation
        Field f = Unsafe.class.getDeclaredField("theUnsafe");
        f.setAccessible(true);
        Unsafe unsafe = (Unsafe) f.get(null);
        
        // ruleid: java-avoid-use-of-unsafe-api
        long size = 4096;
        long address = unsafe.allocateMemory(size);
        unsafe.setMemory(address, size, (byte) 0);
    }

    public void bad_case_4() throws Exception {
        // Using reflection to access private fields
        Class<?> clazz = Class.forName("java.lang.String");
        // ruleid: java-avoid-use-of-unsafe-api
        Field valueField = clazz.getDeclaredField("value");
        valueField.setAccessible(true);
        
        String str = "Hello";
        char[] value = (char[]) valueField.get(str);
        value[0] = 'h';
    }

    public void bad_case_5() throws Exception {
        // Using Runtime.exec for command execution instead of ProcessBuilder
        String command = "ls -la";
        // ruleid: java-avoid-use-of-unsafe-api
        Process process = Runtime.getRuntime().exec(command);
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println(line);
        }
    }

    public void bad_case_6() throws Exception {
        // Using raw JDBC instead of Spring's JdbcTemplate
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        Statement stmt = conn.createStatement();
        // ruleid: java-avoid-use-of-unsafe-api
        ResultSet rs = stmt.executeQuery("SELECT * FROM users");
        while (rs.next()) {
            System.out.println(rs.getString("username"));
        }
    }

    public void bad_case_7() throws Exception {
        // Using raw file I/O instead of NIO
        File file = new File("data.txt");
        // ruleid: java-avoid-use-of-unsafe-api
        FileInputStream fis = new FileInputStream(file);
        byte[] data = new byte[(int) file.length()];
        fis.read(data);
        fis.close();
    }

    public void bad_case_8() throws Exception {
        // Using raw socket instead of higher-level APIs
        // ruleid: java-avoid-use-of-unsafe-api
        Socket socket = new Socket("example.com", 80);
        OutputStream out = socket.getOutputStream();
        out.write("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".getBytes());
        
        InputStream in = socket.getInputStream();
        byte[] response = new byte[1024];
        in.read(response);
        socket.close();
    }

    public void bad_case_9() throws Exception {
        // Using raw thread manipulation instead of ExecutorService
        // ruleid: java-avoid-use-of-unsafe-api
        Thread thread = new Thread(() -> {
            System.out.println("Running in a raw thread");
        });
        thread.start();
        thread.join();
    }

    public void bad_case_10() throws Exception {
        // Using raw cryptography instead of higher-level APIs
        byte[] key = "insecurepassword".getBytes();
        // ruleid: java-avoid-use-of-unsafe-api
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        byte[] encrypted = cipher.doFinal("sensitive data".getBytes());
    }

    public void bad_case_11() throws Exception {
        // Using raw XML parsing without security features
        String xml = "<user>data</user>";
        // ruleid: java-avoid-use-of-unsafe-api
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(new InputSource(new StringReader(xml)));
    }

    public void bad_case_12() throws Exception {
        // Direct manipulation of class loaders
        // ruleid: java-avoid-use-of-unsafe-api
        URLClassLoader classLoader = new URLClassLoader(
            new URL[] { new URL("file:///path/to/classes/") },
            this.getClass().getClassLoader()
        );
        Class<?> loadedClass = classLoader.loadClass("com.example.DynamicClass");
        Object instance = loadedClass.newInstance();
    }

    public void bad_case_13() throws Exception {
        // Using raw serialization
        Object obj = new HashMap<String, String>();
        // ruleid: java-avoid-use-of-unsafe-api
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(obj);
        oos.close();
    }

    public void bad_case_14() throws Exception {
        // Using raw reflection to invoke methods
        String className = "java.lang.Runtime";
        String methodName = "exec";
        // ruleid: java-avoid-use-of-unsafe-api
        Class<?> clazz = Class.forName(className);
        Method method = clazz.getMethod(methodName, String.class);
        Object result = method.invoke(Runtime.getRuntime(), "ls");
    }

    public void bad_case_15() throws Exception {
        // Direct manipulation of system properties
        // ruleid: java-avoid-use-of-unsafe-api
        System.setSecurityManager(null);
        System.setProperty("java.security.policy", "file:/path/to/policy");
    }

    // True Negatives (Safe/Secure Code)

    public void good_case_1() {
        // Using ProcessBuilder instead of Runtime.exec
        try {
            List<String> command = Arrays.asList("ls", "-la");
            // ok: java-avoid-use-of-unsafe-api
            ProcessBuilder processBuilder = new ProcessBuilder(command);
            Process process = processBuilder.start();
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_2() {
        // Using Spring's JdbcTemplate instead of raw JDBC
        try {
            JdbcTemplate jdbcTemplate = new JdbcTemplate();
            // ok: java-avoid-use-of-unsafe-api
            List<Map<String, Object>> users = jdbcTemplate.queryForList("SELECT * FROM users");
            for (Map<String, Object> user : users) {
                System.out.println(user.get("username"));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_3() {
        // Using NIO instead of raw file I/O
        try {
            Path path = Paths.get("data.txt");
            // ok: java-avoid-use-of-unsafe-api
            byte[] data = Files.readAllBytes(path);
            System.out.println(new String(data));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_4() {
        // Using ExecutorService instead of raw threads
        try {
            // ok: java-avoid-use-of-unsafe-api
            ExecutorService executor = java.util.concurrent.Executors.newSingleThreadExecutor();
            executor.submit(() -> {
                System.out.println("Running in an executor service");
            });
            executor.shutdown();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_5() {
        // Using secure XML parsing
        try {
            String xml = "<user>data</user>";
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            // ok: java-avoid-use-of-unsafe-api
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setExpandEntityReferences(false);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(xml)));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_6() {
        // Using high-level cryptography APIs
        try {
            // ok: java-avoid-use-of-unsafe-api
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey secretKey = keyGen.generateKey();
            
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encrypted = cipher.doFinal("sensitive data".getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_7() {
        // Using secure password hashing
        try {
            String password = "userPassword";
            // ok: java-avoid-use-of-unsafe-api
            BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
            String hashedPassword = encoder.encode(password);
            
            boolean matches = encoder.matches(password, hashedPassword);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_8() {
        // Using HttpURLConnection with proper security settings
        try {
            URL url = new URL("https://example.com");
            // ok: java-avoid-use-of-unsafe-api
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);
            
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println(line);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_9() {
        // Using Path API for file operations
        try {
            // ok: java-avoid-use-of-unsafe-api
            Path sourcePath = Paths.get("source.txt");
            Path targetPath = Paths.get("target.txt");
            Files.copy(sourcePath, targetPath, StandardCopyOption.REPLAC_REDACTED_TWILIO_ID_EXISTING);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_10() {
        // Using PreparedStatement instead of raw SQL
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            // ok: java-avoid-use-of-unsafe-api
            PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE username = ?");
            pstmt.setString(1, "john");
            ResultSet rs = pstmt.executeQuery();
            while (rs.next()) {
                System.out.println(rs.getString("username"));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_11() {
        // Using secure random number generation
        try {
            // ok: java-avoid-use-of-unsafe-api
            SecureRandom secureRandom = new SecureRandom();
            byte[] randomBytes = new byte[16];
            secureRandom.nextBytes(randomBytes);
            
            int randomInt = secureRandom.nextInt(100);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_12() {
        // Using proper exception handling
        try {
            // ok: java-avoid-use-of-unsafe-api
            try (FileInputStream fis = new FileInputStream("data.txt")) {
                byte[] data = new byte[fis.available()];
                fis.read(data);
                System.out.println(new String(data));
            }
        } catch (IOException e) {
            // Proper exception handling
            Logger.getLogger(getClass().getName()).log(Level.SEVERE, "Error reading file", e);
        }
    }

    public void good_case_13() {
        // Using secure serialization alternatives
        try {
            Map<String, String> data = new HashMap<>();
            data.put("key", "value");
            
            // ok: java-avoid-use-of-unsafe-api
            ObjectMapper mapper = new ObjectMapper();
            String json = mapper.writeValueAsString(data);
            
            Map<String, String> deserializedData = mapper.readValue(json, Map.class);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_14() {
        // Using proper system property access
        try {
            // ok: java-avoid-use-of-unsafe-api
            String tmpDir = System.getProperty("java.io.tmpdir");
            Path tempFile = Paths.get(tmpDir, "tempfile.txt");
            Files.writeString(tempFile, "Temporary data");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_15(@RequestParam String input) {
        // Using framework-provided validation
        try {
            // ok: java-avoid-use-of-unsafe-api
            if (input == null || input.isEmpty()) {
                throw new IllegalArgumentException("Input cannot be empty");
            }
            
            // Process the validated input
            System.out.println("Processing: " + input);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
// {/fact}