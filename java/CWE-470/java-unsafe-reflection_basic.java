import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.URL;
import java.sql.Connection;
import java.sql.DriverManager;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;

public class UnsafeReflectionExamples {

    // TRUE POSITIVES - Vulnerable code examples

    @WebServlet("/bad1")
    public class bad_case_1 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            String className = request.getParameter("class");
            try {
                // ruleid: java-unsafe-reflection
                Class<?> loadedClass = Class.forName(className);
                Object instance = loadedClass.newInstance();
                response.getWriter().println("Loaded class: " + instance.getClass().getName());
            } catch (Exception e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    @WebServlet("/bad2")
    public class bad_case_2 extends HttpServlet {
        protected void doPost(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            String className = request.getParameter("classToLoad");
            try {
                // ruleid: java-unsafe-reflection
                Class<?> dynamicClass = Class.forName(className);
                Constructor<?> constructor = dynamicClass.getConstructor();
                Object obj = constructor.newInstance();
                response.getWriter().println("Created object: " + obj.toString());
            } catch (Exception e) {
                response.getWriter().println("Failed to load class: " + e.getMessage());
            }
        }
    }

    @WebServlet("/bad3")
    public class bad_case_3 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            String header = request.getHeader("X-Class-Name");
            try {
                // ruleid: java-unsafe-reflection
                Class<?> cls = Class.forName(header);
                Method method = cls.getMethod("toString");
                Object result = method.invoke(cls.newInstance());
                response.getWriter().println(result);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    @WebServlet("/bad4")
    public class bad_case_4 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            String className = request.getParameter("type");
            String methodName = request.getParameter("method");
            
            try {
                // ruleid: java-unsafe-reflection
                Class<?> clazz = Class.forName(className);
                Method method = clazz.getMethod(methodName);
                Object instance = clazz.newInstance();
                Object result = method.invoke(instance);
                response.getWriter().println("Result: " + result);
            } catch (Exception e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    @WebServlet("/bad5")
    public class bad_case_5 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            String userInput = request.getParameter("plugin");
            String pluginClass = "org.example.plugins." + userInput;
            
            try {
                // ruleid: java-unsafe-reflection
                Class<?> pluginType = Class.forName(pluginClass);
                Object plugin = pluginType.newInstance();
                response.getWriter().println("Loaded plugin: " + plugin.getClass().getName());
            } catch (Exception e) {
                response.getWriter().println("Failed to load plugin: " + e.getMessage());
            }
        }
    }

    @WebServlet("/bad6")
    public class bad_case_6 extends HttpServlet {
        protected void doPost(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            String classPath = request.getParameter("classPath");
            String action = request.getParameter("action");
            
            try {
                // ruleid: java-unsafe-reflection
                Class<?> actionClass = Class.forName(classPath);
                Method actionMethod = actionClass.getMethod(action);
                Object instance = actionClass.newInstance();
                actionMethod.invoke(instance);
                response.getWriter().println("Action executed successfully");
            } catch (Exception e) {
                response.getWriter().println("Error executing action: " + e.getMessage());
            }
        }
    }

    @WebServlet("/bad7")
    public class bad_case_7 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            String cookie = request.getHeader("Cookie");
            String className = "";
            
            if (cookie != null && cookie.contains("className=")) {
                className = cookie.substring(cookie.indexOf("className=") + 10);
                if (className.contains(";")) {
                    className = className.substring(0, className.indexOf(";"));
                }
            }
            
            try {
                // ruleid: java-unsafe-reflection
                Class<?> cls = Class.forName(className);
                Object obj = cls.newInstance();
                response.getWriter().println("Created: " + obj.toString());
            } catch (Exception e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    @WebServlet("/bad8")
    public class bad_case_8 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            String referer = request.getHeader("Referer");
            String className = "";
            
            if (referer != null && referer.contains("class=")) {
                int startIdx = referer.indexOf("class=") + 6;
                int endIdx = referer.indexOf("&", startIdx);
                if (endIdx == -1) {
                    className = referer.substring(startIdx);
                } else {
                    className = referer.substring(startIdx, endIdx);
                }
            }
            
            try {
                // ruleid: java-unsafe-reflection
                Class<?> dynamicClass = Class.forName(className);
                Object instance = dynamicClass.newInstance();
                response.getWriter().println("Instance created: " + instance);
            } catch (Exception e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    @WebServlet("/bad9")
    public class bad_case_9 extends HttpServlet {
        protected void doPost(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            Map<String, String> formData = new HashMap<>();
            request.getParameterMap().forEach((key, value) -> {
                formData.put(key, value[0]);
            });
            
            String className = formData.get("className");
            
            try {
                // ruleid: java-unsafe-reflection
                Class<?> cls = Class.forName(className);
                Object obj = cls.newInstance();
                response.getWriter().println("Created object of type: " + obj.getClass().getName());
            } catch (Exception e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    @WebServlet("/bad10")
    public class bad_case_10 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            String userAgent = request.getHeader("User-Agent");
            String className = "";
            
            if (userAgent != null && userAgent.contains("CustomApp/")) {
                className = userAgent.substring(userAgent.indexOf("CustomApp/") + 10);
                if (className.contains(" ")) {
                    className = className.substring(0, className.indexOf(" "));
                }
            }
            
            try {
                // ruleid: java-unsafe-reflection
                Class<?> cls = Class.forName(className);
                Object obj = cls.newInstance();
                response.getWriter().println("Created: " + obj.toString());
            } catch (Exception e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    @WebServlet("/bad11")
    public class bad_case_11 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            String url = "https://example.com/api/class";
            URL obj = new URL(url);
            HttpURLConnection con = (HttpURLConnection) obj.openConnection();
            con.setRequestMethod("GET");
            
            BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
            String inputLine;
            StringBuilder content = new StringBuilder();
            while ((inputLine = in.readLine()) != null) {
                content.append(inputLine);
            }
            in.close();
            con.disconnect();
            
            String className = content.toString();
            
            try {
                // ruleid: java-unsafe-reflection
                Class<?> cls = Class.forName(className);
                Object obj = cls.newInstance();
                response.getWriter().println("Created: " + obj.toString());
            } catch (Exception e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    @WebServlet("/bad12")
    public class bad_case_12 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            String pathInfo = request.getPathInfo();
            if (pathInfo != null && pathInfo.startsWith("/")) {
                String className = pathInfo.substring(1);
                try {
                    // ruleid: java-unsafe-reflection
                    Class<?> cls = Class.forName(className);
                    Object obj = cls.newInstance();
                    response.getWriter().println("Created: " + obj.toString());
                } catch (Exception e) {
                    response.getWriter().println("Error: " + e.getMessage());
                }
            }
        }
    }

    @WebServlet("/bad13")
    public class bad_case_13 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            String queryString = request.getQueryString();
            String className = null;
            
            if (queryString != null && queryString.contains("class=")) {
                int startIdx = queryString.indexOf("class=") + 6;
                int endIdx = queryString.indexOf("&", startIdx);
                if (endIdx == -1) {
                    className = queryString.substring(startIdx);
                } else {
                    className = queryString.substring(startIdx, endIdx);
                }
            }
            
            if (className != null) {
                try {
                    // ruleid: java-unsafe-reflection
                    Class<?> cls = Class.forName(className);
                    Object obj = cls.newInstance();
                    response.getWriter().println("Created: " + obj.toString());
                } catch (Exception e) {
                    response.getWriter().println("Error: " + e.getMessage());
                }
            }
        }
    }

    @WebServlet("/bad14")
    public class bad_case_14 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            String contentType = request.getContentType();
            String className = null;
            
            if (contentType != null && contentType.contains("x-class-name=")) {
                className = contentType.substring(contentType.indexOf("x-class-name=") + 13);
            }
            
            if (className != null) {
                try {
                    // ruleid: java-unsafe-reflection
                    Class<?> cls = Class.forName(className);
                    Object obj = cls.newInstance();
                    response.getWriter().println("Created: " + obj.toString());
                } catch (Exception e) {
                    response.getWriter().println("Error: " + e.getMessage());
                }
            }
        }
    }

    @WebServlet("/bad15")
    public class bad_case_15 extends HttpServlet {
        protected void doPost(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            String requestURI = request.getRequestURI();
            String className = null;
            
            if (requestURI.contains("/class/")) {
                className = requestURI.substring(requestURI.indexOf("/class/") + 7);
            }
            
            if (className != null && !className.isEmpty()) {
                try {
                    // ruleid: java-unsafe-reflection
                    Class<?> cls = Class.forName(className);
                    Object obj = cls.newInstance();
                    response.getWriter().println("Created: " + obj.toString());
                } catch (Exception e) {
                    response.getWriter().println("Error: " + e.getMessage());
                }
            }
        }
    }

    // TRUE NEGATIVES - Safe code examples

    @WebServlet("/good1")
    public class good_case_1 extends HttpServlet {
        private static final Map<String, String> ALLOWED_CLASSES = new HashMap<>();
        
        static {
            ALLOWED_CLASSES.put("user", "com.example.User");
            ALLOWED_CLASSES.put("product", "com.example.Product");
            ALLOWED_CLASSES.put("order", "com.example.Order");
        }
        
        protected void doGet(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            String classKey = request.getParameter("type");
            String className = ALLOWED_CLASSES.get(classKey);
            
            if (className != null) {
                try {
                    // ok: java-unsafe-reflection
                    Class<?> cls = Class.forName(className);
                    Object obj = cls.newInstance();
                    response.getWriter().println("Created: " + obj.toString());
                } catch (Exception e) {
                    response.getWriter().println("Error: " + e.getMessage());
                }
            } else {
                response.getWriter().println("Invalid type specified");
            }
        }
    }

    @WebServlet("/good2")
    public class good_case_2 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            // Using hardcoded class name instead of user input
            try {
                // ok: java-unsafe-reflection
                Class<?> cls = Class.forName("java.util.ArrayList");
                Object obj = cls.newInstance();
                response.getWriter().println("Created: " + obj.toString());
            } catch (Exception e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    @WebServlet("/good3")
    public class good_case_3 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            String className = request.getParameter("class");
            
            // Validate against a whitelist of allowed classes
            if ("java.util.ArrayList".equals(className) || 
                "java.util.HashMap".equals(className) || 
                "java.util.HashSet".equals(className)) {
                try {
                    // ok: java-unsafe-reflection
                    Class<?> cls = Class.forName(className);
                    Object obj = cls.newInstance();
                    response.getWriter().println("Created: " + obj.toString());
                } catch (Exception e) {
                    response.getWriter().println("Error: " + e.getMessage());
                }
            } else {
                response.getWriter().println("Unauthorized class requested");
            }
        }
    }

    @WebServlet("/good4")
    public class good_case_4 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            String type = request.getParameter("type");
            String className;
            
            // Map user input to specific class names
            switch (type) {
                case "list":
                    className = "java.util.ArrayList";
                    break;
                case "map":
                    className = "java.util.HashMap";
                    break;
                case "set":
                    className = "java.util.HashSet";
                    break;
                default:
                    className = null;
            }
            
            if (className != null) {
                try {
                    // ok: java-unsafe-reflection
                    Class<?> cls = Class.forName(className);
                    Object obj = cls.newInstance();
                    response.getWriter().println("Created: " + obj.toString());
                } catch (Exception e) {
                    response.getWriter().println("Error: " + e.getMessage());
                }
            } else {
                response.getWriter().println("Invalid type specified");
            }
        }
    }

    @WebServlet("/good5")
    public class good_case_5 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            // Using a constant class name
            final String CLASS_NAME = "java.util.Date";
            
            try {
                // ok: java-unsafe-reflection
                Class<?> cls = Class.forName(CLASS_NAME);
                Object obj = cls.newInstance();
                response.getWriter().println("Current date: " + obj.toString());
            } catch (Exception e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    @WebServlet("/good6")
    public class good_case_6 extends HttpServlet {
        private static final Pattern CLASS_PATTERN = Pattern.compile("^[a-zA-Z0-9.]+$");
        private static final String PAC_REDACTED_TWILIO_ID_PREFIX = "com.example.safe.";
        
        protected void doGet(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            String className = request.getParameter("class");
            
            // Validate class name format and restrict to specific package
            if (className != null && CLASS_PATTERN.matcher(className).matches()) {
                String fullClassName = PAC_REDACTED_TWILIO_ID_PREFIX + className;
                try {
                    // ok: java-unsafe-reflection
                    Class<?> cls = Class.forName(fullClassName);
                    // Additional validation to ensure it's a subclass of a specific type
                    if (com.example.safe.BaseClass.class.isAssignableFrom(cls)) {
                        Object obj = cls.newInstance();
                        response.getWriter().println("Created: " + obj.toString());
                    } else {
                        response.getWriter().println("Invalid class type");
                    }
                } catch (Exception e) {
                    response.getWriter().println("Error: " + e.getMessage());
                }
            } else {
                response.getWriter().println("Invalid class name format");
            }
        }
    }

    @WebServlet("/good7")
    public class good_case_7 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            // Using Class.forName with a literal string
            try {
                // ok: java-unsafe-reflection
                Class<?> stringClass = Class.forName("java.lang.String");
                Constructor<?> constructor = stringClass.getConstructor(String.class);
                Object instance = constructor.newInstance("Hello, World!");
                response.getWriter().println(instance);
            } catch (Exception e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    @WebServlet("/good8")
    public class good_case_8 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            int classType = 0;
            try {
                classType = Integer.parseInt(request.getParameter("type"));
            } catch (NumberFormatException e) {
                response.getWriter().println("Invalid type parameter");
                return;
            }
            
            String className;
            switch (classType) {
                case 1:
                    className = "java.util.ArrayList";
                    break;
                case 2:
                    className = "java.util.LinkedList";
                    break;
                case 3:
                    className = "java.util.Vector";
                    break;
                default:
                    className = "java.util.ArrayList";
            }
            
            try {
                // ok: java-unsafe-reflection
                Class<?> cls = Class.forName(className);
                Object obj = cls.newInstance();
                response.getWriter().println("Created: " + obj.toString());
            } catch (Exception e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    @WebServlet("/good9")
    public class good_case_9 extends HttpServlet {
        private final Map<String, Class<?>> classCache = new HashMap<>();
        
// {fact rule=unsafe-reflection@v1.0 defects=0}
        public good_case_9() {
            try {
                classCache.put("list", Class.forName("java.util.ArrayList"));
                classCache.put("map", Class.forName("java.util.HashMap"));
                classCache.put("set", Class.forName("java.util.HashSet"));
            } catch (ClassNotFoundException e) {
                // Handle initialization error
            }
        }
        
        protected void doGet(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            String type = request.getParameter("type");
            Class<?> cls = classCache.get(type);
            
            if (cls != null) {
                try {
                    // ok: java-unsafe-reflection
                    Object obj = cls.newInstance();
                    response.getWriter().println("Created: " + obj.toString());
                } catch (Exception e) {
                    response.getWriter().println("Error: " + e.getMessage());
                }
            } else {
                response.getWriter().println("Invalid type specified");
            }
        }
    }
// {/fact}

    @WebServlet("/good10")
    public class good_case_10 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            // Using a configuration file or system property instead of user input
            String className = System.getProperty("app.factory.class", "com.example.DefaultFactory");
            
            try {
                // ok: java-unsafe-reflection
                Class<?> cls = Class.forName(className);
                Object obj = cls.newInstance();
                response.getWriter().println("Created: " + obj.toString());
            } catch (Exception e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    @WebServlet("/good11")
    public class good_case_11 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            // Using a constant class name determined at compile time
            final String[] ALLOWED_CLASSES = {
                "java.util.ArrayList",
                "java.util.LinkedList",
                "java.util.Vector"
            };
            
            int index = 0;
            try {
                index = Integer.parseInt(request.getParameter("index"));
                if (index < 0 || index >= ALLOWED_CLASSES.length) {
                    index = 0;
                }
            } catch (NumberFormatException e) {
                // Default to first class
            }
            
            try {
                // ok: java-unsafe-reflection
                Class<?> cls = Class.forName(ALLOWED_CLASSES[index]);
                Object obj = cls.newInstance();
                response.getWriter().println("Created: " + obj.toString());
            } catch (Exception e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    @WebServlet("/good12")
    public class good_case_12 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            // Using reflection with a class literal
            try {
                // ok: java-unsafe-reflection
                Class<?> cls = String.class;
                Object obj = cls.newInstance();
                response.getWriter().println("Created: " + obj.toString());
            } catch (Exception e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    @WebServlet("/good13")
    public class good_case_13 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            // Using a secure factory pattern instead of direct reflection
            String type = request.getParameter("type");
            Object obj = ObjectFactory.createObject(type);
            
            if (obj != null) {
                response.getWriter().println("Created: " + obj.toString());
            } else {
                response.getWriter().println("Invalid type specified");
            }
        }
        
        // Factory class that safely handles object creation
        private static class ObjectFactory {
            public static Object createObject(String type) {
                if ("list".equals(type)) {
                    return new java.util.ArrayList<>();
                } else if ("map".equals(type)) {
                    return new java.util.HashMap<>();
                } else if ("set".equals(type)) {
                    return new java.util.HashSet<>();
                }
                return null;
            }
        }
    }

    @WebServlet("/good14")
    public class good_case_14 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            // Using Class.forName with a compile-time constant
            try {
                // ok: java-unsafe-reflection
                Class.forName("com.mysql.jdbc.Driver");
                Connection conn = DriverManager.getConnection(
                    "jdbc:mysql://localhost:3306/mydb", "user", "password");
                response.getWriter().println("Database connected");
                conn.close();
            } catch (Exception e) {
                response.getWriter().println("Error: " + e.getMessage());
            }
        }
    }

    @WebServlet("/good15")
    public class good_case_15 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            String className = request.getParameter("class");
            
            // Validate class name against a strict regex pattern
            if (className != null && className.matches("^[a-zA-Z0-9]+$")) {
                // Map to a specific package and validate against known classes
                Map<String, String> classMap = new HashMap<>();
                classMap.put("user", "com.example.model.User");
                classMap.put("product", "com.example.model.Product");
                classMap.put("order", "com.example.model.Order");
                
                String mappedClassName = classMap.get(className);
                
                if (mappedClassName != null) {
                    try {
                        // ok: java-unsafe-reflection
                        Class<?> cls = Class.forName(mappedClassName);
                        Object obj = cls.newInstance();
                        response.getWriter().println("Created: " + obj.toString());
                    } catch (Exception e) {
                        response.getWriter().println("Error: " + e.getMessage());
                    }
                } else {
                    response.getWriter().println("Unknown class type");
                }
            } else {
                response.getWriter().println("Invalid class name format");
            }
        }
    }
}