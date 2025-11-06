import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import ognl.Ognl;
import ognl.OgnlContext;
import ognl.OgnlException;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.struts2.ServletActionContext;
import com.opensymphony.xwork2.ognl.OgnlUtil;
import com.opensymphony.xwork2.util.ValueStack;
import com.opensymphony.xwork2.ActionContext;

public class OgnlInjectionExamples extends HttpServlet {

    // True Positive Examples (Vulnerable Code)

// {fact rule=autoescape-disabled@v1.0 defects=1}
    protected void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userInput = request.getParameter("expression");
        OgnlContext context = new OgnlContext();
        
        try {
            // ruleid: java-ognl-injection
            Object expr = Ognl.parseExpression(userInput);
            Object result = Ognl.getValue(expr, context, context.getRoot());
            response.getWriter().println("Result: " + result);
        } catch (OgnlException e) {
            e.printStackTrace();
        }
    }

    protected void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userInput = request.getParameter("query");
        Map<String, Object> context = new HashMap<>();
        context.put("user", getCurrentUser());
        
        try {
            // ruleid: java-ognl-injection
            Object value = Ognl.getValue(userInput, context, context);
            response.getWriter().println("Value: " + value);
        } catch (OgnlException e) {
            e.printStackTrace();
        }
    }

    protected void bad_case_3(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userExpression = request.getParameter("expr");
        OgnlContext context = new OgnlContext();
        context.put("data", getDataObject());
        
        try {
            // ruleid: java-ognl-injection
            Object result = Ognl.getValue("data." + userExpression, context, context.getRoot());
            response.getWriter().println("Data: " + result);
        } catch (OgnlException e) {
            e.printStackTrace();
        }
    }

    protected void bad_case_4(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String property = request.getParameter("property");
        String value = request.getParameter("value");
        OgnlContext context = new OgnlContext();
        Object root = new Object();
        
        try {
            // ruleid: java-ognl-injection
            Ognl.setValue(property, context, root, value);
            response.getWriter().println("Property set successfully");
        } catch (OgnlException e) {
            e.printStackTrace();
        }
    }

    protected void bad_case_5(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userInput = request.getHeader("X-Expression");
        OgnlUtil ognlUtil = new OgnlUtil();
        
        try {
            // ruleid: java-ognl-injection
            Object expr = ognlUtil.compile(userInput);
            Object value = ognlUtil.getValue(expr, ActionContext.getContext().getValueStack(), null, null);
            response.getWriter().println("Result: " + value);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected void bad_case_6(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userInput = request.getParameter("condition");
        String expression = "user.role == '" + userInput + "'";
        OgnlContext context = new OgnlContext();
        context.put("user", getCurrentUser());
        
        try {
            // ruleid: java-ognl-injection
            Object expr = Ognl.parseExpression(expression);
            Boolean result = (Boolean) Ognl.getValue(expr, context, context.getRoot());
            response.getWriter().println("Access granted: " + result);
        } catch (OgnlException e) {
            e.printStackTrace();
        }
    }

    protected void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userId = request.getParameter("id");
        OgnlContext context = new OgnlContext();
        context.put("users", getUsersMap());
        
        try {
            String expression = "users[" + userId + "].name";
            // ruleid: java-ognl-injection
            Object result = Ognl.getValue(expression, context, context.getRoot());
            response.getWriter().println("User name: " + result);
        } catch (OgnlException e) {
            e.printStackTrace();
        }
    }

    protected void bad_case_8(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String fieldName = request.getParameter("field");
        String objectName = request.getParameter("object");
        OgnlContext context = new OgnlContext();
        context.put("data", getDataObject());
        
        try {
            String expression = objectName + "." + fieldName;
            // ruleid: java-ognl-injection
            Object result = Ognl.getValue(expression, context, context.getRoot());
            response.getWriter().println("Field value: " + result);
        } catch (OgnlException e) {
            e.printStackTrace();
        }
    }

    protected void bad_case_9(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        ValueStack stack = ActionContext.getContext().getValueStack();
        String userInput = request.getParameter("expression");
        
        try {
            // ruleid: java-ognl-injection
            Object result = stack.findValue(userInput);
            response.getWriter().println("Result: " + result);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected void bad_case_10(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String methodName = request.getParameter("method");
        String expression = "#_memberAccess[\"allowStaticMethodAccess\"]= true, @java.lang.Runtime@getRuntime()." + methodName + "()";
        OgnlContext context = new OgnlContext();
        
        try {
            // ruleid: java-ognl-injection
            Object result = Ognl.getValue(expression, context, context.getRoot());
            response.getWriter().println("Result: " + result);
        } catch (OgnlException e) {
            e.printStackTrace();
        }
    }

    protected void bad_case_11(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String cookieValue = null;
        javax.servlet.http.Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (javax.servlet.http.Cookie cookie : cookies) {
                if ("expression".equals(cookie.getName())) {
                    cookieValue = cookie.getValue();
                    break;
                }
            }
        }
        
        if (cookieValue != null) {
            OgnlContext context = new OgnlContext();
            try {
                // ruleid: java-ognl-injection
                Object expr = Ognl.parseExpression(cookieValue);
                Object result = Ognl.getValue(expr, context, context.getRoot());
                response.getWriter().println("Result: " + result);
            } catch (OgnlException e) {
                e.printStackTrace();
            }
        }
    }

    protected void bad_case_12(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userInput = request.getParameter("query");
        StringBuilder expressionBuilder = new StringBuilder();
        expressionBuilder.append("user.name == '");
        expressionBuilder.append(userInput);
        expressionBuilder.append("'");
        
        OgnlContext context = new OgnlContext();
        context.put("user", getCurrentUser());
        
        try {
            // ruleid: java-ognl-injection
            Object expr = Ognl.parseExpression(expressionBuilder.toString());
            Boolean result = (Boolean) Ognl.getValue(expr, context, context.getRoot());
            response.getWriter().println("Match: " + result);
        } catch (OgnlException e) {
            e.printStackTrace();
        }
    }

    protected void bad_case_13(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String operation = request.getParameter("operation");
        String value1 = request.getParameter("value1");
        String value2 = request.getParameter("value2");
        
        String expression = value1 + " " + operation + " " + value2;
        OgnlContext context = new OgnlContext();
        
        try {
            // ruleid: java-ognl-injection
            Object result = Ognl.getValue(expression, context, context.getRoot());
            response.getWriter().println("Calculation result: " + result);
        } catch (OgnlException e) {
            e.printStackTrace();
        }
    }

    protected void bad_case_14(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        Map<String, String[]> paramMap = request.getParameterMap();
        String expression = paramMap.get("expr")[0];
        OgnlContext context = new OgnlContext();
        
        try {
            // ruleid: java-ognl-injection
            Object result = Ognl.getValue(expression, context, context.getRoot());
            response.getWriter().println("Result: " + result);
        } catch (OgnlException e) {
            e.printStackTrace();
        }
    }

    protected void bad_case_15(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userInput = request.getParameter("path");
        OgnlUtil ognlUtil = new OgnlUtil();
        ValueStack stack = ActionContext.getContext().getValueStack();
        
        try {
            // ruleid: java-ognl-injection
            Object value = ognlUtil.getValue(userInput, stack.getContext(), stack.getRoot());
            response.getWriter().println("Value: " + value);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // True Negative Examples (Safe Code)

    protected void good_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Using a whitelist of allowed expressions
        String userInput = request.getParameter("expression");
        Map<String, String> allowedExpressions = new HashMap<>();
        allowedExpressions.put("getName", "user.name");
        allowedExpressions.put("getAge", "user.age");
        allowedExpressions.put("getEmail", "user.email");
        
        OgnlContext context = new OgnlContext();
        context.put("user", getCurrentUser());
        
        try {
            // ok: java-ognl-injection
            String safeExpression = allowedExpressions.get(userInput);
            if (safeExpression != null) {
                Object expr = Ognl.parseExpression(safeExpression);
                Object result = Ognl.getValue(expr, context, context.getRoot());
                response.getWriter().println("Result: " + result);
            } else {
                response.getWriter().println("Invalid expression");
            }
        } catch (OgnlException e) {
            e.printStackTrace();
        }
    }

    protected void good_case_2(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Using hardcoded expressions instead of user input
        String action = request.getParameter("action");
        OgnlContext context = new OgnlContext();
        context.put("user", getCurrentUser());
        
        String expression = null;
        if ("getName".equals(action)) {
            expression = "user.name";
        } else if ("getAge".equals(action)) {
            expression = "user.age";
        } else {
            expression = "user.defaultInfo";
        }
        
        try {
            // ok: java-ognl-injection
            Object expr = Ognl.parseExpression(expression);
            Object result = Ognl.getValue(expr, context, context.getRoot());
            response.getWriter().println("Result: " + result);
        } catch (OgnlException e) {
            e.printStackTrace();
        }
    }

    protected void good_case_3(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Using direct method calls instead of OGNL
        String property = request.getParameter("property");
        
        // ok: java-ognl-injection
        Object user = getCurrentUser();
        String result = "";
        
        if ("name".equals(property)) {
            result = ((User)user).getName();
        } else if ("age".equals(property)) {
            result = String.valueOf(((User)user).getAge());
        } else if ("email".equals(property)) {
            result = ((User)user).getEmail();
        } else {
            result = "Unknown property";
        }
        
        response.getWriter().println("Result: " + result);
    }

    protected void good_case_4(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Using pattern matching to validate input before using in OGNL
        String userInput = request.getParameter("property");
        OgnlContext context = new OgnlContext();
        context.put("user", getCurrentUser());
        
        try {
            // ok: java-ognl-injection
            if (userInput != null && userInput.matches("^[a-zA-Z0-9]+$")) {
                String safeExpression = "user." + userInput;
                Object expr = Ognl.parseExpression(safeExpression);
                Object result = Ognl.getValue(expr, context, context.getRoot());
                response.getWriter().println("Result: " + result);
            } else {
                response.getWriter().println("Invalid property name");
            }
        } catch (OgnlException e) {
            e.printStackTrace();
        }
    }

    protected void good_case_5(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Using a switch statement to select predefined expressions
        int option = 0;
        try {
            option = Integer.parseInt(request.getParameter("option"));
        } catch (NumberFormatException e) {
            option = 0;
        }
        
        OgnlContext context = new OgnlContext();
        context.put("user", getCurrentUser());
        
        String expression;
        switch (option) {
            case 1:
                expression = "user.name";
                break;
            case 2:
                expression = "user.age";
                break;
            case 3:
                expression = "user.email";
                break;
            default:
                expression = "user.toString()";
        }
        
        try {
            // ok: java-ognl-injection
            Object expr = Ognl.parseExpression(expression);
            Object result = Ognl.getValue(expr, context, context.getRoot());
            response.getWriter().println("Result: " + result);
        } catch (OgnlException e) {
            e.printStackTrace();
        }
    }

    protected void good_case_6(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Using reflection instead of OGNL
        String property = request.getParameter("property");
        User user = getCurrentUser();
        
        try {
            // ok: java-ognl-injection
            if (property != null && property.matches("^[a-zA-Z]+$")) {
                String methodName = "get" + property.substring(0, 1).toUpperCase() + property.substring(1);
                java.lang.reflect.Method method = User.class.getMethod(methodName);
                Object result = method.invoke(user);
                response.getWriter().println("Result: " + result);
            } else {
                response.getWriter().println("Invalid property name");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected void good_case_7(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Using a map to store and retrieve values instead of OGNL
        String key = request.getParameter("key");
        Map<String, Object> dataMap = getDataMap();
        
        // ok: java-ognl-injection
        if (dataMap.containsKey(key)) {
            Object result = dataMap.get(key);
            response.getWriter().println("Result: " + result);
        } else {
            response.getWriter().println("Key not found");
        }
    }

    protected void good_case_8(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Using bean property accessor instead of OGNL
        String property = request.getParameter("property");
        User user = getCurrentUser();
        
        // ok: java-ognl-injection
        java.beans.PropertyDescriptor pd;
        try {
            if (property != null && property.matches("^[a-zA-Z]+$")) {
                pd = new java.beans.PropertyDescriptor(property, User.class);
                java.lang.reflect.Method readMethod = pd.getReadMethod();
                Object result = readMethod.invoke(user);
                response.getWriter().println("Result: " + result);
            } else {
                response.getWriter().println("Invalid property name");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected void good_case_9(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Using hardcoded OGNL expressions
        String action = request.getParameter("action");
        OgnlContext context = new OgnlContext();
        context.put("user", getCurrentUser());
        
        Object result = null;
        try {
            // ok: java-ognl-injection
            if ("getName".equals(action)) {
                result = Ognl.getValue("user.name", context, context.getRoot());
            } else if ("getAge".equals(action)) {
                result = Ognl.getValue("user.age", context, context.getRoot());
            } else if ("getEmail".equals(action)) {
                result = Ognl.getValue("user.email", context, context.getRoot());
            } else {
                result = "Unknown action";
            }
            response.getWriter().println("Result: " + result);
        } catch (OgnlException e) {
            e.printStackTrace();
        }
    }

    protected void good_case_10(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Using a custom method to safely access properties
        String property = request.getParameter("property");
        User user = getCurrentUser();
        
        // ok: java-ognl-injection
        Object result = getPropertySafely(user, property);
        response.getWriter().println("Result: " + result);
    }

    protected void good_case_11(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Using a template with placeholders instead of direct OGNL
        String template = "Hello, ${name}! Your account balance is ${balance}.";
        User user = getCurrentUser();
        
        // ok: java-ognl-injection
        String result = template.replace("${name}", user.getName())
                               .replace("${balance}", String.valueOf(user.getBalance()));
        response.getWriter().println(result);
    }

    protected void good_case_12(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Using enum to limit possible expressions
        String actionParam = request.getParameter("action");
        UserProperty property = null;
        
        try {
            property = UserProperty.valueOf(actionParam.toUpperCase());
        } catch (Exception e) {
            property = UserProperty.DEFAULT;
        }
        
        OgnlContext context = new OgnlContext();
        context.put("user", getCurrentUser());
        
        try {
            // ok: java-ognl-injection
            String safeExpression = property.getExpression();
            Object expr = Ognl.parseExpression(safeExpression);
            Object result = Ognl.getValue(expr, context, context.getRoot());
            response.getWriter().println("Result: " + result);
        } catch (OgnlException e) {
            e.printStackTrace();
        }
    }

    protected void good_case_13(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Using direct method invocation based on user input
        String methodName = request.getParameter("method");
        User user = getCurrentUser();
        
        // ok: java-ognl-injection
        if ("getName".equals(methodName)) {
            response.getWriter().println("Name: " + user.getName());
        } else if ("getAge".equals(methodName)) {
            response.getWriter().println("Age: " + user.getAge());
        } else if ("getEmail".equals(methodName)) {
            response.getWriter().println("Email: " + user.getEmail());
        } else {
            response.getWriter().println("Unknown method");
        }
    }

    protected void good_case_14(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Using a service layer instead of direct OGNL
        String userId = request.getParameter("id");
        String property = request.getParameter("property");
        
        // ok: java-ognl-injection
        UserService userService = new UserService();
        try {
            int id = Integer.parseInt(userId);
            String result = userService.getUserProperty(id, property);
            response.getWriter().println("Result: " + result);
        } catch (NumberFormatException e) {
            response.getWriter().println("Invalid user ID");
        } catch (IllegalArgumentException e) {
            response.getWriter().println("Invalid property");
        }
    }

    protected void good_case_15(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Using a dedicated data access object
        String id = request.getParameter("id");
        
        // ok: java-ognl-injection
        UserDAO userDAO = new UserDAO();
        try {
            int userId = Integer.parseInt(id);
            User user = userDAO.findById(userId);
            if (user != null) {
                response.getWriter().println("User: " + user.getName() + ", " + user.getEmail());
            } else {
                response.getWriter().println("User not found");
            }
        } catch (NumberFormatException e) {
            response.getWriter().println("Invalid user ID");
        }
    }

    // Helper methods
    private User getCurrentUser() {
        return new User("John Doe", 30, "john@example.com", 1000.0);
    }
    
    private Object getDataObject() {
        return new DataObject();
    }
    
    private Map<String, User> getUsersMap() {
        Map<String, User> users = new HashMap<>();
        users.put("1", new User("John Doe", 30, "john@example.com", 1000.0));
        users.put("2", new User("Jane Smith", 25, "jane@example.com", 2000.0));
        return users;
    }
    
    private Map<String, Object> getDataMap() {
        Map<String, Object> dataMap = new HashMap<>();
        dataMap.put("name", "John Doe");
        dataMap.put("age", 30);
        dataMap.put("email", "john@example.com");
        return dataMap;
    }
    
    private Object getPropertySafely(User user, String property) {
        if ("name".equals(property)) {
            return user.getName();
        } else if ("age".equals(property)) {
            return user.getAge();
        } else if ("email".equals(property)) {
            return user.getEmail();
        } else {
            return "Unknown property";
        }
    }
    
    // Helper classes
    private class User {
        private String name;
        private int age;
        private String email;
        private double balance;
        
        public User(String name, int age, String email, double balance) {
            this.name = name;
            this.age = age;
            this.email = email;
            this.balance = balance;
        }
        
        public String getName() { return name; }
        public int getAge() { return age; }
        public String getEmail() { return email; }
        public double getBalance() { return balance; }
    }
    
    private class DataObject {
        private String value = "test";
        public String getValue() { return value; }
    }
    
    private enum UserProperty {
        NAME("user.name"),
        AGE("user.age"),
        EMAIL("user.email"),
        DEFAULT("user.toString()");
        
        private final String expression;
        
        UserProperty(String expression) {
            this.expression = expression;
        }
        
        public String getExpression() {
            return expression;
        }
    }
    
    private class UserService {
        public String getUserProperty(int userId, String property) {
            User user = findUserById(userId);
            if (user == null) {
                throw new IllegalArgumentException("User not found");
            }
            
            if ("name".equals(property)) {
                return user.getName();
            } else if ("age".equals(property)) {
                return String.valueOf(user.getAge());
            } else if ("email".equals(property)) {
                return user.getEmail();
            } else {
                throw new IllegalArgumentException("Invalid property");
            }
        }
        
        private User findUserById(int id) {
            if (id == 1) {
                return new User("John Doe", 30, "john@example.com", 1000.0);
            }
            return null;
        }
    }
    
    private class UserDAO {
        public User findById(int id) {
            if (id == 1) {
                return new User("John Doe", 30, "john@example.com", 1000.0);
            } else if (id == 2) {
                return new User("Jane Smith", 25, "jane@example.com", 2000.0);
            }
            return null;
        }
    }
}
// {/fact}