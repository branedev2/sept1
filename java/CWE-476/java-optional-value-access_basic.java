import java.util.Optional;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import java.util.function.Supplier;
import java.util.stream.Stream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class OptionalValueAccessExamples {

    // True Positives (Vulnerable Code)

// {fact rule=inconsistent-null-check@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) {
        String userId = request.getParameter("userId");
        Optional<User> userOptional = findUserById(userId);
        // ruleid: java-optional-value-access
        User user = userOptional.get(); // Directly calling get() without checking if value is present
        System.out.println("User name: " + user.getName());
    }

    public void bad_case_2() {
        Optional<String> optionalValue = getOptionalString();
        if (optionalValue != null) { // Wrong check - checking if Optional is null, not if value is present
            // ruleid: java-optional-value-access
            String value = optionalValue.get(); // Still unsafe, not checking isPresent()
            System.out.println("Value: " + value);
        }
    }

    public void bad_case_3(HttpServletRequest request) {
        String productId = request.getParameter("productId");
        Optional<Product> productOptional = findProductById(productId);
        try {
            // ruleid: java-optional-value-access
            Product product = productOptional.get(); // Unsafe - using try/catch instead of isPresent()
            processProduct(product);
        } catch (Exception e) {
            System.out.println("Product not found");
        }
    }

    public void bad_case_4() {
        List<Optional<String>> optionalList = getOptionalStringList();
        for (Optional<String> opt : optionalList) {
            // ruleid: java-optional-value-access
            String value = opt.get(); // Unsafe - not checking each Optional before get()
            System.out.println(value);
        }
    }

    public void bad_case_5(HttpServletRequest request, HttpServletResponse response) {
        String orderId = request.getParameter("orderId");
        Optional<Order> orderOptional = findOrderById(orderId);
        
        if (orderOptional == null) {
            response.setStatus(404);
            return;
        }
        
        // ruleid: java-optional-value-access
        Order order = orderOptional.get(); // Unsafe - checking if Optional is null, not if value is present
        response.getWriter().write("Order details: " + order.getDetails());
    }

    public void bad_case_6() {
        Map<String, Optional<Integer>> optionalMap = getOptionalIntegerMap();
        Optional<Integer> valueOptional = optionalMap.get("key");
        
        if (valueOptional != null) {
            // ruleid: java-optional-value-access
            int value = valueOptional.get(); // Unsafe - checking if Optional is null, not if value is present
            System.out.println("Value: " + value);
        }
    }

    public void bad_case_7(HttpServletRequest request) {
        String email = request.getParameter("email");
        Optional<User> userOptional = findUserByEmail(email);
        
        if (someCondition()) {
            // ruleid: java-optional-value-access
            User user = userOptional.get(); // Unsafe - condition not related to Optional's value presence
            sendEmail(user.getEmail());
        }
    }

    public void bad_case_8() {
        Optional<String> optionalValue = getOptionalString();
        while (someLoopCondition()) {
            // ruleid: java-optional-value-access
            String value = optionalValue.get(); // Unsafe - no check before get() in loop
            processValue(value);
        }
    }

    public void bad_case_9(HttpServletRequest request) {
        String username = request.getParameter("username");
        Optional<User> userOptional = findUserByUsername(username);
        
        switch (getStatus()) {
            case AC_REDACTED_TWILIO_ID:
                // ruleid: java-optional-value-access
                User user = userOptional.get(); // Unsafe - switch case not checking Optional value presence
                activateUser(user);
                break;
            case INAC_REDACTED_TWILIO_ID:
                System.out.println("Inactive status");
                break;
        }
    }

    public void bad_case_10() {
        Optional<Integer> optionalValue = getOptionalInteger();
        Runnable runnable = () -> {
            // ruleid: java-optional-value-access
            int value = optionalValue.get(); // Unsafe - lambda not checking Optional value presence
            System.out.println("Value: " + value);
        };
        runnable.run();
    }

    public void bad_case_11(HttpServletRequest request) {
        String itemId = request.getParameter("itemId");
        Optional<Item> itemOptional = findItemById(itemId);
        
        if (itemOptional.equals(Optional.empty())) {
            System.out.println("Item not found");
        } else {
            // ruleid: java-optional-value-access
            Item item = itemOptional.get(); // Unsafe - using equals instead of isPresent/isEmpty
            processItem(item);
        }
    }

    public void bad_case_12() {
        Optional<String> optionalValue = getOptionalString();
        
        for (int i = 0; i < 10; i++) {
            if (i % 2 == 0) {
                // ruleid: java-optional-value-access
                String value = optionalValue.get(); // Unsafe - condition not related to Optional value presence
                System.out.println("Value: " + value);
            }
        }
    }

    public void bad_case_13(HttpServletRequest request) {
        String categoryId = request.getParameter("categoryId");
        Optional<Category> categoryOptional = findCategoryById(categoryId);
        
        if (categoryOptional != Optional.empty()) { // Not recommended way to check
            // ruleid: java-optional-value-access
            Category category = categoryOptional.get(); // Technically works but not idiomatic
            processCategory(category);
        }
    }

    public void bad_case_14() {
        Optional<Double> optionalValue = getOptionalDouble();
        
        if (optionalValue.toString().contains("Optional[")) { // Incorrect way to check
            // ruleid: java-optional-value-access
            double value = optionalValue.get(); // Unsafe - improper check before get()
            System.out.println("Value: " + value);
        }
    }

    public void bad_case_15(HttpServletRequest request) {
        String userId = request.getParameter("userId");
        Optional<User> userOptional = findUserById(userId);
        
        // Using Optional as a conditional expression without proper check
        User user = userOptional != null ? 
            // ruleid: java-optional-value-access
            userOptional.get() : // Unsafe - only checking if Optional is null
            createDefaultUser();
            
        System.out.println("User: " + user.getName());
    }

    // True Negatives (Safe Code)

    public void good_case_1(HttpServletRequest request) {
        String userId = request.getParameter("userId");
        Optional<User> userOptional = findUserById(userId);
        // ok: java-optional-value-access
        if (userOptional.isPresent()) {
            User user = userOptional.get(); // Safe - checking isPresent() before get()
            System.out.println("User name: " + user.getName());
        }
    }

    public void good_case_2() {
        Optional<String> optionalValue = getOptionalString();
        // ok: java-optional-value-access
        String value = optionalValue.orElse("Default value"); // Safe - using orElse
        System.out.println("Value: " + value);
    }

    public void good_case_3(HttpServletRequest request) {
        String productId = request.getParameter("productId");
        Optional<Product> productOptional = findProductById(productId);
        // ok: java-optional-value-access
        Product product = productOptional.orElseThrow(() -> 
            new ProductNotFoundException("Product not found: " + productId));
        processProduct(product);
    }

    public void good_case_4() {
        List<Optional<String>> optionalList = getOptionalStringList();
        for (Optional<String> opt : optionalList) {
            // ok: java-optional-value-access
            opt.ifPresent(value -> System.out.println(value)); // Safe - using ifPresent
        }
    }

    public void good_case_5(HttpServletRequest request, HttpServletResponse response) {
        String orderId = request.getParameter("orderId");
        Optional<Order> orderOptional = findOrderById(orderId);
        
        // ok: java-optional-value-access
        orderOptional.ifPresentOrElse(
            order -> {
                try {
                    response.getWriter().write("Order details: " + order.getDetails());
                } catch (Exception e) {
                    e.printStackTrace();
                }
            },
            () -> {
                try {
                    response.setStatus(404);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        );
    }

    public void good_case_6() {
        Map<String, Optional<Integer>> optionalMap = getOptionalIntegerMap();
        Optional<Integer> valueOptional = optionalMap.get("key");
        
        // ok: java-optional-value-access
        if (valueOptional != null && valueOptional.isPresent()) {
            int value = valueOptional.get(); // Safe - checking both null and isPresent
            System.out.println("Value: " + value);
        }
    }

    public void good_case_7(HttpServletRequest request) {
        String email = request.getParameter("email");
        Optional<User> userOptional = findUserByEmail(email);
        
        // ok: java-optional-value-access
        userOptional.ifPresent(user -> {
            if (someCondition()) {
                sendEmail(user.getEmail());
            }
        });
    }

    public void good_case_8() {
        Optional<String> optionalValue = getOptionalString();
        
        // ok: java-optional-value-access
        String value = optionalValue.orElseGet(() -> {
            // Complex default value generation
            return generateDefaultValue();
        });
        
        processValue(value);
    }

    public void good_case_9(HttpServletRequest request) {
        String username = request.getParameter("username");
        Optional<User> userOptional = findUserByUsername(username);
        
        // ok: java-optional-value-access
        if (!userOptional.isEmpty()) { // Java 11+ alternative to isPresent()
            User user = userOptional.get();
            activateUser(user);
        }
    }

    public void good_case_10() {
        Optional<Integer> optionalValue = getOptionalInteger();
        
        // ok: java-optional-value-access
        optionalValue.ifPresent(value -> {
            System.out.println("Value: " + value);
        });
    }

    public void good_case_11(HttpServletRequest request) {
        String itemId = request.getParameter("itemId");
        Optional<Item> itemOptional = findItemById(itemId);
        
        // ok: java-optional-value-access
        Item item = itemOptional.orElse(null);
        if (item != null) {
            processItem(item);
        } else {
            System.out.println("Item not found");
        }
    }

    public void good_case_12() {
        Optional<String> optionalValue = getOptionalString();
        
        // ok: java-optional-value-access
        optionalValue.ifPresentOrElse(
            value -> System.out.println("Value: " + value),
            () -> System.out.println("No value present")
        );
    }

    public void good_case_13(HttpServletRequest request) {
        String categoryId = request.getParameter("categoryId");
        Optional<Category> categoryOptional = findCategoryById(categoryId);
        
        // ok: java-optional-value-access
        Category category = categoryOptional.orElseGet(() -> createDefaultCategory());
        processCategory(category);
    }

    public void good_case_14() {
        Optional<Double> optionalValue = getOptionalDouble();
        
        // ok: java-optional-value-access
        double value = optionalValue.orElseThrow(IllegalStateException::new);
        System.out.println("Value: " + value);
    }

    public void good_case_15(HttpServletRequest request) {
        String userId = request.getParameter("userId");
        Optional<User> userOptional = findUserById(userId);
        
        // ok: java-optional-value-access
        User user = userOptional.isPresent() ? userOptional.get() : createDefaultUser();
        System.out.println("User: " + user.getName());
    }

    // Helper methods to avoid compilation errors
    private Optional<User> findUserById(String userId) {
        // Implementation would connect to a database or service
        return Optional.empty();
    }
    
    private Optional<Product> findProductById(String productId) {
        return Optional.empty();
    }
    
    private Optional<Order> findOrderById(String orderId) {
        return Optional.empty();
    }
    
    private Optional<User> findUserByEmail(String email) {
        return Optional.empty();
    }
    
    private Optional<User> findUserByUsername(String username) {
        return Optional.empty();
    }
    
    private Optional<Item> findItemById(String itemId) {
        return Optional.empty();
    }
    
    private Optional<Category> findCategoryById(String categoryId) {
        return Optional.empty();
    }
    
    private Optional<String> getOptionalString() {
        return Optional.empty();
    }
    
    private Optional<Integer> getOptionalInteger() {
        return Optional.empty();
    }
    
    private Optional<Double> getOptionalDouble() {
        return Optional.empty();
    }
    
    private List<Optional<String>> getOptionalStringList() {
        return new ArrayList<>();
    }
    
    private Map<String, Optional<Integer>> getOptionalIntegerMap() {
        return new HashMap<>();
    }
    
    private boolean someCondition() {
        return false;
    }
    
    private boolean someLoopCondition() {
        return false;
    }
    
    private Status getStatus() {
        return Status.AC_REDACTED_TWILIO_ID;
    }
    
    private void processProduct(Product product) {
        // Implementation
    }
    
    private void sendEmail(String email) {
        // Implementation
    }
    
    private void processValue(String value) {
        // Implementation
    }
    
    private void activateUser(User user) {
        // Implementation
    }
    
    private void processItem(Item item) {
        // Implementation
    }
    
    private void processCategory(Category category) {
        // Implementation
    }
    
    private String generateDefaultValue() {
        return "default";
    }
    
    private User createDefaultUser() {
        return new User();
    }
    
    private Category createDefaultCategory() {
        return new Category();
    }
    
    // Simple classes for examples
    private enum Status { AC_REDACTED_TWILIO_ID, INAC_REDACTED_TWILIO_ID }
    
    private class User {
        public String getName() { return ""; }
        public String getEmail() { return ""; }
    }
    
    private class Product {
        // Implementation
    }
    
    private class Order {
        public String getDetails() { return ""; }
    }
    
    private class Item {
        // Implementation
    }
    
    private class Category {
        // Implementation
    }
    
    private class ProductNotFoundException extends RuntimeException {
        public ProductNotFoundException(String message) {
            super(message);
        }
    }
}
// {/fact}