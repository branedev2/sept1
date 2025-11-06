import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import org.springframework.web.bind.annotation.*;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import java.util.Objects;

public class NullDereferenceExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=inconsistent-null-check@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String username = request.getParameter("username");
        // ruleid: java-null-dereference
        int length = username.length(); // Potential null dereference
        response.getWriter().println("Username length: " + length);
    }

    public void bad_case_2(HttpServletRequest request, HttpServletResponse response) {
        String email = request.getParameter("email");
        // ruleid: java-null-dereference
        if (email.contains("@")) { // Potential null dereference
            response.setStatus(HttpServletResponse.SC_OK);
        } else {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        }
    }

    public void bad_case_3(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String id = request.getParameter("id");
        // ruleid: java-null-dereference
        int userId = Integer.parseInt(id); // Potential null dereference and NumberFormatException
        response.getWriter().println("User ID: " + userId);
    }

    public void bad_case_4(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String action = request.getParameter("action");
        // ruleid: java-null-dereference
        switch (action.toLowerCase()) { // Potential null dereference
            case "add":
                response.getWriter().println("Adding item");
                break;
            case "remove":
                response.getWriter().println("Removing item");
                break;
            default:
                response.getWriter().println("Unknown action");
        }
    }

    public void bad_case_5(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String firstName = request.getParameter("firstName");
        String lastName = request.getParameter("lastName");
        
        // ruleid: java-null-dereference
        String fullName = firstName.trim() + " " + lastName.trim(); // Potential null dereference on both variables
        response.getWriter().println("Full name: " + fullName);
    }

    public void bad_case_6(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String quantity = request.getParameter("quantity");
        // ruleid: java-null-dereference
        int numItems = Integer.parseInt(quantity.trim()); // Potential null dereference
        response.getWriter().println("Number of items: " + numItems);
    }

    public void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Map<String, Integer> prices = new HashMap<>();
        prices.put("apple", 1);
        prices.put("banana", 2);
        
        String item = request.getParameter("item");
        // ruleid: java-null-dereference
        int price = prices.get(item.toLowerCase()); // Potential null dereference
        response.getWriter().println("Price: " + price);
    }

    public void bad_case_8(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String color = request.getParameter("color");
        // ruleid: java-null-dereference
        String message = "Selected color: " + color.toUpperCase(); // Potential null dereference
        response.getWriter().println(message);
    }

    public void bad_case_9(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String csvData = request.getParameter("data");
        // ruleid: java-null-dereference
        String[] values = csvData.split(","); // Potential null dereference
        response.getWriter().println("Number of values: " + values.length);
    }

    public void bad_case_10(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String password = request.getParameter("password");
        // ruleid: java-null-dereference
        boolean isStrong = password.length() > 8 && password.matches(".*[A-Z].*"); // Potential null dereference
        response.getWriter().println("Password strength: " + (isStrong ? "Strong" : "Weak"));
    }

    @PostMapping("/process")
    public void bad_case_11(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String json = request.getParameter("jsonData");
        // ruleid: java-null-dereference
        boolean isValid = json.startsWith("{") && json.endsWith("}"); // Potential null dereference
        response.getWriter().println("JSON valid: " + isValid);
    }

    public void bad_case_12(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String url = request.getParameter("redirectUrl");
        // ruleid: java-null-dereference
        if (url.startsWith("https://")) { // Potential null dereference
            response.sendRedirect(url);
        } else {
            response.getWriter().println("Invalid URL");
        }
    }

    public void bad_case_13(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String searchTerm = request.getParameter("q");
        // ruleid: java-null-dereference
        if (searchTerm.isEmpty()) { // Potential null dereference
            response.getWriter().println("Please enter a search term");
        } else {
            response.getWriter().println("Searching for: " + searchTerm);
        }
    }

    @WebServlet("/login")
    public class bad_case_14 extends HttpServlet {
        @Override
        protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
            String username = request.getParameter("username");
            String password = request.getParameter("password");
            
            // ruleid: java-null-dereference
            if (username.equals("admin") && password.equals("secret")) { // Potential null dereference on both variables
                response.getWriter().println("Login successful");
            } else {
                response.getWriter().println("Login failed");
            }
        }
    }

    public void bad_case_15(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String age = request.getParameter("age");
        // ruleid: java-null-dereference
        int userAge = Integer.parseInt(age.trim()); // Potential null dereference
        
        if (userAge < 18) {
            response.getWriter().println("Access denied");
        } else {
            response.getWriter().println("Access granted");
        }
    }

    // True Negative Examples (Safe Code)

    public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String username = request.getParameter("username");
        // ok: java-null-dereference
        if (username != null) {
            int length = username.length();
            response.getWriter().println("Username length: " + length);
        } else {
            response.getWriter().println("Username not provided");
        }
    }

    public void good_case_2(HttpServletRequest request, HttpServletResponse response) {
        String email = request.getParameter("email");
        // ok: java-null-dereference
        if (email != null && email.contains("@")) {
            response.setStatus(HttpServletResponse.SC_OK);
        } else {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        }
    }

    public void good_case_3(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String id = request.getParameter("id");
        // ok: java-null-dereference
        if (id != null && !id.isEmpty()) {
            try {
                int userId = Integer.parseInt(id);
                response.getWriter().println("User ID: " + userId);
            } catch (NumberFormatException e) {
                response.getWriter().println("Invalid user ID");
            }
        } else {
            response.getWriter().println("No user ID provided");
        }
    }

    public void good_case_4(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String action = request.getParameter("action");
        // ok: java-null-dereference
        if (action != null) {
            switch (action.toLowerCase()) {
                case "add":
                    response.getWriter().println("Adding item");
                    break;
                case "remove":
                    response.getWriter().println("Removing item");
                    break;
                default:
                    response.getWriter().println("Unknown action");
            }
        } else {
            response.getWriter().println("No action specified");
        }
    }

    public void good_case_5(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String firstName = request.getParameter("firstName");
        String lastName = request.getParameter("lastName");
        
        // ok: java-null-dereference
        String fullName = (firstName != null ? firstName.trim() : "") + " " + 
                          (lastName != null ? lastName.trim() : "");
        response.getWriter().println("Full name: " + fullName);
    }

    public void good_case_6(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String quantity = request.getParameter("quantity");
        // ok: java-null-dereference
        if (quantity != null && !quantity.isEmpty()) {
            try {
                int numItems = Integer.parseInt(quantity.trim());
                response.getWriter().println("Number of items: " + numItems);
            } catch (NumberFormatException e) {
                response.getWriter().println("Invalid quantity");
            }
        } else {
            response.getWriter().println("Quantity not specified");
        }
    }

    public void good_case_7(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Map<String, Integer> prices = new HashMap<>();
        prices.put("apple", 1);
        prices.put("banana", 2);
        
        String item = request.getParameter("item");
        // ok: java-null-dereference
        if (item != null) {
            Integer price = prices.get(item.toLowerCase());
            if (price != null) {
                response.getWriter().println("Price: " + price);
            } else {
                response.getWriter().println("Item not found");
            }
        } else {
            response.getWriter().println("No item specified");
        }
    }

    public void good_case_8(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String color = request.getParameter("color");
        // ok: java-null-dereference
        String message = "Selected color: " + (color != null ? color.toUpperCase() : "none");
        response.getWriter().println(message);
    }

    public void good_case_9(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String csvData = request.getParameter("data");
        // ok: java-null-dereference
        if (csvData != null) {
            String[] values = csvData.split(",");
            response.getWriter().println("Number of values: " + values.length);
        } else {
            response.getWriter().println("No data provided");
        }
    }

    public void good_case_10(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String password = request.getParameter("password");
        // ok: java-null-dereference
        boolean isStrong = password != null && password.length() > 8 && password.matches(".*[A-Z].*");
        response.getWriter().println("Password strength: " + (isStrong ? "Strong" : "Weak"));
    }

    @PostMapping("/process")
    public void good_case_11(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String json = request.getParameter("jsonData");
        // ok: java-null-dereference
        boolean isValid = json != null && json.startsWith("{") && json.endsWith("}");
        response.getWriter().println("JSON valid: " + isValid);
    }

    public void good_case_12(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String url = request.getParameter("redirectUrl");
        // ok: java-null-dereference
        if (url != null && url.startsWith("https://")) {
            response.sendRedirect(url);
        } else {
            response.getWriter().println("Invalid URL");
        }
    }

    public void good_case_13(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String searchTerm = request.getParameter("q");
        // ok: java-null-dereference
        if (searchTerm == null || searchTerm.isEmpty()) {
            response.getWriter().println("Please enter a search term");
        } else {
            response.getWriter().println("Searching for: " + searchTerm);
        }
    }

    @WebServlet("/login")
    public class good_case_14 extends HttpServlet {
        @Override
        protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
            String username = request.getParameter("username");
            String password = request.getParameter("password");
            
            // ok: java-null-dereference
            if (username != null && password != null && 
                username.equals("admin") && password.equals("secret")) {
                response.getWriter().println("Login successful");
            } else {
                response.getWriter().println("Login failed");
            }
        }
    }

    public void good_case_15(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String ageParam = request.getParameter("age");
        // ok: java-null-dereference
        if (ageParam != null && !ageParam.trim().isEmpty()) {
            try {
                int userAge = Integer.parseInt(ageParam.trim());
                if (userAge < 18) {
                    response.getWriter().println("Access denied");
                } else {
                    response.getWriter().println("Access granted");
                }
            } catch (NumberFormatException e) {
                response.getWriter().println("Invalid age format");
            }
        } else {
            response.getWriter().println("Age not provided");
        }
    }
}
// {/fact}