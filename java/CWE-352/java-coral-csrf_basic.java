package com.example.csrf;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.web.filter.CorsFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import java.util.HashMap;
import java.util.Map;
import java.io.IOException;
import java.util.UUID;

@Controller
public class CsrfExampleController {

    // True Positives (Vulnerable Code)

// {fact rule=coral-csrf-rule@v1.0 defects=1}
    @PostMapping("/bad_case_1")
    public String bad_case_1(HttpServletRequest request) {
        // ruleid: java-coral-csrf
        String username = request.getParameter("username");
        updateUserProfile(username, "newValue");
        return "success";
    }

    @PutMapping("/bad_case_2")
    public void bad_case_2(@RequestBody Map<String, String> payload) {
        // ruleid: java-coral-csrf
        String userId = payload.get("userId");
        String newEmail = payload.get("email");
        updateUserEmail(userId, newEmail);
    }

    @DeleteMapping("/bad_case_3")
    public void bad_case_3(@PathVariable("id") String id) {
        // ruleid: java-coral-csrf
        deleteUserAccount(id);
    }

    @RequestMapping(value = "/bad_case_4", method = RequestMethod.POST)
    public String bad_case_4(HttpServletRequest request) {
        // ruleid: java-coral-csrf
        String accountId = request.getParameter("accountId");
        double amount = Double.parseDouble(request.getParameter("amount"));
        transferFunds(accountId, amount);
        return "redirect:/dashboard";
    }

    @PostMapping("/bad_case_5")
    public void bad_case_5(@RequestParam("password") String newPassword, @RequestParam("userId") String userId) {
        // ruleid: java-coral-csrf
        changePassword(userId, newPassword);
    }

    @RequestMapping(value = "/bad_case_6", method = RequestMethod.POST)
    public String bad_case_6(HttpServletRequest request) {
        // ruleid: java-coral-csrf
        String productId = request.getParameter("productId");
        int quantity = Integer.parseInt(request.getParameter("quantity"));
        addToCart(productId, quantity);
        return "cart";
    }

    @PostMapping("/bad_case_7")
    public void bad_case_7(@RequestBody Map<String, Object> orderDetails) {
        // ruleid: java-coral-csrf
        createOrder(orderDetails);
    }

    @PutMapping("/bad_case_8")
    public void bad_case_8(@RequestParam("status") String status, @RequestParam("orderId") String orderId) {
        // ruleid: java-coral-csrf
        updateOrderStatus(orderId, status);
    }

    @PostMapping("/bad_case_9")
    public String bad_case_9(HttpServletRequest request) {
        // ruleid: java-coral-csrf
        String email = request.getParameter("email");
        subscribeToNewsletter(email);
        return "subscribed";
    }

    @RequestMapping(value = "/bad_case_10", method = RequestMethod.POST)
    public void bad_case_10(@RequestBody Map<String, String> userData) {
        // ruleid: java-coral-csrf
        registerUser(userData.get("username"), userData.get("email"), userData.get("password"));
    }

    @DeleteMapping("/bad_case_11")
    public void bad_case_11(@PathVariable("commentId") String commentId) {
        // ruleid: java-coral-csrf
        deleteComment(commentId);
    }

    @PostMapping("/bad_case_12")
    public String bad_case_12(HttpServletRequest request) {
        // ruleid: java-coral-csrf
        String recipient = request.getParameter("recipient");
        String message = request.getParameter("message");
        sendMessage(recipient, message);
        return "messageSent";
    }

    @PutMapping("/bad_case_13")
    public void bad_case_13(@RequestBody Map<String, Object> settings) {
        // ruleid: java-coral-csrf
        updateUserSettings(settings);
    }

    @PostMapping("/bad_case_14")
    public String bad_case_14(HttpServletRequest request) {
        // ruleid: java-coral-csrf
        String reviewText = request.getParameter("review");
        String productId = request.getParameter("productId");
        int rating = Integer.parseInt(request.getParameter("rating"));
        submitProductReview(productId, reviewText, rating);
        return "reviewSubmitted";
    }

    @RequestMapping(value = "/bad_case_15", method = RequestMethod.POST)
    public void bad_case_15(@RequestParam("friendId") String friendId) {
        // ruleid: java-coral-csrf
        addFriend(friendId);
    }

    // True Negatives (Secure Code)

    @PostMapping("/good_case_1")
    public String good_case_1(HttpServletRequest request, @RequestParam("_csrf") String csrfToken) {
        HttpSession session = request.getSession();
        String expectedToken = (String) session.getAttribute("CSRF_TOKEN");
        
        // ok: java-coral-csrf
        if (csrfToken != null && csrfToken.equals(expectedToken)) {
            String username = request.getParameter("username");
            updateUserProfile(username, "newValue");
            return "success";
        }
        return "error";
    }

    @PutMapping("/good_case_2")
    public void good_case_2(@RequestBody Map<String, String> payload, @RequestHeader("X-CSRF-TOKEN") String csrfToken, HttpServletRequest request) {
        CsrfToken token = (CsrfToken) request.getAttribute("_csrf");
        
        // ok: java-coral-csrf
        if (token != null && token.getToken().equals(csrfToken)) {
            String userId = payload.get("userId");
            String newEmail = payload.get("email");
            updateUserEmail(userId, newEmail);
        }
    }

    @DeleteMapping("/good_case_3")
    public void good_case_3(@PathVariable("id") String id, @RequestHeader("X-CSRF-TOKEN") String csrfToken, HttpSession session) {
        String expectedToken = (String) session.getAttribute("CSRF_TOKEN");
        
        // ok: java-coral-csrf
        if (csrfToken != null && csrfToken.equals(expectedToken)) {
            deleteUserAccount(id);
        }
    }

    @RequestMapping(value = "/good_case_4", method = RequestMethod.POST)
    public String good_case_4(HttpServletRequest request) {
        CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        String csrfToken = request.getParameter("_csrf");
        
        // ok: java-coral-csrf
        if (token != null && token.getToken().equals(csrfToken)) {
            String accountId = request.getParameter("accountId");
            double amount = Double.parseDouble(request.getParameter("amount"));
            transferFunds(accountId, amount);
            return "redirect:/dashboard";
        }
        return "error";
    }

    @PostMapping("/good_case_5")
    @CsrfProtected
    public void good_case_5(@RequestParam("password") String newPassword, @RequestParam("userId") String userId) {
        // ok: java-coral-csrf
        // The @CsrfProtected annotation ensures CSRF protection
        changePassword(userId, newPassword);
    }

    @Configuration
    @EnableWebSecurity
    public static class WebSecurityConfig extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            // ok: java-coral-csrf
            http.csrf().csrfTokenRepository(csrfTokenRepository());
        }
        
        private CsrfTokenRepository csrfTokenRepository() {
            HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
            repository.setHeaderName("X-CSRF-TOKEN");
            return repository;
        }
    }

    public static class CsrfFilter extends OncePerRequestFilter {
        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, javax.servlet.FilterChain filterChain) throws javax.servlet.ServletException, IOException {
            // ok: java-coral-csrf
            CsrfToken csrf = new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", UUID.randomUUID().toString());
            request.setAttribute(CsrfToken.class.getName(), csrf);
            request.setAttribute("_csrf", csrf);
            filterChain.doFilter(request, response);
        }
    }

    @PostMapping("/good_case_7")
    public void good_case_7(@RequestBody Map<String, Object> orderDetails, HttpServletRequest request) {
        String csrfToken = request.getHeader("X-CSRF-TOKEN");
        HttpSession session = request.getSession();
        String expectedToken = (String) session.getAttribute("CSRF_TOKEN");
        
        // ok: java-coral-csrf
        if (csrfToken != null && csrfToken.equals(expectedToken)) {
            createOrder(orderDetails);
        }
    }

    @PutMapping("/good_case_8")
    public void good_case_8(@RequestParam("status") String status, @RequestParam("orderId") String orderId, 
                           @RequestParam("_csrf") String csrfToken, HttpServletRequest request) {
        CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        
        // ok: java-coral-csrf
        if (token != null && token.getToken().equals(csrfToken)) {
            updateOrderStatus(orderId, status);
        }
    }

    @PostMapping("/good_case_9")
    public String good_case_9(HttpServletRequest request) {
        String csrfToken = request.getParameter("_csrf");
        HttpSession session = request.getSession();
        String expectedToken = (String) session.getAttribute("CSRF_TOKEN");
        
        // ok: java-coral-csrf
        if (csrfToken != null && csrfToken.equals(expectedToken)) {
            String email = request.getParameter("email");
            subscribeToNewsletter(email);
            return "subscribed";
        }
        return "error";
    }

    public static class CsrfSecurityRequestMatcher implements org.springframework.security.web.util.matcher.RequestMatcher {
        @Override
        public boolean matches(HttpServletRequest request) {
            // ok: java-coral-csrf
            return true; // This would normally have logic to determine which requests need CSRF protection
        }
    }

    @GetMapping("/good_case_11")
    public String good_case_11(HttpServletRequest request, HttpServletResponse response) {
        // ok: java-coral-csrf
        // GET requests are idempotent and don't change state, so they don't need CSRF protection
        return "viewPage";
    }

    @PostMapping("/good_case_12")
    public String good_case_12(HttpServletRequest request) {
        CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        String csrfToken = request.getParameter("_csrf");
        
        // ok: java-coral-csrf
        if (token != null && token.getToken().equals(csrfToken)) {
            String recipient = request.getParameter("recipient");
            String message = request.getParameter("message");
            sendMessage(recipient, message);
            return "messageSent";
        }
        return "error";
    }

    @PutMapping("/good_case_13")
    public void good_case_13(@RequestBody Map<String, Object> settings, 
                            @RequestHeader("X-CSRF-TOKEN") String csrfToken, 
                            HttpServletRequest request) {
        CsrfToken token = (CsrfToken) request.getAttribute("_csrf");
        
        // ok: java-coral-csrf
        if (token != null && token.getToken().equals(csrfToken)) {
            updateUserSettings(settings);
        }
    }

    @PostMapping("/good_case_14")
    public String good_case_14(HttpServletRequest request, @RequestParam("_csrf") String csrfToken) {
        CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        
        // ok: java-coral-csrf
        if (token != null && token.getToken().equals(csrfToken)) {
            String reviewText = request.getParameter("review");
            String productId = request.getParameter("productId");
            int rating = Integer.parseInt(request.getParameter("rating"));
            submitProductReview(productId, reviewText, rating);
            return "reviewSubmitted";
        }
        return "error";
    }

    @RequestMapping(value = "/good_case_15", method = RequestMethod.POST)
    public void good_case_15(@RequestParam("friendId") String friendId, 
                            @RequestParam("_csrf") String csrfToken, 
                            HttpSession session) {
        String expectedToken = (String) session.getAttribute("CSRF_TOKEN");
        
        // ok: java-coral-csrf
        if (csrfToken != null && csrfToken.equals(expectedToken)) {
            addFriend(friendId);
        }
    }

    // Helper methods
    private void updateUserProfile(String username, String value) {
        // Implementation for updating user profile
    }

    private void updateUserEmail(String userId, String email) {
        // Implementation for updating user email
    }

    private void deleteUserAccount(String id) {
        // Implementation for deleting user account
    }

    private void transferFunds(String accountId, double amount) {
        // Implementation for transferring funds
    }

    private void changePassword(String userId, String newPassword) {
        // Implementation for changing password
    }

    private void addToCart(String productId, int quantity) {
        // Implementation for adding to cart
    }

    private void createOrder(Map<String, Object> orderDetails) {
        // Implementation for creating an order
    }

    private void updateOrderStatus(String orderId, String status) {
        // Implementation for updating order status
    }

    private void subscribeToNewsletter(String email) {
        // Implementation for newsletter subscription
    }

    private void registerUser(String username, String email, String password) {
        // Implementation for user registration
    }

    private void deleteComment(String commentId) {
        // Implementation for deleting a comment
    }

    private void sendMessage(String recipient, String message) {
        // Implementation for sending a message
    }

    private void updateUserSettings(Map<String, Object> settings) {
        // Implementation for updating user settings
    }

    private void submitProductReview(String productId, String reviewText, int rating) {
        // Implementation for submitting a product review
    }

    private void addFriend(String friendId) {
        // Implementation for adding a friend
    }
}
// {/fact}

@interface CsrfProtected {
    // Custom annotation for CSRF protection
}