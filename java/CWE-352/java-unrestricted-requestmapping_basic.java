package com.example.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;

// True Positives (Vulnerable Code)

@Controller
class BadController1 {
    // ruleid: java-unrestricted-requestmapping
// {fact rule=coral-csrf-rule@v1.0 defects=1}
    @RequestMapping("/delete-account")
    public String bad_case_1() {
        // This endpoint can be accessed via any HTTP method (GET, POST, etc.)
        // making it vulnerable to CSRF attacks
        return "account-deleted";
    }
}
// {/fact}

@Controller
class BadController2 {
    // ruleid: java-unrestricted-requestmapping
// {fact rule=coral-csrf-rule@v1.0 defects=1}
    @RequestMapping(value = "/transfer-funds")
    public String bad_case_2(@RequestParam("amount") Double amount, @RequestParam("to") String recipient) {
        // No HTTP method restriction, vulnerable to CSRF
        return "funds-transferred";
    }
}
// {/fact}

@Controller
class BadController3 {
    // ruleid: java-unrestricted-requestmapping
// {fact rule=coral-csrf-rule@v1.0 defects=1}
    @RequestMapping(path = "/update-profile")
    public String bad_case_3() {
        // State-changing operation without HTTP method restriction
        return "profile-updated";
    }
}
// {/fact}

@Controller
@RequestMapping("/api")
class BadController4 {
    // ruleid: java-unrestricted-requestmapping
// {fact rule=coral-csrf-rule@v1.0 defects=1}
    @RequestMapping("/users/{id}/delete")
    public String bad_case_4(@PathVariable("id") Long userId) {
        // Destructive operation accessible via any HTTP method
        return "user-deleted";
    }
}
// {/fact}

@Controller
class BadController5 {
    // ruleid: java-unrestricted-requestmapping
// {fact rule=coral-csrf-rule@v1.0 defects=1}
    @RequestMapping(value = {"/admin/delete", "/admin/remove"})
    public String bad_case_5() {
        // Multiple paths, all vulnerable to CSRF
        return "admin-action-performed";
    }
}
// {/fact}

@Controller
class BadController6 {
    // ruleid: java-unrestricted-requestmapping
// {fact rule=coral-csrf-rule@v1.0 defects=1}
    @RequestMapping(produces = "application/json")
    public String bad_case_6() {
        // Specifies produces but not HTTP method
        return "{\"status\":\"success\"}";
    }
}
// {/fact}

@Controller
class BadController7 {
    // ruleid: java-unrestricted-requestmapping
// {fact rule=coral-csrf-rule@v1.0 defects=1}
    @RequestMapping(consumes = "application/x-www-form-urlencoded")
    public String bad_case_7() {
        // Specifies consumes but not HTTP method
        return "form-processed";
    }
}
// {/fact}

@Controller
class BadController8 {
    // ruleid: java-unrestricted-requestmapping
// {fact rule=coral-csrf-rule@v1.0 defects=1}
    @RequestMapping(headers = "Content-Type=application/json")
    public String bad_case_8() {
        // Specifies headers but not HTTP method
        return "json-processed";
    }
}
// {/fact}

@Controller
class BadController9 {
    // ruleid: java-unrestricted-requestmapping
// {fact rule=coral-csrf-rule@v1.0 defects=1}
    @RequestMapping(params = "action=save")
    public String bad_case_9() {
        // Specifies params but not HTTP method
        return "action-saved";
    }
}
// {/fact}

@EnableWebSecurity
class BadSecurityConfig10 extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // ruleid: java-unrestricted-requestmapping
        http
            .authorizeRequests()
                .anyRequest().authenticated()
                .and()
            .csrf().disable(); // Disabling CSRF protection globally
    }
    
    public String bad_case_10() {
        return "csrf-disabled";
    }
}

@Controller
class BadController11 {
    // ruleid: java-unrestricted-requestmapping
// {fact rule=coral-csrf-rule@v1.0 defects=1}
    @RequestMapping("/change-password")
    public String bad_case_11(@RequestParam("newPassword") String newPassword) {
        // Security-sensitive operation without HTTP method restriction
        return "password-changed";
    }
}
// {/fact}

@Controller
class BadController12 {
    // ruleid: java-unrestricted-requestmapping
// {fact rule=coral-csrf-rule@v1.0 defects=1}
    @RequestMapping
    public String bad_case_12() {
        // Default mapping with no path or method restrictions
        return "default-action";
    }
}
// {/fact}

@Controller
class BadController13 {
    // ruleid: java-unrestricted-requestmapping
// {fact rule=coral-csrf-rule@v1.0 defects=1}
    @RequestMapping("/submit-order")
    public String bad_case_13() {
        // Business transaction without HTTP method restriction
        return "order-submitted";
    }
}
// {/fact}

@Controller
class BadController14 {
    // ruleid: java-unrestricted-requestmapping
// {fact rule=coral-csrf-rule@v1.0 defects=1}
    @RequestMapping(value = "/api/v1/users", produces = {"application/json", "application/xml"})
    public String bad_case_14() {
        // Multiple content types but no HTTP method restriction
        return "users-data";
    }
}
// {/fact}

@Controller
class BadController15 {
    // ruleid: java-unrestricted-requestmapping
// {fact rule=coral-csrf-rule@v1.0 defects=1}
    @RequestMapping(value = "/process-payment", params = {"amount", "currency"})
    public String bad_case_15(@RequestParam("amount") Double amount, @RequestParam("currency") String currency) {
        // Financial transaction without HTTP method restriction
        return "payment-processed";
    }
}
// {/fact}

// True Negatives (Secure Code)

@Controller
class GoodController1 {
    // ok: java-unrestricted-requestmapping
// {fact rule=coral-csrf-rule@v1.0 defects=0}
    @RequestMapping(value = "/delete-account", method = RequestMethod.POST)
    public String good_case_1() {
        // This endpoint can only be accessed via POST, reducing CSRF risk
        return "account-deleted";
    }
}
// {/fact}

@Controller
class GoodController2 {
    // ok: java-unrestricted-requestmapping
// {fact rule=coral-csrf-rule@v1.0 defects=0}
    @PostMapping("/transfer-funds")
    public String good_case_2(@RequestParam("amount") Double amount, @RequestParam("to") String recipient) {
        // Using specific HTTP method annotation
        return "funds-transferred";
    }
}
// {/fact}

@Controller
class GoodController3 {
    // ok: java-unrestricted-requestmapping
// {fact rule=coral-csrf-rule@v1.0 defects=0}
    @RequestMapping(path = "/update-profile", method = {RequestMethod.PUT, RequestMethod.POST})
    public String good_case_3() {
        // Restricted to specific HTTP methods
        return "profile-updated";
    }
}
// {/fact}

@Controller
@RequestMapping("/api")
class GoodController4 {
    // ok: java-unrestricted-requestmapping
// {fact rule=coral-csrf-rule@v1.0 defects=0}
    @DeleteMapping("/users/{id}")
    public String good_case_4(@PathVariable("id") Long userId) {
        // Using specific HTTP method annotation
        return "user-deleted";
    }
}
// {/fact}

@Controller
class GoodController5 {
    // ok: java-unrestricted-requestmapping
// {fact rule=coral-csrf-rule@v1.0 defects=0}
    @GetMapping("/view-profile")
    public String good_case_5() {
        // Read-only operation using appropriate HTTP method
        return "profile-view";
    }
}
// {/fact}

@EnableWebSecurity
class GoodSecurityConfig6 extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // ok: java-unrestricted-requestmapping
        http
            .authorizeRequests()
                .anyRequest().authenticated()
                .and()
            .csrf(); // CSRF protection enabled (default)
    }
    
    public String good_case_6() {
        return "csrf-enabled";
    }
}

@Controller
class GoodController7 {
    // ok: java-unrestricted-requestmapping
// {fact rule=coral-csrf-rule@v1.0 defects=0}
    @PutMapping(value = "/update-user/{id}", consumes = "application/json")
    public String good_case_7(@PathVariable("id") Long id, @RequestBody User user) {
        // Using specific HTTP method with content type restriction
        return "user-updated";
    }
}
// {/fact}

@EnableWebSecurity
class GoodSecurityConfig8 extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // ok: java-unrestricted-requestmapping
        http
            .authorizeRequests()
                .anyRequest().authenticated()
                .and()
            .csrf()
                .csrfTokenRepository(csrfTokenRepository());
    }
    
    private CsrfTokenRepository csrfTokenRepository() {
        HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
        repository.setHeaderName("X-CSRF-TOKEN");
        return repository;
    }
    
    public String good_case_8() {
        return "custom-csrf-token";
    }
}

@Controller
class GoodController9 {
    // ok: java-unrestricted-requestmapping
// {fact rule=coral-csrf-rule@v1.0 defects=0}
    @RequestMapping(value = "/search", method = RequestMethod.GET)
    public String good_case_9(@RequestParam("query") String query) {
        // Read-only operation with explicit GET method
        return "search-results";
    }
}
// {/fact}

@Controller
class GoodController10 {
    // ok: java-unrestricted-requestmapping
// {fact rule=coral-csrf-rule@v1.0 defects=0}
    @PatchMapping("/users/{id}/status")
    public String good_case_10(@PathVariable("id") Long id, @RequestParam("status") String status) {
        // Using specific HTTP method annotation
        return "status-updated";
    }
}
// {/fact}

@Controller
class GoodController11 {
    // ok: java-unrestricted-requestmapping
// {fact rule=coral-csrf-rule@v1.0 defects=0}
    @GetMapping("/products")
    public String good_case_11() {
        // Read-only operation using appropriate HTTP method
        return "products-list";
    }
    
    // ok: java-unrestricted-requestmapping
    @PostMapping("/products")
    public String addProduct() {
        // State-changing operation using appropriate HTTP method
        return "product-added";
    }
}
// {/fact}

@EnableWebSecurity
class GoodSecurityConfig12 extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // ok: java-unrestricted-requestmapping
        http
            .authorizeRequests()
                .anyRequest().authenticated()
                .and()
            .csrf()
                .ignoringAntMatchers("/api/public/**"); // Selectively disable CSRF for specific endpoints
    }
    
    public String good_case_12() {
        return "selective-csrf-protection";
    }
}

@Controller
class GoodController13 {
    // ok: java-unrestricted-requestmapping
// {fact rule=coral-csrf-rule@v1.0 defects=0}
    @RequestMapping(value = "/change-password", method = RequestMethod.POST, consumes = "application/json")
    public String good_case_13(@RequestBody PasswordChangeRequest request) {
        // Security-sensitive operation with HTTP method restriction
        return "password-changed";
    }
}
// {/fact}

@Controller
class GoodController14 {
    // ok: java-unrestricted-requestmapping
// {fact rule=coral-csrf-rule@v1.0 defects=0}
    @PostMapping(value = "/submit-order", consumes = "application/json", produces = "application/json")
    public String good_case_14(@RequestBody Order order) {
        // Business transaction with appropriate HTTP method
        return "order-submitted";
    }
}
// {/fact}

@Controller
class GoodController15 {
    // ok: java-unrestricted-requestmapping
// {fact rule=coral-csrf-rule@v1.0 defects=0}
    @RequestMapping(value = "/process-payment", method = RequestMethod.POST, params = {"amount", "currency"})
    public String good_case_15(@RequestParam("amount") Double amount, @RequestParam("currency") String currency) {
        // Financial transaction with HTTP method restriction
        return "payment-processed";
    }
}
// {/fact}

// Helper classes for request bodies
class User {
    private String name;
    private String email;
    // getters and setters omitted
}

class PasswordChangeRequest {
    private String oldPassword;
    private String newPassword;
    // getters and setters omitted
}

class Order {
    private String productId;
    private int quantity;
    // getters and setters omitted
}