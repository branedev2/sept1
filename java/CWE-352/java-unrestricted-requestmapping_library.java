import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.web.filter.OncePerRequestFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import java.io.IOException;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.http.HttpStatus;
import org.springframework.ui.Model;
import java.util.Map;
import java.util.HashMap;

// Security Issue: Insecure configuration can lead to a cross-site request forgery (CSRF) vulnerability, 
// allowing an attacker to trick authenticated users into performing unintended actions on a web application.

// True Positive Examples (Vulnerable/Insecure Code)

@Controller
class bad_case_1 {
    // ruleid: java-unrestricted-requestmapping
    @RequestMapping("/deleteAccount")
    public String deleteUserAccount() {
        // This endpoint is vulnerable to CSRF because it uses @RequestMapping without method restriction
        // and has no CSRF protection
        return "accountDeleted";
    }
}

@Controller
class bad_case_2 {
    // ruleid: java-unrestricted-requestmapping
    @RequestMapping(value = "/transferFunds")
    public String transferFunds(
            @RequestParam("toAccount") String toAccount,
            @RequestParam("amount") double amount) {
        // This endpoint allows fund transfers without CSRF protection
        // and doesn't restrict HTTP methods
        return "transferSuccess";
    }
}

@Controller
class bad_case_3 {
    // ruleid: java-unrestricted-requestmapping
    @RequestMapping(path = "/updateProfile")
    public String updateUserProfile(@RequestBody Map<String, String> profileData) {
        // This endpoint allows profile updates without CSRF protection
        // and doesn't restrict HTTP methods
        return "profileUpdated";
    }
}

@Controller
class bad_case_4 {
    // ruleid: java-unrestricted-requestmapping
    @RequestMapping(value = {"/admin/users/delete", "/admin/users/remove"})
    public String deleteUser(@RequestParam("userId") Long userId) {
        // This admin endpoint allows user deletion without CSRF protection
        // and doesn't restrict HTTP methods
        return "redirect:/admin/users";
    }
}

@Controller
class bad_case_5 {
    // ruleid: java-unrestricted-requestmapping
    @RequestMapping("/changePassword")
    public String changePassword(
            @RequestParam("oldPassword") String oldPassword,
            @RequestParam("newPassword") String newPassword) {
        // This endpoint allows password changes without CSRF protection
        // and doesn't restrict HTTP methods
        return "passwordChanged";
    }
}

@RestController
class bad_case_6 {
    // ruleid: java-unrestricted-requestmapping
    @RequestMapping("/api/orders/cancel")
    public ResponseEntity<?> cancelOrder(@RequestParam("orderId") String orderId) {
        // This API endpoint allows order cancellation without CSRF protection
        // and doesn't restrict HTTP methods
        return ResponseEntity.ok().build();
    }
}

@Controller
class bad_case_7 {
    // ruleid: java-unrestricted-requestmapping
    @RequestMapping("/subscriptions/upgrade")
    public String upgradeSubscription(@RequestParam("plan") String plan) {
        // This endpoint allows subscription upgrades without CSRF protection
        // and doesn't restrict HTTP methods
        return "subscriptionUpgraded";
    }
}

@RestController
class bad_case_8 {
    // ruleid: java-unrestricted-requestmapping
    @RequestMapping("/api/comments/post")
    public ResponseEntity<?> postComment(
            @RequestParam("articleId") Long articleId,
            @RequestParam("content") String content) {
        // This API endpoint allows comment posting without CSRF protection
        // and doesn't restrict HTTP methods
        return ResponseEntity.ok().build();
    }
}

@Controller
class bad_case_9 {
    // ruleid: java-unrestricted-requestmapping
    @RequestMapping("/settings/notifications")
    public String updateNotificationSettings(@RequestBody Map<String, Boolean> settings) {
        // This endpoint allows notification settings changes without CSRF protection
        // and doesn't restrict HTTP methods
        return "settingsUpdated";
    }
}

@RestController
class bad_case_10 {
    // ruleid: java-unrestricted-requestmapping
    @RequestMapping("/api/friends/add")
    public ResponseEntity<?> addFriend(@RequestParam("friendId") Long friendId) {
        // This API endpoint allows adding friends without CSRF protection
        // and doesn't restrict HTTP methods
        return ResponseEntity.ok().build();
    }
}

@Controller
class bad_case_11 {
    // ruleid: java-unrestricted-requestmapping
    @RequestMapping("/cart/checkout")
    public String checkoutCart() {
        // This endpoint allows cart checkout without CSRF protection
        // and doesn't restrict HTTP methods
        return "orderPlaced";
    }
}

@RestController
class bad_case_12 {
    // ruleid: java-unrestricted-requestmapping
    @RequestMapping("/api/votes/submit")
    public ResponseEntity<?> submitVote(
            @RequestParam("pollId") Long pollId,
            @RequestParam("optionId") Long optionId) {
        // This API endpoint allows vote submission without CSRF protection
        // and doesn't restrict HTTP methods
        return ResponseEntity.ok().build();
    }
}

@Controller
class bad_case_13 {
    // ruleid: java-unrestricted-requestmapping
    @RequestMapping("/account/close")
    public String closeAccount() {
        // This endpoint allows account closure without CSRF protection
        // and doesn't restrict HTTP methods
        return "accountClosed";
    }
}

@RestController
class bad_case_14 {
    // ruleid: java-unrestricted-requestmapping
    @RequestMapping("/api/messages/send")
    public ResponseEntity<?> sendMessage(
            @RequestParam("recipientId") Long recipientId,
            @RequestParam("content") String content) {
        // This API endpoint allows message sending without CSRF protection
        // and doesn't restrict HTTP methods
        return ResponseEntity.ok().build();
    }
}

@Controller
class bad_case_15 {
    // ruleid: java-unrestricted-requestmapping
    @RequestMapping("/payments/process")
    public String processPayment(
            @RequestParam("amount") double amount,
            @RequestParam("method") String method) {
        // This endpoint allows payment processing without CSRF protection
        // and doesn't restrict HTTP methods
        return "paymentProcessed";
    }
}

// True Negative Examples (Safe/Secure Code)

@Controller
class good_case_1 {
    // ok: java-unrestricted-requestmapping
    @RequestMapping(value = "/deleteAccount", method = RequestMethod.POST)
    public String deleteUserAccount() {
        // This endpoint is protected against CSRF by restricting to POST method
        // which will be protected by Spring Security's default CSRF protection
        return "accountDeleted";
    }
}

@Controller
class good_case_2 {
    // ok: java-unrestricted-requestmapping
    @PostMapping("/transferFunds")
    public String transferFunds(
            @RequestParam("toAccount") String toAccount,
            @RequestParam("amount") double amount) {
        // This endpoint uses @PostMapping which restricts to POST method
        // and will be protected by Spring Security's default CSRF protection
        return "transferSuccess";
    }
}

@RestController
class good_case_3 {
    // ok: java-unrestricted-requestmapping
    @GetMapping("/api/users")
    public ResponseEntity<?> getUsers() {
        // This endpoint is safe because it's a read-only operation using GET
        // GET requests should not modify state and are not subject to CSRF
        return ResponseEntity.ok().build();
    }
}

@Configuration
@EnableWebSecurity
class good_case_4 extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // ok: java-unrestricted-requestmapping
        http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
        
        // Properly configured security with CSRF protection enabled
    }
}

@RestController
class good_case_5 {
    // ok: java-unrestricted-requestmapping
    @DeleteMapping("/api/posts/{id}")
    public ResponseEntity<?> deletePost(@PathVariable("id") Long id) {
        // This endpoint uses @DeleteMapping which restricts to DELETE method
        // and will be protected by Spring Security's default CSRF protection
        return ResponseEntity.ok().build();
    }
}

@Controller
class good_case_6 {
    // ok: java-unrestricted-requestmapping
    @PutMapping("/updateProfile")
    public String updateUserProfile(@RequestBody Map<String, String> profileData) {
        // This endpoint uses @PutMapping which restricts to PUT method
        // and will be protected by Spring Security's default CSRF protection
        return "profileUpdated";
    }
}

@RestController
class good_case_7 {
    // ok: java-unrestricted-requestmapping
    @PatchMapping("/api/users/{id}")
    public ResponseEntity<?> partialUpdateUser(
            @PathVariable("id") Long id,
            @RequestBody Map<String, Object> updates) {
        // This endpoint uses @PatchMapping which restricts to PATCH method
        // and will be protected by Spring Security's default CSRF protection
        return ResponseEntity.ok().build();
    }
}

@Configuration
class good_case_8 {
    @Bean
    public FilterRegistrationBean<CsrfProtectionFilter> csrfFilter() {
        FilterRegistrationBean<CsrfProtectionFilter> registrationBean = new FilterRegistrationBean<>();
        
        // ok: java-unrestricted-requestmapping
        registrationBean.setFilter(new CsrfProtectionFilter());
        registrationBean.addUrlPatterns("/*");
        
        // Custom CSRF filter registration that protects all endpoints
        return registrationBean;
    }
    
    // Custom CSRF filter implementation
    private static class CsrfProtectionFilter extends OncePerRequestFilter {
        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
                throws ServletException, IOException {
            // Custom CSRF protection logic
            filterChain.doFilter(request, response);
        }
    }
}

@Configuration
@EnableWebSecurity
class good_case_9 extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // ok: java-unrestricted-requestmapping
        http.csrf()
            .ignoringAntMatchers("/api/public/**") // Only ignore for public APIs
            .csrfTokenRepository(new HttpSessionCsrfTokenRepository());
        
        // Properly configured security with CSRF protection enabled except for specific paths
    }
}

@RestController
@RequestMapping("/api/readonly")
class good_case_10 {
    // ok: java-unrestricted-requestmapping
    @RequestMapping(method = RequestMethod.GET)
    public ResponseEntity<?> getReadOnlyData() {
        // This endpoint explicitly restricts to GET method which is safe for CSRF
        return ResponseEntity.ok().build();
    }
}

@Controller
class good_case_11 {
    // ok: java-unrestricted-requestmapping
    @RequestMapping(value = "/checkout", method = {RequestMethod.POST})
    public String checkout() {
        // This endpoint explicitly restricts to POST method
        // and will be protected by Spring Security's default CSRF protection
        return "checkoutComplete";
    }
}

@ControllerAdvice
class good_case_12 {
    // ok: java-unrestricted-requestmapping
    @ModelAttribute
    public void addCsrfToken(Model model, HttpServletRequest request) {
        // This adds CSRF token to all models, helping protect all forms
        CsrfTokenRepository tokenRepository = new HttpSessionCsrfTokenRepository();
        model.addAttribute("_csrf", tokenRepository.generateToken(request));
    }
}

@Configuration
@EnableWebSecurity
class good_case_13 extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // ok: java-unrestricted-requestmapping
        http.csrf()
            .requireCsrfProtectionMatcher(
                new AntPathRequestMatcher("/**", "POST")
            );
        
        // Properly configured security with CSRF protection for all POST requests
    }
}

@RestController
class good_case_14 {
    // ok: java-unrestricted-requestmapping
    @RequestMapping(value = "/api/data", method = RequestMethod.HEAD)
    public ResponseEntity<?> checkDataExists() {
        // This endpoint explicitly restricts to HEAD method which is safe for CSRF
        return ResponseEntity.ok().build();
    }
}

@Controller
class good_case_15 {
    // ok: java-unrestricted-requestmapping
    @RequestMapping(value = "/api/options", method = RequestMethod.OPTIONS)
    public ResponseEntity<?> getOptions() {
        // This endpoint explicitly restricts to OPTIONS method which is safe for CSRF
        return ResponseEntity.ok().build();
    }
}