import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.regex.Pattern;
import java.util.List;
import java.util.Arrays;
import org.springframework.util.StringUtils;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.web.util.UriComponentsBuilder;
import org.thymeleaf.context.WebContext;
import org.thymeleaf.spring5.SpringTemplateEngine;
import jakarta.validation.constraints.NotBlank;
import org.apache.commons.validator.routines.UrlValidator;

// Security Issue: Unvalidated Redirects in Spring Framework Applications

// True Positive Examples (Vulnerable/Insecure Code)

@Controller
class BadCase1 {
// {fact rule=cross-site-scripting@v1.0 defects=1}
    @GetMapping("/redirect1")
    public String bad_case_1(HttpServletRequest request) {
        String url = request.getParameter("url");
        // ruleid: java-spring-unvalidated-redirect
        return "redirect:" + url;
    }
}
// {/fact}

@Controller
class BadCase2 {
// {fact rule=cross-site-scripting@v1.0 defects=1}
    @GetMapping("/redirect2")
    public ModelAndView bad_case_2(@RequestParam String targetUrl) {
        // ruleid: java-spring-unvalidated-redirect
        return new ModelAndView("redirect:" + targetUrl);
    }
}
// {/fact}

@Controller
class BadCase3 {
// {fact rule=cross-site-scripting@v1.0 defects=1}
    @GetMapping("/redirect3")
    public RedirectView bad_case_3(@RequestParam("destination") String destination) {
        // ruleid: java-spring-unvalidated-redirect
        return new RedirectView(destination);
    }
}
// {/fact}

@Controller
class BadCase4 {
// {fact rule=cross-site-scripting@v1.0 defects=1}
    @GetMapping("/redirect4")
    public void bad_case_4(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String redirectUrl = request.getParameter("redirectUrl");
        // ruleid: java-spring-unvalidated-redirect
        response.sendRedirect(redirectUrl);
    }
}
// {/fact}

@Controller
class BadCase5 {
// {fact rule=cross-site-scripting@v1.0 defects=1}
    @GetMapping("/redirect5")
    public ResponseEntity<Void> bad_case_5(@RequestHeader("Redirect-To") String redirectTo) {
        // ruleid: java-spring-unvalidated-redirect
        return ResponseEntity.status(HttpStatus.FOUND)
                .header("Location", redirectTo)
                .build();
    }
}
// {/fact}

@RestController
class BadCase6 {
    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
    
// {fact rule=cross-site-scripting@v1.0 defects=1}
    @GetMapping("/redirect6")
    public void bad_case_6(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String redirectUrl = request.getParameter("to");
        // ruleid: java-spring-unvalidated-redirect
        redirectStrategy.sendRedirect(request, response, redirectUrl);
    }
}
// {/fact}

@Controller
class BadCase7 {
    @GetMapping("/redirect7")
    public String bad_case_7(@RequestParam(required = false) String redirectPath) {
        if (redirectPath != null) {
            // ruleid: java-spring-unvalidated-redirect
            return String.format("redirect:%s", redirectPath);
        }
        return "home";
    }
}

@Controller
class BadCase8 {
// {fact rule=cross-site-scripting@v1.0 defects=1}
    @PostMapping("/redirect8")
    public RedirectView bad_case_8(@RequestBody RedirectRequest redirectRequest) {
        // ruleid: java-spring-unvalidated-redirect
        RedirectView redirectView = new RedirectView();
        redirectView.setUrl(redirectRequest.getRedirectUrl());
        return redirectView;
    }
    
    static class RedirectRequest {
        private String redirectUrl;
        public String getRedirectUrl() { return redirectUrl; }
        public void setRedirectUrl(String redirectUrl) { this.redirectUrl = redirectUrl; }
    }
}
// {/fact}

@Controller
class BadCase9 {
// {fact rule=cross-site-scripting@v1.0 defects=1}
    @GetMapping("/redirect9")
    public ModelAndView bad_case_9(HttpServletRequest request) {
        String url = request.getParameter("url");
        ModelAndView mav = new ModelAndView();
        // ruleid: java-spring-unvalidated-redirect
        mav.setViewName("redirect:" + url);
        return mav;
    }
}
// {/fact}

@Controller
class BadCase10 {
// {fact rule=cross-site-scripting@v1.0 defects=1}
    @GetMapping("/redirect10")
    public ResponseEntity<Void> bad_case_10(@RequestParam String target) {
        URI location = URI.create(target);
        // ruleid: java-spring-unvalidated-redirect
        return ResponseEntity.status(HttpStatus.TEMPORARY_REDIRECT)
                .location(location)
                .build();
    }
}
// {/fact}

@Controller
class BadCase11 {
// {fact rule=cross-site-scripting@v1.0 defects=1}
    @GetMapping("/redirect11")
    public String bad_case_11(@CookieValue("redirect_url") String redirectUrl) {
        // ruleid: java-spring-unvalidated-redirect
        return "redirect:" + redirectUrl;
    }
}
// {/fact}

@Controller
class BadCase12 {
// {fact rule=cross-site-scripting@v1.0 defects=1}
    @GetMapping("/redirect12/{path}")
    public String bad_case_12(@PathVariable String path) {
        // ruleid: java-spring-unvalidated-redirect
        return "redirect:/" + path;
    }
}
// {/fact}

@Controller
class BadCase13 {
    private SpringTemplateEngine templateEngine;
    
// {fact rule=cross-site-scripting@v1.0 defects=1}
    @GetMapping("/redirect13")
    public void bad_case_13(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String redirectUrl = request.getParameter("next");
        // ruleid: java-spring-unvalidated-redirect
        response.setHeader("Location", redirectUrl);
        response.setStatus(302);
    }
}
// {/fact}

@Controller
class BadCase14 {
    @GetMapping("/redirect14")
    public String bad_case_14(@RequestParam(name = "returnTo", defaultValue = "/home") String returnTo) {
        // ruleid: java-spring-unvalidated-redirect
        return "redirect:" + returnTo;
    }
}

@Controller
class BadCase15 {
// {fact rule=cross-site-scripting@v1.0 defects=1}
    @GetMapping("/redirect15")
    public RedirectView bad_case_15(HttpServletRequest request) {
        String url = request.getQueryString().split("=")[1];
        // ruleid: java-spring-unvalidated-redirect
        return new RedirectView(url);
    }
}
// {/fact}

// True Negative Examples (Safe/Secure Code)

@Controller
class GoodCase1 {
    private static final String SAFE_REDIRECT_URL = "/dashboard";
    
// {fact rule=cross-site-scripting@v1.0 defects=0}
    @GetMapping("/safe-redirect1")
    public String good_case_1(HttpServletRequest request) {
        String url = request.getParameter("url");
        // Ignoring user input, using a constant instead
        // ok: java-spring-unvalidated-redirect
        return "redirect:" + SAFE_REDIRECT_URL;
    }
}
// {/fact}

@Controller
class GoodCase2 {
    private final List<String> ALLOWED_REDIRECT_HOSTS = Arrays.asList("example.com", "trusted-site.org");
    
// {fact rule=cross-site-scripting@v1.0 defects=0}
    @GetMapping("/safe-redirect2")
    public ModelAndView good_case_2(@RequestParam String targetUrl) {
        URI uri = URI.create(targetUrl);
        String host = uri.getHost();
        
        if (ALLOWED_REDIRECT_HOSTS.contains(host)) {
            // ok: java-spring-unvalidated-redirect
            return new ModelAndView("redirect:" + targetUrl);
        }
        return new ModelAndView("redirect:/default");
    }
}
// {/fact}

@Controller
class GoodCase3 {
// {fact rule=cross-site-scripting@v1.0 defects=0}
    @GetMapping("/safe-redirect3")
    public RedirectView good_case_3(@RequestParam("destination") String destination) {
        // Validate that the URL is relative (starts with /)
        if (destination != null && destination.startsWith("/") && !destination.contains("://")) {
            // ok: java-spring-unvalidated-redirect
            return new RedirectView(destination);
        }
        return new RedirectView("/home");
    }
}
// {/fact}

@Controller
class GoodCase4 {
    private static final Pattern SAFE_REDIRECT_PATTERN = Pattern.compile("^/(dashboard|profile|settings|logout)$");
    
// {fact rule=cross-site-scripting@v1.0 defects=0}
    @GetMapping("/safe-redirect4")
    public void good_case_4(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String redirectUrl = request.getParameter("redirectUrl");
        
        if (redirectUrl != null && SAFE_REDIRECT_PATTERN.matcher(redirectUrl).matches()) {
            // ok: java-spring-unvalidated-redirect
            response.sendRedirect(redirectUrl);
        } else {
            response.sendRedirect("/home");
        }
    }
}
// {/fact}

@Controller
class GoodCase5 {
    private static final List<String> ALLOWED_URLS = Arrays.asList("/home", "/dashboard", "/profile");
    
// {fact rule=cross-site-scripting@v1.0 defects=0}
    @GetMapping("/safe-redirect5")
    public ResponseEntity<Void> good_case_5(@RequestHeader("Redirect-To") String redirectTo) {
        String safeRedirect = "/home"; // Default
        
        if (ALLOWED_URLS.contains(redirectTo)) {
            safeRedirect = redirectTo;
        }
        
        // ok: java-spring-unvalidated-redirect
        return ResponseEntity.status(HttpStatus.FOUND)
                .header("Location", safeRedirect)
                .build();
    }
}
// {/fact}

@RestController
class GoodCase6 {
    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
    private static final String[] ALLOWED_PATHS = {"/login", "/dashboard", "/account"};
    
// {fact rule=cross-site-scripting@v1.0 defects=0}
    @GetMapping("/safe-redirect6")
    public void good_case_6(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String redirectUrl = request.getParameter("to");
        String safeUrl = "/home"; // Default
        
        for (String path : ALLOWED_PATHS) {
            if (path.equals(redirectUrl)) {
                safeUrl = path;
                break;
            }
        }
        
        // ok: java-spring-unvalidated-redirect
        redirectStrategy.sendRedirect(request, response, safeUrl);
    }
}
// {/fact}

@Controller
class GoodCase7 {
    @GetMapping("/safe-redirect7")
    public String good_case_7(@RequestParam(required = false) String redirectPath) {
        // Using a switch statement with predefined values
        switch (redirectPath) {
            case "dashboard":
                // ok: java-spring-unvalidated-redirect
                return "redirect:/dashboard";
            case "profile":
                // ok: java-spring-unvalidated-redirect
                return "redirect:/profile";
            default:
                // ok: java-spring-unvalidated-redirect
                return "redirect:/home";
        }
    }
}

@Controller
class GoodCase8 {
// {fact rule=cross-site-scripting@v1.0 defects=0}
    @PostMapping("/safe-redirect8")
    public RedirectView good_case_8(@RequestBody RedirectRequest redirectRequest) {
        RedirectView redirectView = new RedirectView();
        
        // Validate URL is internal by ensuring it starts with / and doesn't have protocol
        String url = redirectRequest.getRedirectUrl();
        if (url != null && url.startsWith("/") && !url.contains("://")) {
            // ok: java-spring-unvalidated-redirect
            redirectView.setUrl(url);
        } else {
            redirectView.setUrl("/default");
        }
        
        return redirectView;
    }
    
    static class RedirectRequest {
        private String redirectUrl;
        public String getRedirectUrl() { return redirectUrl; }
        public void setRedirectUrl(String redirectUrl) { this.redirectUrl = redirectUrl; }
    }
}
// {/fact}

@Controller
class GoodCase9 {
    private static final String DOMAIN_WHITELIST = "example\\.com|trusted-site\\.org";
    
// {fact rule=cross-site-scripting@v1.0 defects=0}
    @GetMapping("/safe-redirect9")
    public ModelAndView good_case_9(HttpServletRequest request) {
        String url = request.getParameter("url");
        ModelAndView mav = new ModelAndView();
        
        // Validate URL against whitelist
        if (url != null && url.matches("https?://(" + DOMAIN_WHITELIST + ")(/.*)?")) {
            // ok: java-spring-unvalidated-redirect
            mav.setViewName("redirect:" + url);
        } else {
            mav.setViewName("redirect:/home");
        }
        
        return mav;
    }
}
// {/fact}

@Controller
class GoodCase10 {
// {fact rule=cross-site-scripting@v1.0 defects=0}
    @GetMapping("/safe-redirect10")
    public ResponseEntity<Void> good_case_10(@RequestParam String target) {
        // Using UriComponentsBuilder to create a relative URL
        URI location = UriComponentsBuilder.fromPath("/")
                .path(target.startsWith("/") ? target.substring(1) : target)
                .build()
                .toUri();
        
        // ok: java-spring-unvalidated-redirect
        return ResponseEntity.status(HttpStatus.TEMPORARY_REDIRECT)
                .location(location)
                .build();
    }
}
// {/fact}

@Controller
class GoodCase11 {
// {fact rule=cross-site-scripting@v1.0 defects=0}
    @GetMapping("/safe-redirect11")
    public String good_case_11(@CookieValue("redirect_url") String redirectUrl) {
        // Map external URLs to internal paths
        Map<String, String> allowedRedirects = Map.of(
            "dashboard", "/dashboard",
            "profile", "/profile",
            "settings", "/settings"
        );
        
        // ok: java-spring-unvalidated-redirect
        return "redirect:" + allowedRedirects.getOrDefault(redirectUrl, "/home");
    }
}
// {/fact}

@Controller
class GoodCase12 {
// {fact rule=cross-site-scripting@v1.0 defects=0}
    @GetMapping("/safe-redirect12/{path}")
    public String good_case_12(@PathVariable String path) {
        // Validate path parameter against allowed values
        List<String> allowedPaths = Arrays.asList("dashboard", "profile", "settings");
        
        if (allowedPaths.contains(path)) {
            // ok: java-spring-unvalidated-redirect
            return "redirect:/" + path;
        }
        return "redirect:/home";
    }
}
// {/fact}

@Controller
class GoodCase13 {
// {fact rule=cross-site-scripting@v1.0 defects=0}
    @GetMapping("/safe-redirect13")
    public void good_case_13(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String redirectUrl = request.getParameter("next");
        
        // Use URL validator to ensure it's a valid URL and on the same host
        UrlValidator urlValidator = new UrlValidator();
        String currentHost = request.getServerName();
        
        if (redirectUrl != null && redirectUrl.startsWith("/")) {
            // ok: java-spring-unvalidated-redirect
            response.setHeader("Location", redirectUrl);
            response.setStatus(302);
        } else {
            response.setHeader("Location", "/home");
            response.setStatus(302);
        }
    }
}
// {/fact}

@Controller
class GoodCase14 {
    @GetMapping("/safe-redirect14")
    public String good_case_14(@RequestParam(name = "returnTo", defaultValue = "/home") String returnTo) {
        // Ensure URL is relative and doesn't try to escape the application
        if (returnTo.startsWith("/") && !returnTo.contains("..")) {
            // ok: java-spring-unvalidated-redirect
            return "redirect:" + returnTo;
        }
        return "redirect:/home";
    }
}

@Controller
class GoodCase15 {
    private static final Map<String, String> URL_MAPPING = Map.of(
        "dashboard", "/dashboard",
        "profile", "/user/profile",
        "settings", "/user/settings",
        "logout", "/auth/logout"
    );
    
// {fact rule=cross-site-scripting@v1.0 defects=0}
    @GetMapping("/safe-redirect15")
    public RedirectView good_case_15(HttpServletRequest request) {
        String key = request.getParameter("page");
        // Map user input to predefined URLs
        String url = URL_MAPPING.getOrDefault(key, "/home");
        
        // ok: java-spring-unvalidated-redirect
        return new RedirectView(url);
    }
}
// {/fact}

// Helper class for request body examples
class RedirectRequest {
    private String redirectUrl;
    
    public String getRedirectUrl() {
        return redirectUrl;
    }
    
    public void setRedirectUrl(String redirectUrl) {
        this.redirectUrl = redirectUrl;
    }
}