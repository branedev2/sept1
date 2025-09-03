package com.example.redirectvulnerability;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.regex.Pattern;
import java.util.ArrayList;
import java.util.List;

@Controller
public class RedirectController {

    private static final String SAFE_DOMAIN = "https://example.com";
    private static final List<String> ALLOWED_DOMAINS = new ArrayList<String>() {{
        add("example.com");
        add("safe-site.org");
    }};

    // True Positive Examples (Vulnerable Code)

// {fact rule=cross-site-scripting@v1.0 defects=1}
    @GetMapping("/bad_case_1")
    public String bad_case_1(@RequestParam("url") String url) {
        // ruleid: java-spring-unvalidated-redirect
        return "redirect:" + url;
    }

    @GetMapping("/bad_case_2")
    public ModelAndView bad_case_2(HttpServletRequest request) {
        String redirectUrl = request.getParameter("redirectUrl");
        ModelAndView modelAndView = new ModelAndView();
        // ruleid: java-spring-unvalidated-redirect
        modelAndView.setViewName("redirect:" + redirectUrl);
        return modelAndView;
    }

    @GetMapping("/bad_case_3")
    public RedirectView bad_case_3(@RequestParam("target") String target) {
        // ruleid: java-spring-unvalidated-redirect
        return new RedirectView(target);
    }

    @GetMapping("/bad_case_4")
    public void bad_case_4(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String url = request.getParameter("url");
        // ruleid: java-spring-unvalidated-redirect
        response.sendRedirect(url);
    }

    @GetMapping("/bad_case_5")
    public String bad_case_5(@RequestHeader("Redirect-To") String redirectTo) {
        // ruleid: java-spring-unvalidated-redirect
        return "redirect:" + redirectTo;
    }

    @PostMapping("/bad_case_6")
    public String bad_case_6(@RequestBody String redirectUrl) {
        // ruleid: java-spring-unvalidated-redirect
        return "redirect:" + redirectUrl;
    }

    @GetMapping("/bad_case_7")
    public RedirectView bad_case_7(HttpServletRequest request) {
        String url = request.getParameter("url");
        String finalUrl = "https://" + url;
        // ruleid: java-spring-unvalidated-redirect
        return new RedirectView(finalUrl);
    }

    @GetMapping("/bad_case_8")
    public String bad_case_8(@CookieValue("returnUrl") String returnUrl) {
        // ruleid: java-spring-unvalidated-redirect
        return "redirect:" + returnUrl;
    }

    @GetMapping("/bad_case_9")
    public ModelAndView bad_case_9(@RequestParam("page") String page) {
        String url = "/content/" + page;
        ModelAndView modelAndView = new ModelAndView();
        // ruleid: java-spring-unvalidated-redirect
        modelAndView.setViewName("redirect:" + url);
        return modelAndView;
    }

    @GetMapping("/bad_case_10")
    public String bad_case_10(HttpServletRequest request) {
        String baseUrl = request.getParameter("baseUrl");
        String path = request.getParameter("path");
        String fullUrl = baseUrl + "/" + path;
        // ruleid: java-spring-unvalidated-redirect
        return "redirect:" + fullUrl;
    }

    @GetMapping("/bad_case_11")
    public void bad_case_11(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String url = request.getParameter("url");
        if (url.startsWith("http://")) {
            url = url.replace("http://", "https://");
        }
        // ruleid: java-spring-unvalidated-redirect
        response.sendRedirect(url);
    }

    @GetMapping("/bad_case_12")
    public RedirectView bad_case_12(@RequestParam(value = "url", defaultValue = "/home") String url) {
        // ruleid: java-spring-unvalidated-redirect
        return new RedirectView(url);
    }

    @GetMapping("/bad_case_13")
    public String bad_case_13(@MatrixVariable String destination) {
        // ruleid: java-spring-unvalidated-redirect
        return "redirect:" + destination;
    }

    @GetMapping("/bad_case_14")
    public ModelAndView bad_case_14(@RequestParam("id") String id, @RequestParam("returnUrl") String returnUrl) {
        // Some processing with id
        ModelAndView modelAndView = new ModelAndView();
        // ruleid: java-spring-unvalidated-redirect
        modelAndView.setViewName("redirect:" + returnUrl);
        return modelAndView;
    }

    @GetMapping("/bad_case_15")
    public String bad_case_15(HttpServletRequest request) {
        String url = request.getQueryString();
        if (url != null && !url.isEmpty()) {
            // ruleid: java-spring-unvalidated-redirect
            return "redirect:" + url;
        }
        return "redirect:/home";
    }

    // True Negative Examples (Safe Code)

    @GetMapping("/good_case_1")
    public String good_case_1() {
        // ok: java-spring-unvalidated-redirect
        return "redirect:/home";
    }

    @GetMapping("/good_case_2")
    public ModelAndView good_case_2() {
        ModelAndView modelAndView = new ModelAndView();
        // ok: java-spring-unvalidated-redirect
        modelAndView.setViewName("redirect:/dashboard");
        return modelAndView;
    }

    @GetMapping("/good_case_3")
    public RedirectView good_case_3() {
        // ok: java-spring-unvalidated-redirect
        return new RedirectView("/login");
    }

    @GetMapping("/good_case_4")
    public void good_case_4(HttpServletResponse response) throws IOException {
        // ok: java-spring-unvalidated-redirect
        response.sendRedirect("/welcome");
    }

    @GetMapping("/good_case_5")
    public String good_case_5(@RequestParam("id") String id) {
        // ok: java-spring-unvalidated-redirect
        return "redirect:/user/" + id;
    }

    @GetMapping("/good_case_6")
    public String good_case_6(@RequestParam("url") String url) {
        // Validate against a whitelist of allowed domains
        for (String domain : ALLOWED_DOMAINS) {
            if (url.startsWith("https://" + domain)) {
                // ok: java-spring-unvalidated-redirect
                return "redirect:" + url;
            }
        }
        return "redirect:/error";
    }

    @GetMapping("/good_case_7")
    public RedirectView good_case_7(@RequestParam("page") String page) {
        // Validate that the page is local and doesn't contain path traversal
        if (page.matches("^[a-zA-Z0-9_-]+$")) {
            // ok: java-spring-unvalidated-redirect
            return new RedirectView("/pages/" + page);
        }
        return new RedirectView("/error");
    }

    @GetMapping("/good_case_8")
    public ModelAndView good_case_8(@RequestParam("returnUrl") String returnUrl) {
        ModelAndView modelAndView = new ModelAndView();
        // Validate URL is from the same site
        if (returnUrl.startsWith("/")) {
            // ok: java-spring-unvalidated-redirect
            modelAndView.setViewName("redirect:" + returnUrl);
            return modelAndView;
        }
        modelAndView.setViewName("redirect:/home");
        return modelAndView;
    }

    @GetMapping("/good_case_9")
    public String good_case_9(@RequestParam(value = "action", required = false) String action) {
        // Use a switch statement to map user input to safe redirects
        switch (action) {
            case "dashboard":
                // ok: java-spring-unvalidated-redirect
                return "redirect:/dashboard";
            case "profile":
                return "redirect:/user/profile";
            case "settings":
                return "redirect:/user/settings";
            default:
                return "redirect:/home";
        }
    }

    @GetMapping("/good_case_10")
    public void good_case_10(@RequestParam("url") String url, HttpServletResponse response) throws IOException {
        // Validate URL is from trusted domain
        if (url.startsWith(SAFE_DOMAIN)) {
            // ok: java-spring-unvalidated-redirect
            response.sendRedirect(url);
        } else {
            response.sendRedirect("/error");
        }
    }

    @GetMapping("/good_case_11")
    public RedirectView good_case_11(@RequestParam("id") String id) {
        // Validate id is numeric before using in redirect
        if (id.matches("\\d+")) {
            // ok: java-spring-unvalidated-redirect
            return new RedirectView("/product/" + id);
        }
        return new RedirectView("/products");
    }

    @GetMapping("/good_case_12")
    public String good_case_12(@RequestParam("returnUrl") String returnUrl) {
        try {
            // Validate URL using Java's URI class
            URI uri = new URI(returnUrl);
            if (uri.getHost() == null) {
                // Relative URL, safe to use
                // ok: java-spring-unvalidated-redirect
                return "redirect:" + returnUrl;
            }
        } catch (Exception e) {
            // Invalid URL
        }
        return "redirect:/home";
    }

    @GetMapping("/good_case_13")
    public ModelAndView good_case_13(@RequestParam("section") String section) {
        ModelAndView modelAndView = new ModelAndView();
        // Map user input to predefined paths
        String[] allowedSections = {"news", "events", "about", "contact"};
        for (String allowed : allowedSections) {
            if (allowed.equals(section)) {
                // ok: java-spring-unvalidated-redirect
                modelAndView.setViewName("redirect:/content/" + section);
                return modelAndView;
            }
        }
        modelAndView.setViewName("redirect:/content/home");
        return modelAndView;
    }

    @GetMapping("/good_case_14")
    public String good_case_14(@RequestParam("redirectTo") String redirectTo) {
        // Use regex pattern to validate URL format
        Pattern pattern = Pattern.compile("^/[a-zA-Z0-9/_-]*$");
        if (pattern.matcher(redirectTo).matches()) {
            // ok: java-spring-unvalidated-redirect
            return "redirect:" + redirectTo;
        }
        return "redirect:/home";
    }

    @GetMapping("/good_case_15")
    public RedirectView good_case_15(@RequestParam("external") String externalUrl) {
        // Use a service to validate URL is safe
        if (isUrlSafe(externalUrl)) {
            // ok: java-spring-unvalidated-redirect
            return new RedirectView(externalUrl);
        }
        return new RedirectView("/error");
    }
    
    private boolean isUrlSafe(String url) {
        // Implementation of URL safety check
        // This could check against whitelist, validate domain, etc.
        for (String domain : ALLOWED_DOMAINS) {
            if (url.startsWith("https://" + domain)) {
                return true;
            }
        }
        return false;
    }
}
// {/fact}