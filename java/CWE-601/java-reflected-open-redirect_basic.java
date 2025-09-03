import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpSession;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.regex.Pattern;
import java.util.ArrayList;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.stereotype.Controller;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;
import org.owasp.encoder.Encode;

public class ReflectedOpenRedirectExamples extends HttpServlet {

    // True Positive Examples (Vulnerable Code)

// {fact rule=cross-site-scripting@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String url = request.getParameter("url");
        // ruleid: java-reflected-open-redirect
        response.sendRedirect(url);
    }

    public void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String redirectUrl = request.getParameter("redirect");
        String finalUrl = redirectUrl + "?processed=true";
        // ruleid: java-reflected-open-redirect
        response.sendRedirect(finalUrl);
    }

    public void bad_case_3(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String target = request.getHeader("Referer");
        if (target != null) {
            // ruleid: java-reflected-open-redirect
            response.sendRedirect(target);
        } else {
            response.sendRedirect("/home");
        }
    }

    @GetMapping("/login")
    public void bad_case_4(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String returnTo = request.getParameter("returnTo");
        if (authenticate(request)) {
            // ruleid: java-reflected-open-redirect
            response.sendRedirect(returnTo);
        } else {
            response.sendRedirect("/login-failed");
        }
    }

    @RequestMapping("/checkout")
    public void bad_case_5(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Cookie[] cookies = request.getCookies();
        String redirectUrl = null;
        
        for (Cookie cookie : cookies) {
            if (cookie.getName().equals("redirect_after_purchase")) {
                redirectUrl = cookie.getValue();
                break;
            }
        }
        
        if (redirectUrl != null) {
            // ruleid: java-reflected-open-redirect
            response.sendRedirect(redirectUrl);
        }
    }

    @RequestMapping("/process")
    public ModelAndView bad_case_6(HttpServletRequest request) {
        String redirectUrl = request.getParameter("next");
        // ruleid: java-reflected-open-redirect
        return new ModelAndView("redirect:" + redirectUrl);
    }

    @GetMapping("/oauth/callback")
    public void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String state = request.getParameter("state");
        String[] parts = state.split(":");
        String redirectUrl = parts[0];
        // ruleid: java-reflected-open-redirect
        response.sendRedirect(redirectUrl);
    }

    @RequestMapping("/redirect")
    public RedirectView bad_case_8(@RequestParam String destination) {
        // ruleid: java-reflected-open-redirect
        return new RedirectView(destination);
    }

    @GetMapping("/sso/complete")
    public void bad_case_9(HttpServletRequest request, HttpServletResponse response) throws IOException {
        HttpSession session = request.getSession();
        String redirectUrl = (String) session.getAttribute("originalRequestUrl");
        // ruleid: java-reflected-open-redirect
        response.sendRedirect(redirectUrl);
    }

    @RequestMapping("/error")
    public void bad_case_10(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String errorPage = request.getParameter("errorPage");
        String errorCode = request.getParameter("code");
        // ruleid: java-reflected-open-redirect
        response.sendRedirect(errorPage + "?code=" + errorCode);
    }

    @GetMapping("/language")
    public void bad_case_11(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String lang = request.getParameter("lang");
        String returnUrl = request.getParameter("returnUrl");
        
        // Set language preference
        Cookie cookie = new Cookie("language", lang);
        response.addCookie(cookie);
        
        // ruleid: java-reflected-open-redirect
        response.sendRedirect(returnUrl);
    }

    @RequestMapping("/download")
    public void bad_case_12(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String file = request.getParameter("file");
        String redirectOnComplete = request.getParameter("redirectOnComplete");
        
        // Process download logic here
        
        if (downloadSuccessful) {
            // ruleid: java-reflected-open-redirect
            response.sendRedirect(redirectOnComplete);
        }
    }

    @GetMapping("/share")
    public void bad_case_13(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String shareUrl = request.getParameter("url");
        String platform = request.getParameter("platform");
        
        if ("twitter".equals(platform)) {
            // ruleid: java-reflected-open-redirect
            response.sendRedirect("https://twitter.com/intent/tweet?url=" + shareUrl);
        } else if ("facebook".equals(platform)) {
            // ruleid: java-reflected-open-redirect
            response.sendRedirect("https://www.facebook.com/sharer/sharer.php?u=" + shareUrl);
        }
    }

    @RequestMapping("/payment/complete")
    public void bad_case_14(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String successUrl = request.getParameter("successUrl");
        String failureUrl = request.getParameter("failureUrl");
        
        boolean paymentSuccess = processPayment(request);
        
        if (paymentSuccess) {
            // ruleid: java-reflected-open-redirect
            response.sendRedirect(successUrl);
        } else {
            // ruleid: java-reflected-open-redirect
            response.sendRedirect(failureUrl);
        }
    }

    @GetMapping("/external-link")
    public void bad_case_15(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String externalUrl = request.getParameter("url");
        
        // Add tracking parameter
        String trackingUrl = externalUrl + (externalUrl.contains("?") ? "&" : "?") + "source=ourwebsite";
        
        // ruleid: java-reflected-open-redirect
        response.sendRedirect(trackingUrl);
    }

    // True Negative Examples (Secure Code)

    public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String url = request.getParameter("url");
        // ok: java-reflected-open-redirect
        response.sendRedirect("/dashboard");
    }

    public void good_case_2(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String redirectUrl = request.getParameter("redirect");
        List<String> allowedUrls = new ArrayList<>();
        allowedUrls.add("/home");
        allowedUrls.add("/dashboard");
        allowedUrls.add("/profile");
        
        // ok: java-reflected-open-redirect
        if (allowedUrls.contains(redirectUrl)) {
            response.sendRedirect(redirectUrl);
        } else {
            response.sendRedirect("/home");
        }
    }

    public void good_case_3(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String target = request.getHeader("Referer");
        // ok: java-reflected-open-redirect
        if (target != null && target.startsWith("https://mywebsite.com/")) {
            response.sendRedirect(target);
        } else {
            response.sendRedirect("/home");
        }
    }

    @GetMapping("/login")
    public void good_case_4(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String returnTo = request.getParameter("returnTo");
        // ok: java-reflected-open-redirect
        if (returnTo != null && returnTo.startsWith("/") && !returnTo.contains("//")) {
            response.sendRedirect(returnTo);
        } else {
            response.sendRedirect("/dashboard");
        }
    }

    @RequestMapping("/checkout")
    public void good_case_5(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Cookie[] cookies = request.getCookies();
        String redirectUrl = null;
        
        for (Cookie cookie : cookies) {
            if (cookie.getName().equals("redirect_after_purchase")) {
                redirectUrl = cookie.getValue();
                break;
            }
        }
        
        // ok: java-reflected-open-redirect
        if (redirectUrl != null && isValidRedirectUrl(redirectUrl)) {
            response.sendRedirect(redirectUrl);
        } else {
            response.sendRedirect("/thank-you");
        }
    }

    @RequestMapping("/process")
    public ModelAndView good_case_6(HttpServletRequest request) {
        String redirectUrl = request.getParameter("next");
        // ok: java-reflected-open-redirect
        if (redirectUrl != null && redirectUrl.startsWith("/")) {
            return new ModelAndView("redirect:" + redirectUrl);
        } else {
            return new ModelAndView("redirect:/home");
        }
    }

    @GetMapping("/oauth/callback")
    public void good_case_7(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String state = request.getParameter("state");
        String[] parts = state.split(":");
        String redirectUrl = parts[0];
        
        // ok: java-reflected-open-redirect
        String[] allowedDomains = {"example.com", "trusted-partner.com"};
        try {
            URI uri = new URI(redirectUrl);
            String host = uri.getHost();
            boolean isAllowed = false;
            
            for (String domain : allowedDomains) {
                if (host != null && host.endsWith(domain)) {
                    isAllowed = true;
                    break;
                }
            }
            
            if (isAllowed) {
                response.sendRedirect(redirectUrl);
            } else {
                response.sendRedirect("/home");
            }
        } catch (URISyntaxException e) {
            response.sendRedirect("/home");
        }
    }

    @RequestMapping("/redirect")
    public RedirectView good_case_8(@RequestParam String destination) {
        // ok: java-reflected-open-redirect
        if (destination != null && destination.startsWith("/")) {
            return new RedirectView(destination);
        } else {
            return new RedirectView("/default");
        }
    }

    @GetMapping("/sso/complete")
    public void good_case_9(HttpServletRequest request, HttpServletResponse response) throws IOException {
        HttpSession session = request.getSession();
        String redirectUrl = (String) session.getAttribute("originalRequestUrl");
        
        // ok: java-reflected-open-redirect
        Pattern pattern = Pattern.compile("^/[a-zA-Z0-9/_-]*$");
        if (redirectUrl != null && pattern.matcher(redirectUrl).matches()) {
            response.sendRedirect(redirectUrl);
        } else {
            response.sendRedirect("/dashboard");
        }
    }

    @RequestMapping("/error")
    public void good_case_10(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String errorPage = request.getParameter("errorPage");
        String errorCode = request.getParameter("code");
        
        // ok: java-reflected-open-redirect
        Map<String, String> allowedErrorPages = new HashMap<>();
        allowedErrorPages.put("payment", "/errors/payment");
        allowedErrorPages.put("auth", "/errors/authentication");
        allowedErrorPages.put("general", "/errors/general");
        
        String validErrorPage = allowedErrorPages.getOrDefault(errorPage, "/errors/general");
        response.sendRedirect(validErrorPage + "?code=" + errorCode);
    }

    @GetMapping("/language")
    public void good_case_11(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String lang = request.getParameter("lang");
        String returnUrl = request.getParameter("returnUrl");
        
        // Set language preference
        Cookie cookie = new Cookie("language", lang);
        response.addCookie(cookie);
        
        // ok: java-reflected-open-redirect
        if (returnUrl != null && returnUrl.startsWith("/") && !returnUrl.contains("//")) {
            response.sendRedirect(returnUrl);
        } else {
            response.sendRedirect("/home");
        }
    }

    @RequestMapping("/download")
    public void good_case_12(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String file = request.getParameter("file");
        String redirectOnComplete = request.getParameter("redirectOnComplete");
        
        // Process download logic here
        
        // ok: java-reflected-open-redirect
        String safeRedirect = "/download/complete";
        if (redirectOnComplete != null && redirectOnComplete.startsWith("/download/") && !redirectOnComplete.contains("..")) {
            safeRedirect = redirectOnComplete;
        }
        response.sendRedirect(safeRedirect);
    }

    @GetMapping("/share")
    public void good_case_13(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String shareUrl = request.getParameter("url");
        String platform = request.getParameter("platform");
        
        // ok: java-reflected-open-redirect
        if ("twitter".equals(platform)) {
            String encodedUrl = Encode.forUriComponent(shareUrl);
            response.sendRedirect("https://twitter.com/intent/tweet?url=" + encodedUrl);
        } else if ("facebook".equals(platform)) {
            String encodedUrl = Encode.forUriComponent(shareUrl);
            response.sendRedirect("https://www.facebook.com/sharer/sharer.php?u=" + encodedUrl);
        } else {
            response.sendRedirect("/share");
        }
    }

    @RequestMapping("/payment/complete")
    public void good_case_14(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String successUrl = request.getParameter("successUrl");
        String failureUrl = request.getParameter("failureUrl");
        
        boolean paymentSuccess = processPayment(request);
        
        // ok: java-reflected-open-redirect
        if (paymentSuccess) {
            if (successUrl != null && successUrl.startsWith("/") && !successUrl.contains("//")) {
                response.sendRedirect(successUrl);
            } else {
                response.sendRedirect("/payment/success");
            }
        } else {
            if (failureUrl != null && failureUrl.startsWith("/") && !failureUrl.contains("//")) {
                response.sendRedirect(failureUrl);
            } else {
                response.sendRedirect("/payment/failure");
            }
        }
    }

    @GetMapping("/external-link")
    public void good_case_15(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String externalUrl = request.getParameter("url");
        
        // ok: java-reflected-open-redirect
        List<String> allowedDomains = List.of("partner1.com", "partner2.com", "trusted-site.org");
        boolean isAllowed = false;
        
        try {
            URI uri = new URI(externalUrl);
            String host = uri.getHost();
            
            if (host != null) {
                for (String domain : allowedDomains) {
                    if (host.equals(domain) || host.endsWith("." + domain)) {
                        isAllowed = true;
                        break;
                    }
                }
            }
            
            if (isAllowed) {
                String trackingUrl = externalUrl + (externalUrl.contains("?") ? "&" : "?") + "source=ourwebsite";
                response.sendRedirect(trackingUrl);
            } else {
                response.sendRedirect("/external-links");
            }
        } catch (URISyntaxException e) {
            response.sendRedirect("/external-links");
        }
    }
    
    // Helper methods
    
    private boolean authenticate(HttpServletRequest request) {
        // Authentication logic
        return true;
    }
    
    private boolean isValidRedirectUrl(String url) {
        return url != null && (url.startsWith("/") || url.startsWith("https://mywebsite.com/"));
    }
    
    private boolean processPayment(HttpServletRequest request) {
        // Payment processing logic
        return true;
    }
    
    private boolean downloadSuccessful = true;
}
// {/fact}