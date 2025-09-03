package com.example.securitytests;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

public class AuthTokenExamples {

    // TRUE POSITIVES (Vulnerable Code)

// {fact rule=hardcoded-credentials@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response, Model model) {
        String authToken = generateJwtToken("user123");
        // ruleid: java-mishandled-auth-token-in-view
        model.addAttribute("authToken", authToken);
        // The auth token is directly exposed in the view model
    }

    public void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String apiKey = "sk_REDAC_REDACTED_TWILIO_ID_STRIPE_KEY";
        Map<String, Object> viewData = new HashMap<>();
        // ruleid: java-mishandled-auth-token-in-view
        viewData.put("apiKey", apiKey);
        response.getWriter().write(renderTemplate("dashboard", viewData));
    }

    @GetMapping("/user-profile")
    public ModelAndView bad_case_3() {
        ModelAndView modelAndView = new ModelAndView("user-profile");
        String bearerToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0";
        // ruleid: java-mishandled-auth-token-in-view
        modelAndView.addObject("token", bearerToken);
        return modelAndView;
    }

    public void bad_case_4(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String sessionId = request.getSession().getId();
        // ruleid: java-mishandled-auth-token-in-view
        response.getWriter().println("<script>const sessionToken = '" + sessionId + "';</script>");
    }

    @RequestMapping("/admin-dashboard")
    public String bad_case_5(Model model) {
        String adminToken = generateAdminToken();
        // ruleid: java-mishandled-auth-token-in-view
        model.addAttribute("adminAuthToken", adminToken);
        return "admin/dashboard";
    }

    public void bad_case_6(HttpServletRequest request, HttpServletResponse response, Model model) {
        HttpSession session = request.getSession();
        String csrfToken = UUID.randomUUID().toString();
        session.setAttribute("CSRF_TOKEN", csrfToken);
        // ruleid: java-mishandled-auth-token-in-view
        model.addAttribute("csrfToken", csrfToken);
        // CSRF tokens should be handled securely
    }

    @GetMapping("/payment-page")
    public String bad_case_7(Model model) {
        String paymentApiKey = "pk_REDAC_REDACTED_TWILIO_ID_STRIPE_KEY";
        // ruleid: java-mishandled-auth-token-in-view
        model.addAttribute("stripeKey", paymentApiKey);
        return "payment";
    }

    public void bad_case_8(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String oauthToken = "oauth2_abcdefghijklmnopqrstuvwxyz";
        // ruleid: java-mishandled-auth-token-in-view
        response.getWriter().write("<div data-auth-token=\"" + oauthToken + "\"></div>");
    }

    @GetMapping("/api-console")
    public ModelAndView bad_case_9() {
        ModelAndView modelAndView = new ModelAndView("api-console");
        // ruleid: java-mishandled-auth-token-in-view
        modelAndView.addObject("apiSecret", "api_secret_key_12345");
        return modelAndView;
    }

    public void bad_case_10(HttpServletRequest request, HttpServletResponse response, Model model) {
        // ruleid: java-mishandled-auth-token-in-view
        model.addAttribute("accessToken", "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMzQ1Njc4OTAifQ");
        model.addAttribute("username", "john.doe");
    }

    @RequestMapping("/widget")
    public String bad_case_11(Model model) {
        String widgetToken = generateWidgetToken();
        // ruleid: java-mishandled-auth-token-in-view
        model.addAttribute("widgetAuthToken", widgetToken);
        return "widget/display";
    }

    public void bad_case_12(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String refreshToken = "refresh_token_abcdefghijklmnopqrstuvwxyz";
        // ruleid: java-mishandled-auth-token-in-view
        response.getWriter().println("var refreshToken = '" + refreshToken + "';");
    }

    @GetMapping("/analytics")
    public ModelAndView bad_case_13() {
        ModelAndView modelAndView = new ModelAndView("analytics");
        // ruleid: java-mishandled-auth-token-in-view
        modelAndView.addObject("analyticsToken", "analytics_api_key_12345");
        return modelAndView;
    }

    public void bad_case_14(HttpServletRequest request, HttpServletResponse response, Model model) {
        String twoFactorToken = generate2FAToken();
        // ruleid: java-mishandled-auth-token-in-view
        model.addAttribute("twoFactorAuthToken", twoFactorToken);
    }

    @RequestMapping("/checkout")
    public String bad_case_15(Model model) {
        // ruleid: java-mishandled-auth-token-in-view
        model.addAttribute("checkoutToken", "checkout_session_token_12345");
        return "checkout/payment";
    }

    // TRUE NEGATIVES (Secure Code)

    public void good_case_1(HttpServletRequest request, HttpServletResponse response, Model model) {
        String authToken = generateJwtToken("user123");
        // Store token in session instead of view
        HttpSession session = request.getSession();
        // ok: java-mishandled-auth-token-in-view
        session.setAttribute("authToken", authToken);
        model.addAttribute("isAuthenticated", true);
    }

    public void good_case_2(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String apiKey = "sk_REDAC_REDACTED_TWILIO_ID_STRIPE_KEY";
        // Store sensitive data in secure cookie, not in view
        // ok: java-mishandled-auth-token-in-view
        Cookie secureCookie = new Cookie("API_SESSION", encryptData(apiKey));
        secureCookie.setHttpOnly(true);
        secureCookie.setSecure(true);
        response.addCookie(secureCookie);
    }

    @GetMapping("/user-profile-secure")
    public ModelAndView good_case_3(HttpServletRequest request) {
        ModelAndView modelAndView = new ModelAndView("user-profile");
        String bearerToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0";
        // Store token in session, send only user info to view
        HttpSession session = request.getSession();
        // ok: java-mishandled-auth-token-in-view
        session.setAttribute("userToken", bearerToken);
        modelAndView.addObject("hasValidToken", true);
        return modelAndView;
    }

    public void good_case_4(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Use session for authentication instead of exposing session ID
        HttpSession session = request.getSession();
        // ok: java-mishandled-auth-token-in-view
        boolean isAuthenticated = session.getAttribute("user") != null;
        response.getWriter().println("<script>const isUserAuthenticated = " + isAuthenticated + ";</script>");
    }

    @RequestMapping("/admin-dashboard-secure")
    public String good_case_5(HttpServletRequest request, Model model) {
        HttpSession session = request.getSession();
        String adminToken = generateAdminToken();
        // ok: java-mishandled-auth-token-in-view
        session.setAttribute("adminAuthToken", adminToken);
        model.addAttribute("isAdmin", true);
        return "admin/dashboard";
    }

    public void good_case_6(HttpServletRequest request, HttpServletResponse response, Model model) {
        HttpSession session = request.getSession();
        String csrfToken = UUID.randomUUID().toString();
        // ok: java-mishandled-auth-token-in-view
        session.setAttribute("CSRF_TOKEN", csrfToken);
        // Use a form field for CSRF token instead of exposing it directly
        model.addAttribute("csrfFieldName", "csrf_token");
    }

    @GetMapping("/payment-page-secure")
    public String good_case_7(Model model) {
        // Use a server endpoint to handle payment API interactions
        // ok: java-mishandled-auth-token-in-view
        model.addAttribute("paymentEndpoint", "/api/process-payment");
        return "payment";
    }

    public void good_case_8(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String oauthToken = "oauth2_abcdefghijklmnopqrstuvwxyz";
        HttpSession session = request.getSession();
        // ok: java-mishandled-auth-token-in-view
        session.setAttribute("oauth_token", oauthToken);
        response.getWriter().write("<div data-auth-status=\"authenticated\"></div>");
    }

    @GetMapping("/api-console-secure")
    public ModelAndView good_case_9(HttpServletRequest request) {
        ModelAndView modelAndView = new ModelAndView("api-console");
        String apiSecret = "api_secret_key_12345";
        // Store API secret in session, not in view
        HttpSession session = request.getSession();
        // ok: java-mishandled-auth-token-in-view
        session.setAttribute("apiSecret", apiSecret);
        modelAndView.addObject("hasApiAccess", true);
        return modelAndView;
    }

    public void good_case_10(HttpServletRequest request, HttpServletResponse response, Model model) {
        String accessToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMzQ1Njc4OTAifQ";
        // Store token in session
        HttpSession session = request.getSession();
        // ok: java-mishandled-auth-token-in-view
        session.setAttribute("accessToken", accessToken);
        model.addAttribute("username", "john.doe");
    }

    @RequestMapping("/widget-secure")
    public String good_case_11(HttpServletRequest request, Model model) {
        String widgetToken = generateWidgetToken();
        // Store token in session
        HttpSession session = request.getSession();
        // ok: java-mishandled-auth-token-in-view
        session.setAttribute("widgetAuthToken", widgetToken);
        model.addAttribute("widgetId", "widget-123");
        return "widget/display";
    }

    public void good_case_12(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String refreshToken = "refresh_token_abcdefghijklmnopqrstuvwxyz";
        // Store token in HTTP-only cookie
        // ok: java-mishandled-auth-token-in-view
        Cookie cookie = new Cookie("refresh_token", refreshToken);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/api/refresh");
        response.addCookie(cookie);
    }

    @GetMapping("/analytics-secure")
    public ModelAndView good_case_13(HttpServletRequest request) {
        ModelAndView modelAndView = new ModelAndView("analytics");
        String analyticsToken = "analytics_api_key_12345";
        // Use server-side API calls instead of exposing token
        // ok: java-mishandled-auth-token-in-view
        fetchAnalyticsData(analyticsToken);
        modelAndView.addObject("analyticsData", getAnalyticsData());
        return modelAndView;
    }

    public void good_case_14(HttpServletRequest request, HttpServletResponse response, Model model) {
        String twoFactorToken = generate2FAToken();
        HttpSession session = request.getSession();
        // ok: java-mishandled-auth-token-in-view
        session.setAttribute("twoFactorAuthToken", twoFactorToken);
        model.addAttribute("requiresTwoFactor", true);
    }

    @RequestMapping("/checkout-secure")
    public String good_case_15(HttpServletRequest request, Model model) {
        String checkoutToken = "checkout_session_token_12345";
        // Store token in session
        HttpSession session = request.getSession();
        // ok: java-mishandled-auth-token-in-view
        session.setAttribute("checkoutToken", checkoutToken);
        model.addAttribute("checkoutId", "CO-12345");
        return "checkout/payment";
    }

    // Helper methods
    private String generateJwtToken(String userId) {
        Algorithm algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID("secret");
        return JWT.create()
                .withSubject(userId)
                .sign(algorithm);
    }

    private String generateAdminToken() {
        return "admin_" + UUID.randomUUID().toString();
    }

    private String generate2FAToken() {
        return "2fa_" + UUID.randomUUID().toString();
    }

    private String generateWidgetToken() {
        return "widget_" + UUID.randomUUID().toString();
    }

    private String encryptData(String data) {
        // Simplified encryption for example
        return "encrypted_" + data;
    }

    private String renderTemplate(String templateName, Map<String, Object> data) {
        // Simplified template rendering for example
        TemplateEngine engine = new TemplateEngine();
        Context context = new Context();
        for (Map.Entry<String, Object> entry : data.entrySet()) {
            context.setVariable(entry.getKey(), entry.getValue());
        }
        return engine.process(templateName, context);
    }

    private void fetchAnalyticsData(String token) {
        // Server-side API call using token
    }

    private Map<String, Object> getAnalyticsData() {
        // Return processed analytics data
        return new HashMap<>();
    }
}
// {/fact}