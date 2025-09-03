import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;
import org.thymeleaf.context.Context;
import org.thymeleaf.TemplateEngine;
import freemarker.template.Template;
import freemarker.template.Configuration;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.Velocity;
import org.apache.struts2.ServletActionContext;
import org.apache.wicket.markup.html.WebPage;
import org.apache.wicket.markup.html.basic.Label;
import org.apache.wicket.request.mapper.parameter.PageParameters;
import spark.ModelAndView;
import spark.template.mustache.MustacheTemplateEngine;
import play.mvc.Controller;
import play.mvc.Result;
import play.twirl.api.Html;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.component.page.Page;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.server.VaadinSession;
import org.apache.tapestry5.annotations.Property;
import org.apache.tapestry5.annotations.OnEvent;
import org.apache.tapestry5.ioc.annotations.Inject;
import org.apache.tapestry5.services.Request;
import com.github.jknack.handlebars.Handlebars;
import com.github.jknack.handlebars.Template;
import com.github.jknack.handlebars.io.ClassPathTemplateLoader;
import com.github.jknack.handlebars.io.TemplateLoader;
import org.rythmengine.Rythm;
import org.rythmengine.template.TemplateBase;
import org.trimou.engine.MustacheEngine;
import org.trimou.engine.MustacheEngineBuilder;
import org.trimou.engine.locator.ClassPathTemplateLocator;
import java.util.HashMap;
import java.util.Map;
import java.security.Key;
import javax.crypto.SecretKey;

// Security Issue: Authentication tokens exposed in view files

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
    // Spring MVC - Exposing JWT token in view
    String username = request.getParameter("username");
    String password = request.getParameter("password");
    
    // Generate JWT token
    Algorithm algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID("secret");
    String token = JWT.create()
            .withSubject(username)
            .withClaim("role", "user")
            .sign(algorithm);
    
    // Exposing token directly in HTML view
    PrintWriter out = response.getWriter();
    out.println("<!DOCTYPE html>");
    out.println("<html>");
    out.println("<head><title>Welcome</title></head>");
    out.println("<body>");
    // ruleid: java-mishandled-auth-token-in-view
    out.println("<script>const authToken = '" + token + "';</script>");
    out.println("<h1>Welcome, " + username + "!</h1>");
    out.println("</body>");
    out.println("</html>");
}

public void bad_case_2(HttpServletRequest request, Model model) {
    // Thymeleaf - Exposing OAuth token in model attribute
    String accessToken = request.getParameter("access_token");
    String refreshToken = request.getParameter("refresh_token");
    
    // Adding tokens directly to the model to be rendered in view
    // ruleid: java-mishandled-auth-token-in-view
    model.addAttribute("accessToken", accessToken);
    // ruleid: java-mishandled-auth-token-in-view
    model.addAttribute("refreshToken", refreshToken);
    model.addAttribute("username", request.getParameter("username"));
}

public void bad_case_3(HttpServletRequest request) throws Exception {
    // FreeMarker - Exposing session token in template data
    String username = request.getParameter("username");
    
    // Generate a session token
    String sessionToken = generateSessionToken(username);
    
    // Create the data model
    Map<String, Object> data = new HashMap<>();
    data.put("username", username);
    // ruleid: java-mishandled-auth-token-in-view
    data.put("sessionToken", sessionToken);
    
    // Process template with FreeMarker
    Configuration cfg = new Configuration(Configuration.VERSION_2_3_30);
    cfg.setClassForTemplateLoading(this.getClass(), "/templates");
    Template template = cfg.getTemplate("dashboard.ftl");
    
    // Output will contain the session token exposed in the view
    template.process(data, new PrintWriter(System.out));
}

public void bad_case_4(HttpServletRequest request, HttpServletResponse response) {
    // Velocity - Exposing API key in template context
    String username = request.getParameter("username");
    String apiKey = generateApiKey(username);
    
    VelocityContext context = new VelocityContext();
    context.put("username", username);
    // ruleid: java-mishandled-auth-token-in-view
    context.put("apiKey", apiKey);
    
    try {
        Velocity.init();
        PrintWriter out = response.getWriter();
        Velocity.mergeTemplate("templates/profile.vm", "UTF-8", context, out);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public ModelAndView bad_case_5(HttpServletRequest request) {
    // Spring MVC with ModelAndView - Exposing bearer token
    String username = request.getParameter("username");
    String bearerToken = "Bearer " + generateJwtToken(username);
    
    ModelAndView mav = new ModelAndView("userDashboard");
    mav.addObject("username", username);
    // ruleid: java-mishandled-auth-token-in-view
    mav.addObject("authHeader", bearerToken);
    
    return mav;
}

public String bad_case_6(HttpServletRequest request) {
    // JSP with JSTL - Exposing token in request attribute
    String username = request.getParameter("username");
    String token = Jwts.builder()
            .setSubject(username)
            .signWith(SignatureAlgorithm.HS512, "secret")
            .compact();
    
    // ruleid: java-mishandled-auth-token-in-view
    request.setAttribute("jwtToken", token);
    request.setAttribute("username", username);
    
    return "dashboard";
}

public void bad_case_7() {
    // Apache Wicket - Exposing token in page
    String token = generateAuthToken();
    
    add(new Label("username", getUsername()));
    // ruleid: java-mishandled-auth-token-in-view
    add(new Label("authToken", token));
}

public ModelAndView bad_case_8(HttpServletRequest request) {
    // Spark with Mustache - Exposing API token
    String username = request.getParameter("username");
    String apiToken = generateApiToken(username);
    
    Map<String, Object> model = new HashMap<>();
    model.put("username", username);
    // ruleid: java-mishandled-auth-token-in-view
    model.put("apiToken", apiToken);
    
    return new ModelAndView(model, "templates/profile.mustache");
}

public Result bad_case_9(play.mvc.Http.Request request) {
    // Play Framework - Exposing token in template
    String username = request.getQueryString("username").orElse("");
    String token = generateToken(username);
    
    // ruleid: java-mishandled-auth-token-in-view
    return ok(views.html.dashboard.render(username, token));
}

public void bad_case_10(HttpServletRequest request) {
    // Vaadin - Exposing token in client-side component
    String username = request.getParameter("username");
    String token = generateAuthToken(username);
    
    Div tokenDisplay = new Div();
    // ruleid: java-mishandled-auth-token-in-view
    tokenDisplay.setText("Your authentication token: " + token);
    tokenDisplay.setId("token-display");
    
    add(new Div(new Text("Welcome, " + username)), tokenDisplay);
}

public void bad_case_11(HttpServletRequest request) {
    // Tapestry - Exposing token in component property
    String username = request.getParameter("username");
    // ruleid: java-mishandled-auth-token-in-view
    authToken = generateAuthToken(username);
}

public void bad_case_12(HttpServletRequest request, HttpServletResponse response) throws IOException {
    // Handlebars.java - Exposing token in template context
    String username = request.getParameter("username");
    String token = generateToken(username);
    
    TemplateLoader loader = new ClassPathTemplateLoader("/templates", ".hbs");
    Handlebars handlebars = new Handlebars(loader);
    Template template = handlebars.compile("dashboard");
    
    Map<String, Object> context = new HashMap<>();
    context.put("username", username);
    // ruleid: java-mishandled-auth-token-in-view
    context.put("authToken", token);
    
    String result = template.apply(context);
    response.getWriter().write(result);
}

public void bad_case_13(HttpServletRequest request, HttpServletResponse response) throws IOException {
    // Rythm Engine - Exposing token in template params
    String username = request.getParameter("username");
    String token = generateToken(username);
    
    // ruleid: java-mishandled-auth-token-in-view
    String result = Rythm.render("dashboard.rythm", username, token);
    response.getWriter().write(result);
}

public void bad_case_14(HttpServletRequest request, HttpServletResponse response) throws IOException {
    // Trimou - Exposing token in template context
    String username = request.getParameter("username");
    String token = generateToken(username);
    
    MustacheEngine engine = MustacheEngineBuilder.newBuilder()
            .addTemplateLocator(new ClassPathTemplateLocator(1, "templates", "html"))
            .build();
    
    Map<String, Object> context = new HashMap<>();
    context.put("username", username);
    // ruleid: java-mishandled-auth-token-in-view
    context.put("token", token);
    
    String result = engine.getMustache("dashboard").render(context);
    response.getWriter().write(result);
}

public void bad_case_15(HttpServletRequest request, HttpServletResponse response) throws IOException {
    // Struts 2 - Exposing token in action
    String username = request.getParameter("username");
    String token = generateToken(username);
    
    // ruleid: java-mishandled-auth-token-in-view
    ServletActionContext.getRequest().setAttribute("authToken", token);
    ServletActionContext.getRequest().setAttribute("username", username);
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
    // Spring MVC - Securely handling JWT token in session
    String username = request.getParameter("username");
    String password = request.getParameter("password");
    
    // Generate JWT token
    Algorithm algorithm = Algorithm.HMAC_REDACTED_TWILIO_ID("secret");
    String token = JWT.create()
            .withSubject(username)
            .withClaim("role", "user")
            .sign(algorithm);
    
    // Store token in session, not in view
    // ok: java-mishandled-auth-token-in-view
    HttpSession session = request.getSession();
    session.setAttribute("authToken", token);
    
    // Render view without exposing token
    PrintWriter out = response.getWriter();
    out.println("<!DOCTYPE html>");
    out.println("<html>");
    out.println("<head><title>Welcome</title></head>");
    out.println("<body>");
    out.println("<h1>Welcome, " + username + "!</h1>");
    out.println("<script>const isAuthenticated = true;</script>");
    out.println("</body>");
    out.println("</html>");
}

public void good_case_2(HttpServletRequest request, Model model) {
    // Thymeleaf - Securely handling OAuth tokens
    String accessToken = request.getParameter("access_token");
    String refreshToken = request.getParameter("refresh_token");
    
    // Store tokens in session, not in model
    // ok: java-mishandled-auth-token-in-view
    HttpSession session = request.getSession();
    session.setAttribute("accessToken", accessToken);
    session.setAttribute("refreshToken", refreshToken);
    
    // Only add non-sensitive data to model
    model.addAttribute("username", request.getParameter("username"));
    model.addAttribute("isAuthenticated", true);
}

public void good_case_3(HttpServletRequest request) throws Exception {
    // FreeMarker - Secure session handling
    String username = request.getParameter("username");
    
    // Generate a session token
    String sessionToken = generateSessionToken(username);
    
    // Store token in session
    // ok: java-mishandled-auth-token-in-view
    request.getSession().setAttribute("sessionToken", sessionToken);
    
    // Create the data model without sensitive information
    Map<String, Object> data = new HashMap<>();
    data.put("username", username);
    data.put("isLoggedIn", true);
    
    // Process template with FreeMarker
    Configuration cfg = new Configuration(Configuration.VERSION_2_3_30);
    cfg.setClassForTemplateLoading(this.getClass(), "/templates");
    Template template = cfg.getTemplate("dashboard.ftl");
    
    // Output will not contain sensitive tokens
    template.process(data, new PrintWriter(System.out));
}

public void good_case_4(HttpServletRequest request, HttpServletResponse response) {
    // Velocity - Secure API key handling
    String username = request.getParameter("username");
    String apiKey = generateApiKey(username);
    
    // Store API key in session
    // ok: java-mishandled-auth-token-in-view
    request.getSession().setAttribute("apiKey", apiKey);
    
    VelocityContext context = new VelocityContext();
    context.put("username", username);
    context.put("hasApiAccess", true);
    
    try {
        Velocity.init();
        PrintWriter out = response.getWriter();
        Velocity.mergeTemplate("templates/profile.vm", "UTF-8", context, out);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public ModelAndView good_case_5(HttpServletRequest request) {
    // Spring MVC with ModelAndView - Secure bearer token handling
    String username = request.getParameter("username");
    String bearerToken = "Bearer " + generateJwtToken(username);
    
    // Store token in session
    // ok: java-mishandled-auth-token-in-view
    request.getSession().setAttribute("authHeader", bearerToken);
    
    ModelAndView mav = new ModelAndView("userDashboard");
    mav.addObject("username", username);
    mav.addObject("isAuthenticated", true);
    
    return mav;
}

public String good_case_6(HttpServletRequest request) {
    // JSP with JSTL - Secure token handling
    String username = request.getParameter("username");
    String token = Jwts.builder()
            .setSubject(username)
            .signWith(SignatureAlgorithm.HS512, "secret")
            .compact();
    
    // Store token in session
    // ok: java-mishandled-auth-token-in-view
    request.getSession().setAttribute("jwtToken", token);
    request.setAttribute("username", username);
    request.setAttribute("isLoggedIn", true);
    
    return "dashboard";
}

public void good_case_7(HttpServletRequest request) {
    // Apache Wicket - Secure token handling
    String token = generateAuthToken();
    
    // Store token in session
    // ok: java-mishandled-auth-token-in-view
    getSession().setAttribute("authToken", token);
    
    add(new Label("username", getUsername()));
    add(new Label("loginStatus", "Authenticated"));
}

public ModelAndView good_case_8(HttpServletRequest request) {
    // Spark with Mustache - Secure API token handling
    String username = request.getParameter("username");
    String apiToken = generateApiToken(username);
    
    // Store token in session
    // ok: java-mishandled-auth-token-in-view
    request.getSession().setAttribute("apiToken", apiToken);
    
    Map<String, Object> model = new HashMap<>();
    model.put("username", username);
    model.put("hasApiAccess", true);
    
    return new ModelAndView(model, "templates/profile.mustache");
}

public Result good_case_9(play.mvc.Http.Request request) {
    // Play Framework - Secure token handling
    String username = request.getQueryString("username").orElse("");
    String token = generateToken(username);
    
    // Store token in session
    // ok: java-mishandled-auth-token-in-view
    play.mvc.Http.Session session = new play.mvc.Http.Session(new HashMap<>());
    session = session.adding("token", token);
    
    return ok(views.html.dashboard.render(username))
           .withSession(session);
}

public void good_case_10(HttpServletRequest request) {
    // Vaadin - Secure token handling
    String username = request.getParameter("username");
    String token = generateAuthToken(username);
    
    // Store token in session
    // ok: java-mishandled-auth-token-in-view
    VaadinSession.getCurrent().setAttribute("authToken", token);
    
    Div welcomeMessage = new Div();
    welcomeMessage.setText("Welcome, " + username);
    welcomeMessage.setId("welcome-message");
    
    add(welcomeMessage);
}

public void good_case_11(HttpServletRequest request) {
    // Tapestry - Secure token handling
    String username = request.getParameter("username");
    String token = generateAuthToken(username);
    
    // Store token in session
    // ok: java-mishandled-auth-token-in-view
    request.getSession().setAttribute("authToken", token);
    
    // Only expose non-sensitive data
    displayName = username;
    isAuthenticated = true;
}

public void good_case_12(HttpServletRequest request, HttpServletResponse response) throws IOException {
    // Handlebars.java - Secure token handling
    String username = request.getParameter("username");
    String token = generateToken(username);
    
    // Store token in session
    // ok: java-mishandled-auth-token-in-view
    request.getSession().setAttribute("authToken", token);
    
    TemplateLoader loader = new ClassPathTemplateLoader("/templates", ".hbs");
    Handlebars handlebars = new Handlebars(loader);
    Template template = handlebars.compile("dashboard");
    
    Map<String, Object> context = new HashMap<>();
    context.put("username", username);
    context.put("isAuthenticated", true);
    
    String result = template.apply(context);
    response.getWriter().write(result);
}

public void good_case_13(HttpServletRequest request, HttpServletResponse response) throws IOException {
    // Rythm Engine - Secure token handling
    String username = request.getParameter("username");
    String token = generateToken(username);
    
    // Store token in session
    // ok: java-mishandled-auth-token-in-view
    request.getSession().setAttribute("authToken", token);
    
    // Only pass non-sensitive data to template
    String result = Rythm.render("dashboard.rythm", username, true);
    response.getWriter().write(result);
}

public void good_case_14(HttpServletRequest request, HttpServletResponse response) throws IOException {
    // Trimou - Secure token handling
    String username = request.getParameter("username");
    String token = generateToken(username);
    
    // Store token in session
    // ok: java-mishandled-auth-token-in-view
    request.getSession().setAttribute("token", token);
    
    MustacheEngine engine = MustacheEngineBuilder.newBuilder()
            .addTemplateLocator(new ClassPathTemplateLocator(1, "templates", "html"))
            .build();
    
    Map<String, Object> context = new HashMap<>();
    context.put("username", username);
    context.put("isAuthenticated", true);
    
    String result = engine.getMustache("dashboard").render(context);
    response.getWriter().write(result);
}

public void good_case_15(HttpServletRequest request, HttpServletResponse response) throws IOException {
    // Struts 2 - Secure token handling
    String username = request.getParameter("username");
    String token = generateToken(username);
    
    // Store token in session
    // ok: java-mishandled-auth-token-in-view
    request.getSession().setAttribute("authToken", token);
    
    ServletActionContext.getRequest().setAttribute("username", username);
    ServletActionContext.getRequest().setAttribute("isAuthenticated", true);
}

// Helper methods
private String generateSessionToken(String username) {
    return "session_" + username + "_" + System.currentTimeMillis();
}

private String generateApiKey(String username) {
    return "api_" + username + "_" + System.currentTimeMillis();
}

private String generateJwtToken(String username) {
    return Jwts.builder()
            .setSubject(username)
            .signWith(SignatureAlgorithm.HS256, "secret")
            .compact();
}

private String generateToken(String username) {
    return "token_" + username + "_" + System.currentTimeMillis();
}

private String generateAuthToken() {
    return "auth_" + System.currentTimeMillis();
}

private String generateAuthToken(String username) {
    return "auth_" + username + "_" + System.currentTimeMillis();
}

private String getUsername() {
    return "user";
}