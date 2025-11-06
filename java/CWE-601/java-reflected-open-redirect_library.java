import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.regex.Pattern;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;

import org.apache.struts2.dispatcher.DefaultActionSupport;
import org.apache.struts2.ServletActionContext;

import spark.Request;
import spark.Response;
import spark.Spark;

import play.mvc.Controller;
import play.mvc.Result;
import play.mvc.Http.Request;

import io.javalin.Javalin;
import io.javalin.http.Context;

import io.micronaut.http.HttpResponse;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;

import io.quarkus.vertx.web.Route;
import io.quarkus.vertx.web.RouteBase;
import io.vertx.ext.web.RoutingContext;

import ratpack.handling.Context;
import ratpack.handling.Handler;
import ratpack.http.client.ReceivedResponse;

import org.jboss.resteasy.spi.HttpRequest;
import org.jboss.resteasy.spi.HttpResponse;

import com.vaadin.flow.component.UI;
import com.vaadin.flow.server.VaadinRequest;

import org.glassfish.jersey.server.ContainerRequest;
import org.glassfish.jersey.server.ContainerResponse;

import com.google.common.net.UrlEscapers;
import org.apache.commons.validator.routines.UrlValidator;
import org.owasp.encoder.Encode;

// Security Issue: Reflected Open Redirect Vulnerability (CWE-601)

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
    // Using Java Servlet API to perform an unsafe redirect
    String redirectUrl = request.getParameter("url");
    
    // ruleid: java-reflected-open-redirect
    response.sendRedirect(redirectUrl);
}

public void bad_case_2() {
    // Using Spark Java framework for an unsafe redirect
    Spark.get("/redirect", (Request request, Response response) -> {
        String redirectUrl = request.queryParams("url");
        
        // ruleid: java-reflected-open-redirect
        response.redirect(redirectUrl);
        return null;
    });
}

@Controller
public class bad_case_3 {
    // Using Spring MVC for an unsafe redirect
    @GetMapping("/redirect")
    public String redirectToExternalUrl(@RequestParam("url") String url) {
        // ruleid: java-reflected-open-redirect
        return "redirect:" + url;
    }
}

public class bad_case_4 extends DefaultActionSupport {
    // Using Apache Struts 2 for an unsafe redirect
    private String url;
    
    public String getUrl() {
        return url;
    }
    
    public void setUrl(String url) {
        this.url = url;
    }
    
    public String execute() {
        HttpServletResponse response = ServletActionContext.getResponse();
        try {
            // ruleid: java-reflected-open-redirect
            response.sendRedirect(url);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }
}

public class bad_case_5 {
    // Using Play Framework for an unsafe redirect
    public Result redirect(play.mvc.Http.Request request) {
        String url = request.getQueryString("url");
        
        // ruleid: java-reflected-open-redirect
        return play.mvc.Results.redirect(url);
    }
}

public void bad_case_6() {
    // Using Javalin for an unsafe redirect
    Javalin app = Javalin.create().start(7000);
    app.get("/redirect", ctx -> {
        String redirectUrl = ctx.queryParam("url");
        
        // ruleid: java-reflected-open-redirect
        ctx.redirect(redirectUrl);
    });
}

@Controller("/redirect")
public class bad_case_7 {
    // Using Micronaut for an unsafe redirect
    @Get("/{url}")
    public HttpResponse<?> redirect(String url) {
        // ruleid: java-reflected-open-redirect
        return HttpResponse.redirect(URI.create(url));
    }
}

@RouteBase(path = "/api")
public class bad_case_8 {
    // Using Quarkus with Vert.x for an unsafe redirect
    @Route(path = "/redirect")
    public void redirect(RoutingContext rc) {
        String url = rc.request().getParam("url");
        
        // ruleid: java-reflected-open-redirect
        rc.response().putHeader("Location", url).setStatusCode(302).end();
    }
}

public class bad_case_9 implements Handler {
    // Using Ratpack for an unsafe redirect
    @Override
    public void handle(Context ctx) {
        String url = ctx.getRequest().getQueryParams().get("url");
        
        // ruleid: java-reflected-open-redirect
        ctx.redirect(url);
    }
}

public class bad_case_10 {
    // Using RESTEasy for an unsafe redirect
    public void performRedirect(HttpRequest request, HttpResponse response) {
        String url = request.getUri().getQueryParameters().getFirst("url");
        
        // ruleid: java-reflected-open-redirect
        response.setStatus(302);
        response.getOutputHeaders().add("Location", url);
    }
}

public class bad_case_11 {
    // Using Vaadin for an unsafe redirect
    public void redirectUser(VaadinRequest request) {
        String url = request.getParameter("url");
        
        // ruleid: java-reflected-open-redirect
        UI.getCurrent().getPage().setLocation(url);
    }
}

public class bad_case_12 {
    // Using Jersey for an unsafe redirect
    public ContainerResponse handleRedirect(ContainerRequest request) {
        String url = request.getUriInfo().getQueryParameters().getFirst("url");
        ContainerResponse response = new ContainerResponse();
        
        // ruleid: java-reflected-open-redirect
        response.getHeaders().add("Location", url);
        response.setStatus(302);
        return response;
    }
}

public class bad_case_13 extends HttpServlet {
    // Using HttpServletResponse with a different method
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String url = req.getHeader("Redirect-To");
        
        // ruleid: java-reflected-open-redirect
        resp.setHeader("Location", url);
        resp.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
    }
}

@Controller
public class bad_case_14 {
    // Using Spring RedirectView for an unsafe redirect
    @GetMapping("/external")
    public RedirectView redirectToExternalUrl(@RequestParam("url") String url) {
        // ruleid: java-reflected-open-redirect
        return new RedirectView(url);
    }
}

public class bad_case_15 {
    // Using Apache Wicket for an unsafe redirect
    public void onSubmit() {
        String url = getRequest().getQueryParameters().getParameterValue("url").toString();
        
        // ruleid: java-reflected-open-redirect
        getRequestCycle().scheduleRequestHandlerAfterCurrent(new RedirectRequestHandler(url));
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
    // Using Java Servlet API with whitelist validation
    String redirectUrl = request.getParameter("url");
    Map<String, String> allowedUrls = Map.of(
        "home", "https://example.com/home",
        "profile", "https://example.com/profile",
        "settings", "https://example.com/settings"
    );
    
    // ok: java-reflected-open-redirect
    if (allowedUrls.containsKey(redirectUrl)) {
        response.sendRedirect(allowedUrls.get(redirectUrl));
    } else {
        response.sendRedirect("/default");
    }
}

public void good_case_2() {
    // Using Spark Java framework with URL validation
    Spark.get("/redirect", (Request request, Response response) -> {
        String redirectUrl = request.queryParams("url");
        
        // Validate URL is on the same host
        try {
            URI uri = new URI(redirectUrl);
            if (uri.isAbsolute() && !uri.getHost().endsWith("example.com")) {
                redirectUrl = "/";
            }
            
            // ok: java-reflected-open-redirect
            response.redirect(redirectUrl);
            
        } catch (URISyntaxException e) {
            response.redirect("/");
        }
        return null;
    });
}

@Controller
public class good_case_3 {
    // Using Spring MVC with regex pattern validation
    private static final Pattern VALID_REDIRECT_PATTERN = Pattern.compile("^/([-a-zA-Z0-9/]*)$");
    
    @GetMapping("/redirect")
    public String redirectToUrl(@RequestParam("url") String url) {
        // ok: java-reflected-open-redirect
        if (url != null && VALID_REDIRECT_PATTERN.matcher(url).matches()) {
            return "redirect:" + url;
        } else {
            return "redirect:/";
        }
    }
}

public class good_case_4 extends DefaultActionSupport {
    // Using Apache Struts 2 with URL validation
    private String url;
    private static final String[] ALLOWED_HOSTS = {"example.com", "subdomain.example.com"};
    
    public String getUrl() {
        return url;
    }
    
    public void setUrl(String url) {
        this.url = url;
    }
    
    public String execute() {
        HttpServletResponse response = ServletActionContext.getResponse();
        try {
            if (url != null) {
                URI uri = new URI(url);
                boolean isAllowed = false;
                
                if (uri.getHost() != null) {
                    for (String host : ALLOWED_HOSTS) {
                        if (uri.getHost().equals(host)) {
                            isAllowed = true;
                            break;
                        }
                    }
                }
                
                // ok: java-reflected-open-redirect
                if (isAllowed) {
                    response.sendRedirect(url);
                } else {
                    response.sendRedirect("/");
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}

public class good_case_5 {
    // Using Play Framework with relative URL enforcement
    public Result redirect(play.mvc.Http.Request request) {
        String url = request.getQueryString("url");
        
        // Ensure URL is relative by removing protocol and domain if present
        if (url != null) {
            if (url.startsWith("http://") || url.startsWith("https://")) {
                url = "/";
            }
            
            // Ensure URL starts with a slash for relative path
            if (!url.startsWith("/")) {
                url = "/" + url;
            }
        } else {
            url = "/";
        }
        
        // ok: java-reflected-open-redirect
        return play.mvc.Results.redirect(url);
    }
}

public void good_case_6() {
    // Using Javalin with URL validation using Apache Commons Validator
    Javalin app = Javalin.create().start(7000);
    app.get("/redirect", ctx -> {
        String redirectUrl = ctx.queryParam("url");
        String[] schemes = {"http", "https"};
        UrlValidator urlValidator = new UrlValidator(schemes);
        
        // Default URL if invalid or not provided
        String safeUrl = "/home";
        
        if (redirectUrl != null && urlValidator.isValid(redirectUrl)) {
            try {
                URI uri = new URI(redirectUrl);
                // Only allow redirects to our domain
                if ("example.com".equals(uri.getHost())) {
                    safeUrl = redirectUrl;
                }
            } catch (URISyntaxException e) {
                // Use default URL if parsing fails
            }
        }
        
        // ok: java-reflected-open-redirect
        ctx.redirect(safeUrl);
    });
}

@Controller("/redirect")
public class good_case_7 {
    // Using Micronaut with URL validation
    private static final String DEFAULT_URL = "https://example.com/home";
    private static final String DOMAIN = "example.com";
    
    @Get("/{url}")
    public HttpResponse<?> redirect(String url) {
        URI redirectUri;
        
        try {
            redirectUri = new URI(url);
            // Check if URI has a host and it's our domain
            if (redirectUri.getHost() == null || !DOMAIN.equals(redirectUri.getHost())) {
                redirectUri = new URI(DEFAULT_URL);
            }
        } catch (URISyntaxException e) {
            try {
                redirectUri = new URI(DEFAULT_URL);
            } catch (URISyntaxException ex) {
                throw new RuntimeException(ex);
            }
        }
        
        // ok: java-reflected-open-redirect
        return HttpResponse.redirect(redirectUri);
    }
}

@RouteBase(path = "/api")
public class good_case_8 {
    // Using Quarkus with Vert.x with URL sanitization
    private static final String[] ALLOWED_DOMAINS = {"example.com", "api.example.com"};
    
    @Route(path = "/redirect")
    public void redirect(RoutingContext rc) {
        String url = rc.request().getParam("url");
        String safeUrl = "/default";
        
        if (url != null) {
            try {
                URI uri = new URI(url);
                if (uri.getHost() != null) {
                    for (String domain : ALLOWED_DOMAINS) {
                        if (uri.getHost().equals(domain)) {
                            safeUrl = url;
                            break;
                        }
                    }
                }
            } catch (URISyntaxException e) {
                // Use default URL
            }
        }
        
        // ok: java-reflected-open-redirect
        rc.response().putHeader("Location", safeUrl).setStatusCode(302).end();
    }
}

public class good_case_9 implements Handler {
    // Using Ratpack with URL validation
    @Override
    public void handle(Context ctx) {
        String url = ctx.getRequest().getQueryParams().get("url");
        
        // Validate URL is relative
        if (url == null || url.contains("://")) {
            url = "/home";
        } else if (!url.startsWith("/")) {
            url = "/" + url;
        }
        
        // ok: java-reflected-open-redirect
        ctx.redirect(url);
    }
}

public class good_case_10 {
    // Using RESTEasy with URL encoding and validation
    public void performRedirect(HttpRequest request, HttpResponse response) {
        String url = request.getUri().getQueryParameters().getFirst("url");
        String safeUrl = "/default";
        
        if (url != null) {
            // Only allow relative URLs
            if (url.startsWith("/") && !url.contains("://")) {
                // Encode the URL to prevent injection
                safeUrl = Encode.forUriComponent(url);
            }
        }
        
        // ok: java-reflected-open-redirect
        response.setStatus(302);
        response.getOutputHeaders().add("Location", safeUrl);
    }
}

public class good_case_11 {
    // Using Vaadin with URL validation
    public void redirectUser(VaadinRequest request) {
        String url = request.getParameter("url");
        String safeUrl = "https://example.com";
        
        if (url != null) {
            try {
                URI uri = new URI(url);
                if (!uri.isAbsolute() || "example.com".equals(uri.getHost())) {
                    safeUrl = url;
                }
            } catch (URISyntaxException e) {
                // Use default URL
            }
        }
        
        // ok: java-reflected-open-redirect
        UI.getCurrent().getPage().setLocation(safeUrl);
    }
}

public class good_case_12 {
    // Using Jersey with URL validation and sanitization
    public ContainerResponse handleRedirect(ContainerRequest request) {
        String url = request.getUriInfo().getQueryParameters().getFirst("url");
        ContainerResponse response = new ContainerResponse();
        
        // Default to home page
        String safeUrl = "/home";
        
        if (url != null) {
            // Only allow URLs in the whitelist
            Map<String, String> allowedRedirects = Map.of(
                "dashboard", "/dashboard",
                "profile", "/user/profile",
                "settings", "/user/settings"
            );
            
            if (allowedRedirects.containsKey(url)) {
                safeUrl = allowedRedirects.get(url);
            }
        }
        
        // ok: java-reflected-open-redirect
        response.getHeaders().add("Location", safeUrl);
        response.setStatus(302);
        return response;
    }
}

public class good_case_13 extends HttpServlet {
    // Using HttpServletResponse with URL escaping and validation
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String url = req.getHeader("Redirect-To");
        
        // Default URL
        String safeUrl = "/home";
        
        if (url != null) {
            // Only allow relative URLs
            if (url.startsWith("/")) {
                // Use Google Guava to escape the URL
                safeUrl = UrlEscapers.urlPathSegmentEscaper().escape(url);
            }
        }
        
        // ok: java-reflected-open-redirect
        resp.setHeader("Location", safeUrl);
        resp.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
    }
}

@Controller
public class good_case_14 {
    // Using Spring RedirectView with URL validation
    @GetMapping("/external")
    public RedirectView redirectToExternalUrl(@RequestParam("url") String url) {
        RedirectView redirectView = new RedirectView();
        redirectView.setContextRelative(true);
        
        // Validate URL is in our whitelist
        Map<String, String> validUrls = Map.of(
            "home", "/home",
            "login", "/login",
            "dashboard", "/dashboard"
        );
        
        // ok: java-reflected-open-redirect
        if (validUrls.containsKey(url)) {
            redirectView.setUrl(validUrls.get(url));
        } else {
            redirectView.setUrl("/");
        }
        
        return redirectView;
    }
}

public class good_case_15 {
    // Using Apache Wicket with URL validation
    public void onSubmit() {
        String url = getRequest().getQueryParameters().getParameterValue("url").toString();
        String safeUrl = "/home";
        
        // Only allow internal URLs
        if (url != null && url.startsWith("/") && !url.contains("://")) {
            safeUrl = url;
        }
        
        // ok: java-reflected-open-redirect
        getRequestCycle().scheduleRequestHandlerAfterCurrent(new RedirectRequestHandler(safeUrl));
    }
}