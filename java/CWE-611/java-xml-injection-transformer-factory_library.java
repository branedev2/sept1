import javax.xml.XMLConstants;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.apache.cxf.jaxrs.client.WebClient;
import org.glassfish.jersey.client.JerseyClient;
import org.glassfish.jersey.client.JerseyClientBuilder;
import retrofit2.Retrofit;
import retrofit2.Call;
import retrofit2.Callback;
import java.io.File;
import java.io.FileOutputStream;
import org.eclipse.jetty.client.HttpClient as JettyHttpClient;
import org.eclipse.jetty.client.api.ContentResponse;
import org.asynchttpclient.AsyncHttpClient;
import org.asynchttpclient.Dsl;
import org.apache.http.client.fluent.Request as FluentRequest;
import org.apache.http.entity.ContentType;
import java.util.concurrent.Future;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import java.net.http.HttpClient as JavaHttpClient;
import java.net.http.HttpRequest;
import java.net.URI;
import java.net.http.HttpResponse.BodyHandlers;
import org.apache.commons.httpclient.HttpClient as CommonsHttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import kong.unirest.Unirest;
import kong.unirest.HttpResponse as UnirestResponse;

// Security Issue: XML External Entity (XXE) Injection in TransformerFactory

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) {
    try {
        String xmlData = request.getParameter("xml");
        
        // ruleid: java-xml-injection-transformer-factory
        TransformerFactory factory = TransformerFactory.newInstance();
        
        Transformer transformer = factory.newTransformer();
        StreamSource source = new StreamSource(new StringReader(xmlData));
        StreamResult result = new StreamResult(new StringWriter());
        
        transformer.transform(source, result);
        System.out.println(result.getWriter().toString());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_2() {
    try {
        RestTemplate restTemplate = new RestTemplate();
        String xmlData = restTemplate.getForObject("https://example.com/data.xml", String.class);
        
        // ruleid: java-xml-injection-transformer-factory
        TransformerFactory factory = TransformerFactory.newInstance("com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl", null);
        
        Transformer transformer = factory.newTransformer();
        StreamSource source = new StreamSource(new StringReader(xmlData));
        StreamResult result = new StreamResult(System.out);
        
        transformer.transform(source, result);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_3() {
    try {
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
            .url("https://example.com/data.xml")
            .build();
        
        try (Response response = client.newCall(request).execute()) {
            String xmlData = response.body().string();
            
            // ruleid: java-xml-injection-transformer-factory
            TransformerFactory factory = TransformerFactory.newInstance();
            factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            // Missing AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET setting
            
            Transformer transformer = factory.newTransformer();
            StreamSource source = new StreamSource(new StringReader(xmlData));
            StreamResult result = new StreamResult(new StringWriter());
            
            transformer.transform(source, result);
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_4() {
    try {
        HttpClient httpClient = HttpClients.createDefault();
        HttpGet request = new HttpGet("https://example.com/data.xml");
        HttpResponse response = httpClient.execute(request);
        
        String xmlData = IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8);
        
        // ruleid: java-xml-injection-transformer-factory
        TransformerFactory factory = TransformerFactory.newInstance();
        // Missing AC_REDACTED_TWILIO_ID_EXTERNAL_DTD setting
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
        
        Transformer transformer = factory.newTransformer();
        StreamSource source = new StreamSource(new StringReader(xmlData));
        StreamResult result = new StreamResult(new StringWriter());
        
        transformer.transform(source, result);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_5() {
    try {
        WebClient webClient = WebClient.create("https://example.com");
        String xmlData = webClient.path("/data.xml").get(String.class);
        
        // ruleid: java-xml-injection-transformer-factory
        TransformerFactory factory = TransformerFactory.newInstance();
        // Only enabling secure processing without setting access controls
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        
        Transformer transformer = factory.newTransformer();
        StreamSource source = new StreamSource(new StringReader(xmlData));
        StreamResult result = new StreamResult(new StringWriter());
        
        transformer.transform(source, result);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_6() {
    try {
        JerseyClient client = JerseyClientBuilder.createClient();
        String xmlData = client.target("https://example.com/data.xml").request().get(String.class);
        
        // ruleid: java-xml-injection-transformer-factory
        TransformerFactory factory = TransformerFactory.newInstance();
        // No security settings at all
        
        StreamSource xsltSource = new StreamSource(new File("transform.xsl"));
        Transformer transformer = factory.newTransformer(xsltSource);
        StreamSource source = new StreamSource(new StringReader(xmlData));
        StreamResult result = new StreamResult(new StringWriter());
        
        transformer.transform(source, result);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

@PostMapping("/transform")
public void bad_case_7(@RequestBody String xmlData) {
    try {
        // ruleid: java-xml-injection-transformer-factory
        TransformerFactory factory = TransformerFactory.newInstance();
        // Using a custom implementation without security settings
        System.setProperty("javax.xml.transform.TransformerFactory", 
                          "net.sf.saxon.TransformerFactoryImpl");
        
        Transformer transformer = factory.newTransformer();
        StreamSource source = new StreamSource(new StringReader(xmlData));
        StreamResult result = new StreamResult(new StringWriter());
        
        transformer.transform(source, result);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_8() {
    try {
        URL url = new URL("https://example.com/data.xml");
        URLConnection connection = url.openConnection();
        String xmlData = IOUtils.toString(connection.getInputStream(), StandardCharsets.UTF_8);
        
        // ruleid: java-xml-injection-transformer-factory
        TransformerFactory factory = TransformerFactory.newInstance();
        // Incorrectly setting security attributes with wrong values
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "all");
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "all");
        
        Transformer transformer = factory.newTransformer();
        StreamSource source = new StreamSource(new StringReader(xmlData));
        StreamResult result = new StreamResult(new StringWriter());
        
        transformer.transform(source, result);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_9() {
    try {
        JettyHttpClient client = new JettyHttpClient();
        client.start();
        ContentResponse response = client.GET("https://example.com/data.xml");
        String xmlData = response.getContentAsString();
        
        // ruleid: java-xml-injection-transformer-factory
        TransformerFactory factory = TransformerFactory.newInstance();
        // Setting only one attribute with incorrect value
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "file,http");
        
        Transformer transformer = factory.newTransformer();
        StreamSource source = new StreamSource(new StringReader(xmlData));
        StreamResult result = new StreamResult(new StringWriter());
        
        transformer.transform(source, result);
        client.stop();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_10() {
    try {
        AsyncHttpClient client = Dsl.asyncHttpClient();
        Future<String> f = client.prepareGet("https://example.com/data.xml")
                               .execute()
                               .toCompletableFuture()
                               .thenApply(response -> response.getResponseBody());
        String xmlData = f.get();
        
        // ruleid: java-xml-injection-transformer-factory
        TransformerFactory factory = TransformerFactory.newInstance();
        // Disabling secure processing explicitly
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, false);
        
        Transformer transformer = factory.newTransformer();
        StreamSource source = new StreamSource(new StringReader(xmlData));
        StreamResult result = new StreamResult(new StringWriter());
        
        transformer.transform(source, result);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_11() {
    try {
        String xmlData = FluentRequest.Get("https://example.com/data.xml")
                                    .execute()
                                    .returnContent()
                                    .asString();
        
        // ruleid: java-xml-injection-transformer-factory
        TransformerFactory factory = TransformerFactory.newInstance();
        // Using deprecated security approach
        System.setProperty("javax.xml.transform.TransformerFactory", "com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl");
        
        Transformer transformer = factory.newTransformer();
        StreamSource source = new StreamSource(new StringReader(xmlData));
        StreamResult result = new StreamResult(new StringWriter());
        
        transformer.transform(source, result);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_12() {
    try {
        Document doc = Jsoup.connect("https://example.com/data.xml").get();
        String xmlData = doc.html();
        
        // ruleid: java-xml-injection-transformer-factory
        TransformerFactory factory = TransformerFactory.newInstance();
        // Using non-standard property names
        factory.setAttribute("http://javax.xml.XMLConstants/property/accessExternalDTD", "");
        
        Transformer transformer = factory.newTransformer();
        StreamSource source = new StreamSource(new StringReader(xmlData));
        StreamResult result = new StreamResult(new StringWriter());
        
        transformer.transform(source, result);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_13() {
    try {
        JavaHttpClient client = JavaHttpClient.newBuilder().build();
        HttpRequest request = HttpRequest.newBuilder()
                            .uri(URI.create("https://example.com/data.xml"))
                            .build();
        String xmlData = client.send(request, BodyHandlers.ofString()).body();
        
        // ruleid: java-xml-injection-transformer-factory
        TransformerFactory factory = TransformerFactory.newInstance();
        // Setting properties after creating transformer (too late)
        Transformer transformer = factory.newTransformer();
        transformer.setOutputProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        transformer.setOutputProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
        
        StreamSource source = new StreamSource(new StringReader(xmlData));
        StreamResult result = new StreamResult(new StringWriter());
        
        transformer.transform(source, result);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_14() {
    try {
        CommonsHttpClient client = new CommonsHttpClient();
        GetMethod method = new GetMethod("https://example.com/data.xml");
        client.executeMethod(method);
        String xmlData = method.getResponseBodyAsString();
        
        // ruleid: java-xml-injection-transformer-factory
        TransformerFactory factory = TransformerFactory.newInstance();
        // Using custom properties that don't provide security
        factory.setAttribute("indent-number", 2);
        
        Transformer transformer = factory.newTransformer();
        StreamSource source = new StreamSource(new StringReader(xmlData));
        StreamResult result = new StreamResult(new StringWriter());
        
        transformer.transform(source, result);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_15() {
    try {
        UnirestResponse<String> response = Unirest.get("https://example.com/data.xml")
                                                .asString();
        String xmlData = response.getBody();
        
        // ruleid: java-xml-injection-transformer-factory
        TransformerFactory factory = TransformerFactory.newInstance();
        // Trying to set security with wrong method
        factory.setAttribute("secure-processing", Boolean.TRUE);
        
        Transformer transformer = factory.newTransformer();
        StreamSource source = new StreamSource(new StringReader(xmlData));
        StreamResult result = new StreamResult(new StringWriter());
        
        transformer.transform(source, result);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) {
    try {
        String xmlData = request.getParameter("xml");
        
        // ok: java-xml-injection-transformer-factory
        TransformerFactory factory = TransformerFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
        
        Transformer transformer = factory.newTransformer();
        StreamSource source = new StreamSource(new StringReader(xmlData));
        StreamResult result = new StreamResult(new StringWriter());
        
        transformer.transform(source, result);
        System.out.println(result.getWriter().toString());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_2() {
    try {
        RestTemplate restTemplate = new RestTemplate();
        String xmlData = restTemplate.getForObject("https://example.com/data.xml", String.class);
        
        // ok: java-xml-injection-transformer-factory
        TransformerFactory factory = TransformerFactory.newInstance();
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        
        Transformer transformer = factory.newTransformer();
        StreamSource source = new StreamSource(new StringReader(xmlData));
        StreamResult result = new StreamResult(System.out);
        
        transformer.transform(source, result);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_3() {
    try {
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
            .url("https://example.com/data.xml")
            .build();
        
        try (Response response = client.newCall(request).execute()) {
            String xmlData = response.body().string();
            
            // ok: java-xml-injection-transformer-factory
            TransformerFactory factory = TransformerFactory.newInstance();
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
            
            Transformer transformer = factory.newTransformer();
            StreamSource source = new StreamSource(new StringReader(xmlData));
            StreamResult result = new StreamResult(new StringWriter());
            
            transformer.transform(source, result);
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_4() {
    try {
        HttpClient httpClient = HttpClients.createDefault();
        HttpGet request = new HttpGet("https://example.com/data.xml");
        HttpResponse response = httpClient.execute(request);
        
        String xmlData = IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8);
        
        // ok: java-xml-injection-transformer-factory
        System.setProperty("javax.xml.transform.TransformerFactory", "com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl");
        TransformerFactory factory = TransformerFactory.newInstance();
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        
        Transformer transformer = factory.newTransformer();
        StreamSource source = new StreamSource(new StringReader(xmlData));
        StreamResult result = new StreamResult(new StringWriter());
        
        transformer.transform(source, result);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_5() {
    try {
        WebClient webClient = WebClient.create("https://example.com");
        String xmlData = webClient.path("/data.xml").get(String.class);
        
        // ok: java-xml-injection-transformer-factory
        TransformerFactory factory = TransformerFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
        
        StreamSource xsltSource = new StreamSource(new File("transform.xsl"));
        Transformer transformer = factory.newTransformer(xsltSource);
        StreamSource source = new StreamSource(new StringReader(xmlData));
        StreamResult result = new StreamResult(new StringWriter());
        
        transformer.transform(source, result);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

@PostMapping("/transform")
public void good_case_6(@RequestBody String xmlData) {
    try {
        // ok: java-xml-injection-transformer-factory
        System.setProperty("javax.xml.transform.TransformerFactory", "net.sf.saxon.TransformerFactoryImpl");
        TransformerFactory factory = TransformerFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
        
        Transformer transformer = factory.newTransformer();
        StreamSource source = new StreamSource(new StringReader(xmlData));
        StreamResult result = new StreamResult(new StringWriter());
        
        transformer.transform(source, result);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_7() {
    try {
        URL url = new URL("https://example.com/data.xml");
        URLConnection connection = url.openConnection();
        String xmlData = IOUtils.toString(connection.getInputStream(), StandardCharsets.UTF_8);
        
        // ok: java-xml-injection-transformer-factory
        TransformerFactory factory = TransformerFactory.newInstance();
        // Setting all security attributes correctly
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        
        Transformer transformer = factory.newTransformer();
        StreamSource source = new StreamSource(new StringReader(xmlData));
        StreamResult result = new StreamResult(new StringWriter());
        
        transformer.transform(source, result);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_8() {
    try {
        JettyHttpClient client = new JettyHttpClient();
        client.start();
        ContentResponse response = client.GET("https://example.com/data.xml");
        String xmlData = response.getContentAsString();
        
        // ok: java-xml-injection-transformer-factory
        TransformerFactory factory = TransformerFactory.newInstance();
        // Setting all security attributes with empty strings to block external access
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        
        Transformer transformer = factory.newTransformer();
        StreamSource source = new StreamSource(new StringReader(xmlData));
        StreamResult result = new StreamResult(new StringWriter());
        
        transformer.transform(source, result);
        client.stop();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_9() {
    try {
        AsyncHttpClient client = Dsl.asyncHttpClient();
        Future<String> f = client.prepareGet("https://example.com/data.xml")
                               .execute()
                               .toCompletableFuture()
                               .thenApply(response -> response.getResponseBody());
        String xmlData = f.get();
        
        // ok: java-xml-injection-transformer-factory
        TransformerFactory factory = TransformerFactory.newInstance();
        // Enabling secure processing and restricting external access
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
        
        Transformer transformer = factory.newTransformer();
        StreamSource source = new StreamSource(new StringReader(xmlData));
        StreamResult result = new StreamResult(new StringWriter());
        
        transformer.transform(source, result);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_10() {
    try {
        String xmlData = FluentRequest.Get("https://example.com/data.xml")
                                    .execute()
                                    .returnContent()
                                    .asString();
        
        // ok: java-xml-injection-transformer-factory
        TransformerFactory factory = TransformerFactory.newInstance();
        // Setting security attributes correctly
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        
        Transformer transformer = factory.newTransformer();
        StreamSource source = new StreamSource(new StringReader(xmlData));
        StreamResult result = new StreamResult(new StringWriter());
        
        transformer.transform(source, result);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_11() {
    try {
        Document doc = Jsoup.connect("https://example.com/data.xml").get();
        String xmlData = doc.html();
        
        // ok: java-xml-injection-transformer-factory
        TransformerFactory factory = TransformerFactory.newInstance();
        // Using correct property names and values
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        
        Transformer transformer = factory.newTransformer();
        StreamSource source = new StreamSource(new StringReader(xmlData));
        StreamResult result = new StreamResult(new StringWriter());
        
        transformer.transform(source, result);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_12() {
    try {
        JavaHttpClient client = JavaHttpClient.newBuilder().build();
        HttpRequest request = HttpRequest.newBuilder()
                            .uri(URI.create("https://example.com/data.xml"))
                            .build();
        String xmlData = client.send(request, BodyHandlers.ofString()).body();
        
        // ok: java-xml-injection-transformer-factory
        TransformerFactory factory = TransformerFactory.newInstance();
        // Setting security properties before creating transformer
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        
        Transformer transformer = factory.newTransformer();
        StreamSource source = new StreamSource(new StringReader(xmlData));
        StreamResult result = new StreamResult(new StringWriter());
        
        transformer.transform(source, result);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_13() {
    try {
        CommonsHttpClient client = new CommonsHttpClient();
        GetMethod method = new GetMethod("https://example.com/data.xml");
        client.executeMethod(method);
        String xmlData = method.getResponseBodyAsString();
        
        // ok: java-xml-injection-transformer-factory
        TransformerFactory factory = TransformerFactory.newInstance();
        // Setting both security properties and additional properties
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setAttribute("indent-number", 2);
        
        Transformer transformer = factory.newTransformer();
        StreamSource source = new StreamSource(new StringReader(xmlData));
        StreamResult result = new StreamResult(new StringWriter());
        
        transformer.transform(source, result);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_14() {
    try {
        UnirestResponse<String> response = Unirest.get("https://example.com/data.xml")
                                                .asString();
        String xmlData = response.getBody();
        
        // ok: java-xml-injection-transformer-factory
        TransformerFactory factory = TransformerFactory.newInstance();
        // Setting security with correct method and property names
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
        
        Transformer transformer = factory.newTransformer();
        StreamSource source = new StreamSource(new StringReader(xmlData));
        StreamResult result = new StreamResult(new StringWriter());
        
        transformer.transform(source, result);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_15() {
    try {
        HttpClient httpClient = HttpClients.createDefault();
        HttpGet request = new HttpGet("https://example.com/data.xml");
        HttpResponse response = httpClient.execute(request);
        
        String xmlData = IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8);
        
        // Create a custom security manager for additional protection
        SecurityManager securityManager = System.getSecurityManager();
        if (securityManager == null) {
            System.setSecurityManager(new SecurityManager());
        }
        
        // ok: java-xml-injection-transformer-factory
        TransformerFactory factory = TransformerFactory.newInstance();
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        
        Transformer transformer = factory.newTransformer();
        StreamSource source = new StreamSource(new StringReader(xmlData));
        StreamResult result = new StreamResult(new StringWriter());
        
        transformer.transform(source, result);
    } catch (Exception e) {
        e.printStackTrace();
    }
}