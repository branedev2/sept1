import java.beans.XMLDecoder;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import javax.servlet.http.*;
import javax.xml.parsers.*;
import org.xml.sax.*;
import org.springframework.web.bind.annotation.*;
import org.apache.struts2.dispatcher.multipart.MultiPartRequestWrapper;
import org.apache.commons.io.IOUtils;
import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.WebResource;
import okhttp3.*;
import retrofit2.*;
import retrofit2.http.*;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.glassfish.jersey.client.JerseyClient;
import org.glassfish.jersey.client.JerseyClientBuilder;
import java.util.Properties;
import org.springframework.http.*;
import org.springframework.web.client.RestTemplate;
import org.jboss.resteasy.client.jaxrs.ResteasyClient;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.apache.cxf.jaxrs.client.WebClient;
import java.util.Base64;
import javax.xml.stream.*;
import javax.xml.transform.*;
import javax.xml.transform.stream.*;

// Security Issue: Unsafe usage of XMLDecoder with untrusted data can lead to arbitrary code execution

// True Positive Examples (Vulnerable/Insecure Code)

public class XMLDecoderVulnerabilityExamples {

    // Spring MVC web application using XMLDecoder with request parameter
// {fact rule=xml-external-entity@v1.0 defects=1}
    @RequestMapping("/process-xml")
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) {
        try {
            String xmlData = request.getParameter("xml_data");
            ByteArrayInputStream bis = new ByteArrayInputStream(xmlData.getBytes());
            
            // ruleid: java-xml-decoder
            XMLDecoder decoder = new XMLDecoder(bis);
            
            Object decodedObject = decoder.readObject();
            decoder.close();
            
            response.getWriter().write("Processed: " + decodedObject.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Using OkHttp client to fetch XML and process with XMLDecoder
    public void bad_case_2() {
        try {
            OkHttpClient client = new OkHttpClient();
            Request request = new Request.Builder()
                .url("https://example.com/user-data.xml")
                .build();
                
            Response response = client.newCall(request).execute();
            String xmlData = response.body().string();
            
            ByteArrayInputStream bis = new ByteArrayInputStream(xmlData.getBytes());
            
            // ruleid: java-xml-decoder
            XMLDecoder decoder = new XMLDecoder(bis);
            
            Object result = decoder.readObject();
            decoder.close();
            System.out.println("Processed user data: " + result);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Struts2 application processing multipart XML upload
    public void bad_case_3(MultiPartRequestWrapper request) {
        try {
            InputStream xmlStream = request.getFileInputStream("user_config");
            
            // ruleid: java-xml-decoder
            XMLDecoder decoder = new XMLDecoder(xmlStream);
            
            Object config = decoder.readObject();
            decoder.close();
            
            System.out.println("User configuration loaded: " + config);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Using Apache HttpClient to fetch and process XML
    public void bad_case_4() {
        try {
            CloseableHttpClient httpClient = HttpClients.createDefault();
            HttpGet request = new HttpGet("https://api.example.org/data.xml");
            
            String xmlContent = EntityUtils.toString(httpClient.execute(request).getEntity());
            ByteArrayInputStream inputStream = new ByteArrayInputStream(xmlContent.getBytes());
            
            // ruleid: java-xml-decoder
            XMLDecoder decoder = new XMLDecoder(inputStream);
            
            Object data = decoder.readObject();
            decoder.close();
            
            System.out.println("API data: " + data);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Jersey REST client fetching XML configuration
    public void bad_case_5() {
        try {
            Client client = Client.create();
            WebResource webResource = client.resource("https://config.example.com/settings.xml");
            
            String response = webResource.accept("application/xml").get(String.class);
            ByteArrayInputStream bis = new ByteArrayInputStream(response.getBytes());
            
            // ruleid: java-xml-decoder
            XMLDecoder decoder = new XMLDecoder(bis);
            
            Object settings = decoder.readObject();
            decoder.close();
            
            System.out.println("Loaded settings: " + settings);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Retrofit API client processing XML response
    public void bad_case_6() {
        try {
            Retrofit retrofit = new Retrofit.Builder()
                .baseUrl("https://api.example.com/")
                .build();
                
            ApiService service = retrofit.create(ApiService.class);
            Response<ResponseBody> response = service.getXmlData().execute();
            
            String xmlData = response.body().string();
            ByteArrayInputStream bis = new ByteArrayInputStream(xmlData.getBytes());
            
            // ruleid: java-xml-decoder
            XMLDecoder decoder = new XMLDecoder(bis);
            
            Object result = decoder.readObject();
            decoder.close();
            
            System.out.println("API result: " + result);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Spring RestTemplate fetching XML data
    public void bad_case_7() {
        try {
            RestTemplate restTemplate = new RestTemplate();
            String xmlResponse = restTemplate.getForObject("https://service.example.com/data.xml", String.class);
            
            ByteArrayInputStream bis = new ByteArrayInputStream(xmlResponse.getBytes());
            
            // ruleid: java-xml-decoder
            XMLDecoder decoder = new XMLDecoder(bis);
            
            Object data = decoder.readObject();
            decoder.close();
            
            System.out.println("Service data: " + data);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // RESTEasy client processing XML response
    public void bad_case_8() {
        try {
            ResteasyClient client = new ResteasyClientBuilder().build();
            String xmlData = client.target("https://api.example.org/config.xml")
                                  .request()
                                  .get(String.class);
            
            ByteArrayInputStream bis = new ByteArrayInputStream(xmlData.getBytes());
            
            // ruleid: java-xml-decoder
            XMLDecoder decoder = new XMLDecoder(bis);
            
            Object config = decoder.readObject();
            decoder.close();
            
            System.out.println("Configuration: " + config);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Apache CXF WebClient fetching XML
    public void bad_case_9() {
        try {
            WebClient client = WebClient.create("https://services.example.com");
            String response = client.path("/user/profile.xml").get(String.class);
            
            ByteArrayInputStream bis = new ByteArrayInputStream(response.getBytes());
            
            // ruleid: java-xml-decoder
            XMLDecoder decoder = new XMLDecoder(bis);
            
            Object profile = decoder.readObject();
            decoder.close();
            
            System.out.println("User profile: " + profile);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Processing XML from HTTP request headers
    public void bad_case_10(HttpServletRequest request) {
        try {
            String encodedXml = request.getHeader("X-Config-Data");
            byte[] decodedXml = Base64.getDecoder().decode(encodedXml);
            
            ByteArrayInputStream bis = new ByteArrayInputStream(decodedXml);
            
            // ruleid: java-xml-decoder
            XMLDecoder decoder = new XMLDecoder(bis);
            
            Object config = decoder.readObject();
            decoder.close();
            
            System.out.println("Header config: " + config);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Processing XML from request cookies
    public void bad_case_11(HttpServletRequest request) {
        try {
            Cookie[] cookies = request.getCookies();
            String xmlData = null;
            
            for (Cookie cookie : cookies) {
                if ("user_settings".equals(cookie.getName())) {
                    xmlData = cookie.getValue();
                    break;
                }
            }
            
            if (xmlData != null) {
                ByteArrayInputStream bis = new ByteArrayInputStream(
                    Base64.getDecoder().decode(xmlData));
                
                // ruleid: java-xml-decoder
                XMLDecoder decoder = new XMLDecoder(bis);
                
                Object settings = decoder.readObject();
                decoder.close();
                
                System.out.println("User settings: " + settings);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Processing XML from request body using raw input stream
    public void bad_case_12(HttpServletRequest request) {
        try {
            String xmlData = IOUtils.toString(request.getInputStream(), "UTF-8");
            ByteArrayInputStream bis = new ByteArrayInputStream(xmlData.getBytes());
            
            // ruleid: java-xml-decoder
            XMLDecoder decoder = new XMLDecoder(bis);
            
            Object data = decoder.readObject();
            decoder.close();
            
            System.out.println("Request body data: " + data);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Processing XML from URL query parameters
    public void bad_case_13(HttpServletRequest request) {
        try {
            String encodedXml = request.getParameter("config");
            if (encodedXml != null) {
                byte[] decodedXml = Base64.getDecoder().decode(encodedXml);
                ByteArrayInputStream bis = new ByteArrayInputStream(decodedXml);
                
                // ruleid: java-xml-decoder
                XMLDecoder decoder = new XMLDecoder(bis);
                
                Object config = decoder.readObject();
                decoder.close();
                
                System.out.println("Query parameter config: " + config);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Glassfish Jersey client fetching XML
    public void bad_case_14() {
        try {
            JerseyClient client = JerseyClientBuilder.createClient();
            String xmlResponse = client.target("https://api.example.net/data.xml")
                                      .request()
                                      .get(String.class);
            
            ByteArrayInputStream bis = new ByteArrayInputStream(xmlResponse.getBytes());
            
            // ruleid: java-xml-decoder
            XMLDecoder decoder = new XMLDecoder(bis);
            
            Object data = decoder.readObject();
            decoder.close();
            
            System.out.println("API data: " + data);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Processing XML from multipart form data
    public void bad_case_15(HttpServletRequest request) {
        try {
            Part xmlPart = request.getPart("config_file");
            InputStream inputStream = xmlPart.getInputStream();
            
            // ruleid: java-xml-decoder
            XMLDecoder decoder = new XMLDecoder(inputStream);
            
            Object config = decoder.readObject();
            decoder.close();
            
            System.out.println("Uploaded config: " + config);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // True Negative Examples (Safe/Secure Code)
    
    // Spring MVC web application using safe XML parsing instead of XMLDecoder
    @RequestMapping("/process-xml-safe")
    public void good_case_1(HttpServletRequest request, HttpServletResponse response) {
        try {
            String xmlData = request.getParameter("xml_data");
            ByteArrayInputStream bis = new ByteArrayInputStream(xmlData.getBytes());
            
            // ok: java-xml-decoder
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // Disable DTDs and external entities
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setXIncludeAware(false);
            dbf.setExpandEntityReferences(false);
            
            DocumentBuilder builder = dbf.newDocumentBuilder();
            org.w3c.dom.Document doc = builder.parse(bis);
            
            response.getWriter().write("Processed safely");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Using OkHttp client with safe XML parsing
    public void good_case_2() {
        try {
            OkHttpClient client = new OkHttpClient();
            Request request = new Request.Builder()
                .url("https://example.com/user-data.xml")
                .build();
                
            Response response = client.newCall(request).execute();
            String xmlData = response.body().string();
            
            // ok: java-xml-decoder
            // Use JAXB or other safe parsing instead of XMLDecoder
            SAXParserFactory spf = SAXParserFactory.newInstance();
            spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            spf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            
            SAXParser parser = spf.newSAXParser();
            MyHandler handler = new MyHandler();
            parser.parse(new InputSource(new StringReader(xmlData)), handler);
            
            System.out.println("Processed user data safely");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Struts2 application processing multipart XML upload safely
    public void good_case_3(MultiPartRequestWrapper request) {
        try {
            InputStream xmlStream = request.getFileInputStream("user_config");
            
            // ok: java-xml-decoder
            // Use StAX parser instead of XMLDecoder
            XMLInputFactory xif = XMLInputFactory.newFactory();
            xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
            xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
            
            XMLStreamReader xsr = xif.createXMLStreamReader(xmlStream);
            while (xsr.hasNext()) {
                xsr.next();
                // Process XML safely
            }
            
            System.out.println("User configuration loaded safely");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Using Apache HttpClient to fetch and process XML safely
    public void good_case_4() {
        try {
            CloseableHttpClient httpClient = HttpClients.createDefault();
            HttpGet request = new HttpGet("https://api.example.org/data.xml");
            
            String xmlContent = EntityUtils.toString(httpClient.execute(request).getEntity());
            
            // ok: java-xml-decoder
            // Use DOM parser with security features enabled
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            dbf.setXIncludeAware(false);
            dbf.setExpandEntityReferences(false);
            
            DocumentBuilder db = dbf.newDocumentBuilder();
            org.w3c.dom.Document doc = db.parse(new InputSource(new StringReader(xmlContent)));
            
            System.out.println("API data processed safely");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Jersey REST client fetching XML configuration safely
    public void good_case_5() {
        try {
            Client client = Client.create();
            WebResource webResource = client.resource("https://config.example.com/settings.xml");
            
            String response = webResource.accept("application/xml").get(String.class);
            
            // ok: java-xml-decoder
            // Use SAX parser with security features enabled
            SAXParserFactory spf = SAXParserFactory.newInstance();
            spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            
            SAXParser saxParser = spf.newSAXParser();
            ConfigHandler handler = new ConfigHandler();
            saxParser.parse(new InputSource(new StringReader(response)), handler);
            
            System.out.println("Loaded settings safely");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Retrofit API client processing XML response safely
    public void good_case_6() {
        try {
            Retrofit retrofit = new Retrofit.Builder()
                .baseUrl("https://api.example.com/")
                .build();
                
            ApiService service = retrofit.create(ApiService.class);
            Response<ResponseBody> response = service.getXmlData().execute();
            
            String xmlData = response.body().string();
            
            // ok: java-xml-decoder
            // Use StAX parser with security features
            XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();
            xmlInputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
            xmlInputFactory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
            
            XMLStreamReader reader = xmlInputFactory.createXMLStreamReader(new StringReader(xmlData));
            // Process XML safely with reader
            
            System.out.println("API result processed safely");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Spring RestTemplate fetching XML data safely
    public void good_case_7() {
        try {
            RestTemplate restTemplate = new RestTemplate();
            String xmlResponse = restTemplate.getForObject("https://service.example.com/data.xml", String.class);
            
            // ok: java-xml-decoder
            // Use transformer with security features
            TransformerFactory tf = TransformerFactory.newInstance();
            tf.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            tf.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
            
            // Create safe source
            Source xmlSource = new StreamSource(new StringReader(xmlResponse));
            // Process XML safely
            
            System.out.println("Service data processed safely");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // RESTEasy client processing XML response safely
    public void good_case_8() {
        try {
            ResteasyClient client = new ResteasyClientBuilder().build();
            String xmlData = client.target("https://api.example.org/config.xml")
                                  .request()
                                  .get(String.class);
            
            // ok: java-xml-decoder
            // Use DOM parser with security features
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            dbf.setXIncludeAware(false);
            dbf.setExpandEntityReferences(false);
            
            DocumentBuilder db = dbf.newDocumentBuilder();
            org.w3c.dom.Document doc = db.parse(new InputSource(new StringReader(xmlData)));
            
            System.out.println("Configuration processed safely");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Apache CXF WebClient fetching XML safely
    public void good_case_9() {
        try {
            WebClient client = WebClient.create("https://services.example.com");
            String response = client.path("/user/profile.xml").get(String.class);
            
            // ok: java-xml-decoder
            // Use SAX parser with security features
            SAXParserFactory spf = SAXParserFactory.newInstance();
            spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            
            SAXParser parser = spf.newSAXParser();
            ProfileHandler handler = new ProfileHandler();
            parser.parse(new InputSource(new StringReader(response)), handler);
            
            System.out.println("User profile processed safely");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Processing XML from HTTP request headers safely
    public void good_case_10(HttpServletRequest request) {
        try {
            String encodedXml = request.getHeader("X-Config-Data");
            byte[] decodedXml = Base64.getDecoder().decode(encodedXml);
            
            // ok: java-xml-decoder
            // Use StAX parser with security features
            XMLInputFactory xif = XMLInputFactory.newFactory();
            xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
            xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
            
            XMLStreamReader xsr = xif.createXMLStreamReader(new ByteArrayInputStream(decodedXml));
            // Process XML safely
            
            System.out.println("Header config processed safely");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Processing XML from request cookies safely
    public void good_case_11(HttpServletRequest request) {
        try {
            Cookie[] cookies = request.getCookies();
            String xmlData = null;
            
            for (Cookie cookie : cookies) {
                if ("user_settings".equals(cookie.getName())) {
                    xmlData = cookie.getValue();
                    break;
                }
            }
            
            if (xmlData != null) {
                byte[] decodedXml = Base64.getDecoder().decode(xmlData);
                
                // ok: java-xml-decoder
                // Use DOM parser with security features
                DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
                dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
                dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
                dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
                dbf.setXIncludeAware(false);
                dbf.setExpandEntityReferences(false);
                
                DocumentBuilder db = dbf.newDocumentBuilder();
                org.w3c.dom.Document doc = db.parse(new ByteArrayInputStream(decodedXml));
                
                System.out.println("User settings processed safely");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Processing XML from request body using raw input stream safely
    public void good_case_12(HttpServletRequest request) {
        try {
            String xmlData = IOUtils.toString(request.getInputStream(), "UTF-8");
            
            // ok: java-xml-decoder
            // Use SAX parser with security features
            SAXParserFactory spf = SAXParserFactory.newInstance();
            spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            
            SAXParser parser = spf.newSAXParser();
            DefaultHandler handler = new DefaultHandler();
            parser.parse(new InputSource(new StringReader(xmlData)), handler);
            
            System.out.println("Request body data processed safely");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Processing XML from URL query parameters safely
    public void good_case_13(HttpServletRequest request) {
        try {
            String encodedXml = request.getParameter("config");
            if (encodedXml != null) {
                byte[] decodedXml = Base64.getDecoder().decode(encodedXml);
                
                // ok: java-xml-decoder
                // Use StAX parser with security features
                XMLInputFactory xif = XMLInputFactory.newFactory();
                xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
                xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
                
                XMLStreamReader xsr = xif.createXMLStreamReader(new ByteArrayInputStream(decodedXml));
                // Process XML safely
                
                System.out.println("Query parameter config processed safely");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Glassfish Jersey client fetching XML safely
    public void good_case_14() {
        try {
            JerseyClient client = JerseyClientBuilder.createClient();
            String xmlResponse = client.target("https://api.example.net/data.xml")
                                      .request()
                                      .get(String.class);
            
            // ok: java-xml-decoder
            // Use transformer with security features
            TransformerFactory tf = TransformerFactory.newInstance();
            tf.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            tf.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
            
            Source xmlSource = new StreamSource(new StringReader(xmlResponse));
            // Process XML safely
            
            System.out.println("API data processed safely");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Processing XML from multipart form data safely
    public void good_case_15(HttpServletRequest request) {
        try {
            Part xmlPart = request.getPart("config_file");
            InputStream inputStream = xmlPart.getInputStream();
            
            // ok: java-xml-decoder
            // Use DOM parser with security features
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            dbf.setXIncludeAware(false);
            dbf.setExpandEntityReferences(false);
            
            DocumentBuilder db = dbf.newDocumentBuilder();
            org.w3c.dom.Document doc = db.parse(inputStream);
            
            System.out.println("Uploaded config processed safely");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Helper classes
    private static class MyHandler extends DefaultHandler {}
    private static class ConfigHandler extends DefaultHandler {}
    private static class ProfileHandler extends DefaultHandler {}
    
    private interface ApiService {
        @GET("data.xml")
        Call<ResponseBody> getXmlData();
    }
}
// {/fact}