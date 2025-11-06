import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.io.SAXReader;
import org.jdom.input.SAXBuilder;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.XMLReaderFactory;
import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.net.URL;
import org.apache.commons.io.IOUtils;
import org.springframework.web.bind.annotation.*;
import org.apache.struts2.ServletActionContext;
import javax.xml.XMLConstants;
import org.apache.xerces.parsers.SAXParser;
import nu.xom.Builder;
import org.xml.sax.helpers.DefaultHandler;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpEntity;
import org.springframework.web.client.RestTemplate;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.HttpResponse;
import org.apache.http.entity.StringEntity;
import org.apache.http.util.EntityUtils;
import javax.ws.rs.core.Response;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Consumes;
import javax.ws.rs.core.MediaType;
import java.util.Properties;

// Security Issue: XML External Entity (XXE) Injection with SAXReader, SAXBuilder, and XMLReader

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) throws DocumentException {
    String xmlData = request.getParameter("xml");
    SAXReader reader = new SAXReader();
    // ruleid: java-xml-injection-saxreader
    Document document = reader.read(new StringReader(xmlData));
    System.out.println("Document processed: " + document.getRootElement().getName());
}

public void bad_case_2(HttpServletRequest request) throws Exception {
    String xmlContent = request.getHeader("X-XML-Data");
    SAXBuilder builder = new SAXBuilder();
    // ruleid: java-xml-injection-saxreader
    org.jdom.Document document = builder.build(new StringReader(xmlContent));
    System.out.println("Root element: " + document.getRootElement().getName());
}

@PostMapping("/process-xml")
public void bad_case_3(@RequestBody String xmlPayload) throws SAXException, IOException {
    XMLReader xmlReader = XMLReaderFactory.createXMLReader();
    DefaultHandler handler = new DefaultHandler();
    xmlReader.setContentHandler(handler);
    // ruleid: java-xml-injection-saxreader
    xmlReader.parse(new InputSource(new StringReader(xmlPayload)));
    System.out.println("XML processed successfully");
}

public void bad_case_4() throws Exception {
    RestTemplate restTemplate = new RestTemplate();
    ResponseEntity<String> response = restTemplate.getForEntity("https://api.example.com/data", String.class);
    String xmlData = response.getBody();
    
    SAXReader reader = new SAXReader();
    // ruleid: java-xml-injection-saxreader
    Document doc = reader.read(new ByteArrayInputStream(xmlData.getBytes()));
    System.out.println("Processed XML from API: " + doc.asXML());
}

@Path("/xml-service")
public class XmlService {
// {fact rule=xml-external-entity@v1.0 defects=1}
    @POST
    @Consumes(MediaType.APPLICATION_XML)
    public void bad_case_5(String xmlInput) throws Exception {
        SAXBuilder builder = new SAXBuilder();
        // ruleid: java-xml-injection-saxreader
        org.jdom.Document document = builder.build(new StringReader(xmlInput));
        System.out.println("Processed with JAX-RS: " + document.getRootElement().getName());
    }
}
// {/fact}

public void bad_case_6() throws Exception {
    CloseableHttpClient httpClient = HttpClients.createDefault();
    HttpPost httpPost = new HttpPost("https://api.example.org/data");
    HttpResponse response = httpClient.execute(httpPost);
    String xmlContent = EntityUtils.toString(response.getEntity());
    
    XMLReader reader = XMLReaderFactory.createXMLReader();
    // ruleid: java-xml-injection-saxreader
    reader.parse(new InputSource(new StringReader(xmlContent)));
    httpClient.close();
}

public class StrutsXmlAction {
// {fact rule=xml-external-entity@v1.0 defects=1}
    public void bad_case_7() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        String xmlData = IOUtils.toString(request.getInputStream());
        
        SAXParserFactory factory = SAXParserFactory.newInstance();
        SAXParser saxParser = factory.newSAXParser();
        // ruleid: java-xml-injection-saxreader
        saxParser.parse(new ByteArrayInputStream(xmlData.getBytes()), new DefaultHandler());
    }
}
// {/fact}

public void bad_case_8(HttpServletRequest request) throws Exception {
    String url = request.getParameter("xml_url");
    SAXReader reader = new SAXReader();
    // ruleid: java-xml-injection-saxreader
    Document document = reader.read(new URL(url));
    System.out.println("Processed XML from URL: " + document.asXML());
}

public void bad_case_9() throws Exception {
    HttpEntity<String> requestEntity = new HttpEntity<>("request body");
    RestTemplate restTemplate = new RestTemplate();
    ResponseEntity<String> response = restTemplate.postForEntity("https://api.example.com/data", requestEntity, String.class);
    String xmlData = response.getBody();
    
    org.apache.xerces.parsers.SAXParser parser = new org.apache.xerces.parsers.SAXParser();
    // ruleid: java-xml-injection-saxreader
    parser.parse(new InputSource(new StringReader(xmlData)));
}

public void bad_case_10(HttpServletRequest request) throws Exception {
    InputStream xmlStream = request.getInputStream();
    Builder builder = new Builder();
    // ruleid: java-xml-injection-saxreader
    nu.xom.Document doc = builder.build(xmlStream);
    System.out.println("Processed with XOM: " + doc.getRootElement().getLocalName());
}

public void bad_case_11() throws Exception {
    RestTemplate restTemplate = new RestTemplate();
    String xmlResponse = restTemplate.getForObject("https://api.example.com/xml", String.class);
    
    SAXParserFactory spf = SAXParserFactory.newInstance();
    SAXParser parser = spf.newSAXParser();
    XMLReader xmlReader = parser.getXMLReader();
    // ruleid: java-xml-injection-saxreader
    xmlReader.parse(new InputSource(new StringReader(xmlResponse)));
}

@RequestMapping(value = "/upload-xml", method = RequestMethod.POST)
public void bad_case_12(@RequestParam("file") String xmlContent) throws Exception {
    SAXBuilder builder = new SAXBuilder(false);
    // ruleid: java-xml-injection-saxreader
    org.jdom.Document document = builder.build(new StringReader(xmlContent));
    System.out.println("XML uploaded: " + document.getRootElement().getName());
}

public void bad_case_13(HttpServletRequest request) throws Exception {
    String xmlData = request.getParameter("data");
    SAXParserFactory factory = SAXParserFactory.newInstance();
    SAXParser saxParser = factory.newSAXParser();
    XMLReader reader = saxParser.getXMLReader();
    // ruleid: java-xml-injection-saxreader
    reader.parse(new InputSource(new StringReader(xmlData)));
}

public void bad_case_14() throws Exception {
    CloseableHttpClient httpClient = HttpClients.createDefault();
    HttpPost httpPost = new HttpPost("https://api.example.com/xml-service");
    HttpResponse response = httpClient.execute(httpPost);
    String xmlData = EntityUtils.toString(response.getEntity());
    
    SAXReader reader = new SAXReader();
    reader.setEncoding("UTF-8");
    // ruleid: java-xml-injection-saxreader
    Document document = reader.read(new StringReader(xmlData));
}

public void bad_case_15(HttpServletRequest request) throws Exception {
    Properties props = new Properties();
    props.load(request.getInputStream());
    String xmlConfig = props.getProperty("xmlConfig");
    
    SAXBuilder builder = new SAXBuilder();
    // ruleid: java-xml-injection-saxreader
    org.jdom.Document doc = builder.build(new StringReader(xmlConfig));
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) throws DocumentException {
    String xmlData = request.getParameter("xml");
    SAXReader reader = new SAXReader();
    reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
    reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    // ok: java-xml-injection-saxreader
    Document document = reader.read(new StringReader(xmlData));
    System.out.println("Document processed securely: " + document.getRootElement().getName());
}

public void good_case_2(HttpServletRequest request) throws Exception {
    String xmlContent = request.getHeader("X-XML-Data");
    SAXBuilder builder = new SAXBuilder();
    builder.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    builder.setFeature("http://xml.org/sax/features/external-general-entities", false);
    builder.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    // ok: java-xml-injection-saxreader
    org.jdom.Document document = builder.build(new StringReader(xmlContent));
    System.out.println("Root element: " + document.getRootElement().getName());
}

@PostMapping("/process-xml-secure")
public void good_case_3(@RequestBody String xmlPayload) throws SAXException, IOException {
    XMLReader xmlReader = XMLReaderFactory.createXMLReader();
    xmlReader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    xmlReader.setFeature("http://xml.org/sax/features/external-general-entities", false);
    xmlReader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    DefaultHandler handler = new DefaultHandler();
    xmlReader.setContentHandler(handler);
    // ok: java-xml-injection-saxreader
    xmlReader.parse(new InputSource(new StringReader(xmlPayload)));
    System.out.println("XML processed securely");
}

public void good_case_4() throws Exception {
    RestTemplate restTemplate = new RestTemplate();
    ResponseEntity<String> response = restTemplate.getForEntity("https://api.example.com/data", String.class);
    String xmlData = response.getBody();
    
    SAXReader reader = new SAXReader();
    reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
    reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    // ok: java-xml-injection-saxreader
    Document doc = reader.read(new ByteArrayInputStream(xmlData.getBytes()));
    System.out.println("Processed XML from API securely: " + doc.asXML());
}

@Path("/xml-service-secure")
public class SecureXmlService {
// {fact rule=xml-external-entity@v1.0 defects=0}
    @POST
    @Consumes(MediaType.APPLICATION_XML)
    public Response good_case_5(String xmlInput) throws Exception {
        SAXBuilder builder = new SAXBuilder();
        builder.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        builder.setFeature("http://xml.org/sax/features/external-general-entities", false);
        builder.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        // ok: java-xml-injection-saxreader
        org.jdom.Document document = builder.build(new StringReader(xmlInput));
        return Response.ok("Processed with JAX-RS: " + document.getRootElement().getName()).build();
    }
}
// {/fact}

public void good_case_6() throws Exception {
    CloseableHttpClient httpClient = HttpClients.createDefault();
    HttpPost httpPost = new HttpPost("https://api.example.org/data");
    HttpResponse response = httpClient.execute(httpPost);
    String xmlContent = EntityUtils.toString(response.getEntity());
    
    XMLReader reader = XMLReaderFactory.createXMLReader();
    reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
    reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    // ok: java-xml-injection-saxreader
    reader.parse(new InputSource(new StringReader(xmlContent)));
    httpClient.close();
}

public class SecureStrutsXmlAction {
// {fact rule=xml-external-entity@v1.0 defects=0}
    public void good_case_7() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        String xmlData = IOUtils.toString(request.getInputStream());
        
        SAXParserFactory factory = SAXParserFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        SAXParser saxParser = factory.newSAXParser();
        // ok: java-xml-injection-saxreader
        saxParser.parse(new ByteArrayInputStream(xmlData.getBytes()), new DefaultHandler());
    }
}
// {/fact}

public void good_case_8(HttpServletRequest request) throws Exception {
    String url = request.getParameter("xml_url");
    SAXReader reader = new SAXReader();
    reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
    reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    // ok: java-xml-injection-saxreader
    Document document = reader.read(new URL(url));
    System.out.println("Processed XML from URL securely: " + document.asXML());
}

public void good_case_9() throws Exception {
    HttpEntity<String> requestEntity = new HttpEntity<>("request body");
    RestTemplate restTemplate = new RestTemplate();
    ResponseEntity<String> response = restTemplate.postForEntity("https://api.example.com/data", requestEntity, String.class);
    String xmlData = response.getBody();
    
    org.apache.xerces.parsers.SAXParser parser = new org.apache.xerces.parsers.SAXParser();
    parser.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    parser.setFeature("http://xml.org/sax/features/external-general-entities", false);
    parser.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    // ok: java-xml-injection-saxreader
    parser.parse(new InputSource(new StringReader(xmlData)));
}

public void good_case_10(HttpServletRequest request) throws Exception {
    InputStream xmlStream = request.getInputStream();
    Builder builder = new Builder(false);
    // ok: java-xml-injection-saxreader
    nu.xom.Document doc = builder.build(xmlStream);
    System.out.println("Processed with XOM securely: " + doc.getRootElement().getLocalName());
}

public void good_case_11() throws Exception {
    RestTemplate restTemplate = new RestTemplate();
    String xmlResponse = restTemplate.getForObject("https://api.example.com/xml", String.class);
    
    SAXParserFactory spf = SAXParserFactory.newInstance();
    spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
    spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    SAXParser parser = spf.newSAXParser();
    XMLReader xmlReader = parser.getXMLReader();
    // ok: java-xml-injection-saxreader
    xmlReader.parse(new InputSource(new StringReader(xmlResponse)));
}

@RequestMapping(value = "/upload-xml-secure", method = RequestMethod.POST)
public void good_case_12(@RequestParam("file") String xmlContent) throws Exception {
    SAXBuilder builder = new SAXBuilder();
    builder.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    builder.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    builder.setFeature("http://xml.org/sax/features/external-general-entities", false);
    // ok: java-xml-injection-saxreader
    org.jdom.Document document = builder.build(new StringReader(xmlContent));
    System.out.println("XML uploaded securely: " + document.getRootElement().getName());
}

public void good_case_13(HttpServletRequest request) throws Exception {
    String xmlData = request.getParameter("data");
    SAXParserFactory factory = SAXParserFactory.newInstance();
    factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    SAXParser saxParser = factory.newSAXParser();
    XMLReader reader = saxParser.getXMLReader();
    // ok: java-xml-injection-saxreader
    reader.parse(new InputSource(new StringReader(xmlData)));
}

public void good_case_14() throws Exception {
    CloseableHttpClient httpClient = HttpClients.createDefault();
    HttpPost httpPost = new HttpPost("https://api.example.com/xml-service");
    HttpResponse response = httpClient.execute(httpPost);
    String xmlData = EntityUtils.toString(response.getEntity());
    
    SAXReader reader = new SAXReader();
    reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
    reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    reader.setEncoding("UTF-8");
    // ok: java-xml-injection-saxreader
    Document document = reader.read(new StringReader(xmlData));
}

public void good_case_15(HttpServletRequest request) throws Exception {
    Properties props = new Properties();
    props.load(request.getInputStream());
    String xmlConfig = props.getProperty("xmlConfig");
    
    SAXBuilder builder = new SAXBuilder();
    builder.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    builder.setFeature("http://xml.org/sax/features/external-general-entities", false);
    builder.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    // ok: java-xml-injection-saxreader
    org.jdom.Document doc = builder.build(new StringReader(xmlConfig));
}