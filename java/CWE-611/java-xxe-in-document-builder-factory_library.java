import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;
import java.io.IOException;
import java.io.StringReader;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamException;
import org.apache.commons.io.IOUtils;
import org.jdom2.input.SAXBuilder;
import org.dom4j.io.SAXReader;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Schema;
import javax.xml.validation.Validator;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpEntity;
import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import nu.xom.Builder;
import nu.xom.ParsingException;
import org.apache.commons.digester3.Digester;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.Unmarshaller;
import org.apache.axiom.om.OMXMLBuilderFactory;
import org.apache.axiom.om.OMXMLParserWrapper;
import org.apache.commons.digester.Digester;
import org.xml.sax.InputSource;
import java.io.StringWriter;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.apache.commons.configuration.XMLConfiguration;
import org.apache.commons.configuration.ConfigurationException;
import javax.xml.xpath.XPathFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;

// Security Issue: XML External Entity (XXE) Injection in Java XML Parsers

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) throws ParserConfigurationException, SAXException, IOException {
    // Vulnerable implementation using DocumentBuilderFactory with HTTP input
    String xmlData = request.getParameter("xml");
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    // ruleid: java-xxe-in-document-builder-factory
    DocumentBuilder builder = dbf.newDocumentBuilder();
    Document doc = builder.parse(new ByteArrayInputStream(xmlData.getBytes()));
    System.out.println("Parsed XML document: " + doc.getDocumentElement().getNodeName());
}

public void bad_case_2(HttpServletRequest request) throws XMLStreamException {
    // Vulnerable implementation using XMLInputFactory with HTTP input
    String xmlData = request.getParameter("xml");
    XMLInputFactory factory = XMLInputFactory.newInstance();
    // ruleid: java-xxe-in-document-builder-factory
    XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlData));
    while (reader.hasNext()) {
        reader.next();
    }
}

public void bad_case_3(HttpServletRequest request) throws Exception {
    // Vulnerable implementation using SAXBuilder (JDOM) with HTTP input
    String xmlData = request.getParameter("xml");
    SAXBuilder builder = new SAXBuilder();
    // ruleid: java-xxe-in-document-builder-factory
    org.jdom2.Document document = builder.build(new StringReader(xmlData));
    System.out.println("Root element: " + document.getRootElement().getName());
}

public void bad_case_4(HttpServletRequest request) throws Exception {
    // Vulnerable implementation using SAXReader (DOM4J) with HTTP input
    String xmlData = request.getParameter("xml");
    SAXReader reader = new SAXReader();
    // ruleid: java-xxe-in-document-builder-factory
    org.dom4j.Document document = reader.read(new StringReader(xmlData));
    System.out.println("Root element: " + document.getRootElement().getName());
}

public void bad_case_5(HttpServletRequest request) throws Exception {
    // Vulnerable implementation using SchemaFactory with HTTP input
    String xmlData = request.getParameter("xml");
    String xsdData = request.getParameter("xsd");
    
    SchemaFactory factory = SchemaFactory.newInstance("http://www.w3.org/2001/XMLSchema");
    // ruleid: java-xxe-in-document-builder-factory
    Schema schema = factory.newSchema(new StreamSource(new StringReader(xsdData)));
    Validator validator = schema.newValidator();
    validator.validate(new StreamSource(new StringReader(xmlData)));
}

@RestController
public class bad_case_6 {
    @PostMapping("/process-xml")
    public ResponseEntity<String> processXml(@RequestBody String xmlData) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // ruleid: java-xxe-in-document-builder-factory
        DocumentBuilder builder = dbf.newDocumentBuilder();
        Document doc = builder.parse(new ByteArrayInputStream(xmlData.getBytes()));
        return ResponseEntity.ok("Processed XML: " + doc.getDocumentElement().getNodeName());
    }
}

public void bad_case_7(HttpServletRequest request) throws Exception {
    // Vulnerable implementation using XmlMapper (Jackson) with HTTP input
    String xmlData = request.getParameter("xml");
    XmlMapper xmlMapper = new XmlMapper();
    // ruleid: java-xxe-in-document-builder-factory
    Object obj = xmlMapper.readValue(xmlData, Object.class);
    System.out.println("Parsed object: " + obj);
}

public void bad_case_8(HttpServletRequest request) throws ParsingException, IOException {
    // Vulnerable implementation using XOM Builder with HTTP input
    String xmlData = request.getParameter("xml");
    Builder builder = new Builder();
    // ruleid: java-xxe-in-document-builder-factory
    nu.xom.Document doc = builder.build(new StringReader(xmlData));
    System.out.println("Root element: " + doc.getRootElement().getLocalName());
}

public void bad_case_9(HttpServletRequest request) throws Exception {
    // Vulnerable implementation using Apache Commons Digester with HTTP input
    String xmlData = request.getParameter("xml");
    Digester digester = new Digester();
    // ruleid: java-xxe-in-document-builder-factory
    Object result = digester.parse(new StringReader(xmlData));
    System.out.println("Parsed result: " + result);
}

public void bad_case_10(HttpServletRequest request) throws Exception {
    // Vulnerable implementation using JAXB with HTTP input
    String xmlData = request.getParameter("xml");
    JAXBContext jaxbContext = JAXBContext.newInstance(Object.class);
    Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
    // ruleid: java-xxe-in-document-builder-factory
    Object result = unmarshaller.unmarshal(new StringReader(xmlData));
    System.out.println("Unmarshalled object: " + result);
}

public void bad_case_11(HttpServletRequest request) throws Exception {
    // Vulnerable implementation using Apache Axiom with HTTP input
    String xmlData = request.getParameter("xml");
    // ruleid: java-xxe-in-document-builder-factory
    OMXMLParserWrapper builder = OMXMLBuilderFactory.createOMBuilder(new StringReader(xmlData));
    System.out.println("Root element: " + builder.getDocumentElement().getLocalName());
}

public void bad_case_12(HttpServletRequest request) throws Exception {
    // Vulnerable implementation using TransformerFactory with HTTP input
    String xmlData = request.getParameter("xml");
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    DocumentBuilder builder = dbf.newDocumentBuilder();
    Document doc = builder.parse(new ByteArrayInputStream(xmlData.getBytes()));
    
    TransformerFactory transformerFactory = TransformerFactory.newInstance();
    // ruleid: java-xxe-in-document-builder-factory
    Transformer transformer = transformerFactory.newTransformer();
    StringWriter writer = new StringWriter();
    transformer.transform(new DOMSource(doc), new StreamResult(writer));
    System.out.println(writer.toString());
}

public void bad_case_13(HttpServletRequest request) throws ConfigurationException {
    // Vulnerable implementation using Apache Commons Configuration with HTTP input
    String configPath = request.getParameter("configPath");
    // ruleid: java-xxe-in-document-builder-factory
    XMLConfiguration config = new XMLConfiguration(configPath);
    String value = config.getString("property.key");
    System.out.println("Config value: " + value);
}

public void bad_case_14(HttpServletRequest request) throws Exception {
    // Vulnerable implementation using XPathFactory with HTTP input
    String xmlData = request.getParameter("xml");
    String xpathExpr = request.getParameter("xpath");
    
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    DocumentBuilder builder = dbf.newDocumentBuilder();
    Document doc = builder.parse(new ByteArrayInputStream(xmlData.getBytes()));
    
    XPathFactory xPathFactory = XPathFactory.newInstance();
    // ruleid: java-xxe-in-document-builder-factory
    XPath xpath = xPathFactory.newXPath();
    XPathExpression expr = xpath.compile(xpathExpr);
    String result = expr.evaluate(doc);
    System.out.println("XPath result: " + result);
}

public void bad_case_15(HttpServletRequest request) throws Exception {
    // Vulnerable implementation using SAX InputSource with HTTP input
    String xmlData = request.getParameter("xml");
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    DocumentBuilder builder = dbf.newDocumentBuilder();
    InputSource inputSource = new InputSource(new StringReader(xmlData));
    // ruleid: java-xxe-in-document-builder-factory
    Document doc = builder.parse(inputSource);
    System.out.println("Root element: " + doc.getDocumentElement().getNodeName());
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) throws ParserConfigurationException, SAXException, IOException {
    // Secure implementation using DocumentBuilderFactory with HTTP input
    String xmlData = request.getParameter("xml");
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    
    // ok: java-xxe-in-document-builder-factory
    dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
    dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    dbf.setXIncludeAware(false);
    dbf.setExpandEntityReferences(false);
    
    DocumentBuilder builder = dbf.newDocumentBuilder();
    Document doc = builder.parse(new ByteArrayInputStream(xmlData.getBytes()));
    System.out.println("Parsed XML document: " + doc.getDocumentElement().getNodeName());
}

public void good_case_2(HttpServletRequest request) throws XMLStreamException {
    // Secure implementation using XMLInputFactory with HTTP input
    String xmlData = request.getParameter("xml");
    XMLInputFactory factory = XMLInputFactory.newInstance();
    
    // ok: java-xxe-in-document-builder-factory
    factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
    factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
    
    XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlData));
    while (reader.hasNext()) {
        reader.next();
    }
}

public void good_case_3(HttpServletRequest request) throws Exception {
    // Secure implementation using SAXBuilder (JDOM) with HTTP input
    String xmlData = request.getParameter("xml");
    SAXBuilder builder = new SAXBuilder();
    
    // ok: java-xxe-in-document-builder-factory
    builder.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    builder.setFeature("http://xml.org/sax/features/external-general-entities", false);
    builder.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    builder.setExpandEntities(false);
    
    org.jdom2.Document document = builder.build(new StringReader(xmlData));
    System.out.println("Root element: " + document.getRootElement().getName());
}

public void good_case_4(HttpServletRequest request) throws Exception {
    // Secure implementation using SAXReader (DOM4J) with HTTP input
    String xmlData = request.getParameter("xml");
    SAXReader reader = new SAXReader();
    
    // ok: java-xxe-in-document-builder-factory
    reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
    reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    
    org.dom4j.Document document = reader.read(new StringReader(xmlData));
    System.out.println("Root element: " + document.getRootElement().getName());
}

public void good_case_5(HttpServletRequest request) throws Exception {
    // Secure implementation using SchemaFactory with HTTP input
    String xmlData = request.getParameter("xml");
    String xsdData = request.getParameter("xsd");
    
    SchemaFactory factory = SchemaFactory.newInstance("http://www.w3.org/2001/XMLSchema");
    
    // ok: java-xxe-in-document-builder-factory
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    
    Schema schema = factory.newSchema(new StreamSource(new StringReader(xsdData)));
    Validator validator = schema.newValidator();
    validator.validate(new StreamSource(new StringReader(xmlData)));
}

@RestController
public class good_case_6 {
    @PostMapping("/process-xml")
    public ResponseEntity<String> processXml(@RequestBody String xmlData) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        
        // ok: java-xxe-in-document-builder-factory
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        
        DocumentBuilder builder = dbf.newDocumentBuilder();
        Document doc = builder.parse(new ByteArrayInputStream(xmlData.getBytes()));
        return ResponseEntity.ok("Processed XML: " + doc.getDocumentElement().getNodeName());
    }
}

public void good_case_7(HttpServletRequest request) throws Exception {
    // Secure implementation using XmlMapper (Jackson) with HTTP input
    String xmlData = request.getParameter("xml");
    XmlMapper xmlMapper = new XmlMapper();
    
    // ok: java-xxe-in-document-builder-factory
    xmlMapper.getFactory().getXMLInputFactory().setProperty(XMLInputFactory.SUPPORT_DTD, false);
    xmlMapper.getFactory().getXMLInputFactory().setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
    
    Object obj = xmlMapper.readValue(xmlData, Object.class);
    System.out.println("Parsed object: " + obj);
}

public void good_case_8(HttpServletRequest request) throws ParsingException, IOException {
    // Secure implementation using XOM Builder with HTTP input
    String xmlData = request.getParameter("xml");
    
    // ok: java-xxe-in-document-builder-factory
    // Create a secure SAXParser first
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
    dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    
    // Use the secure parser with XOM
    Builder builder = new Builder(dbf.newDocumentBuilder().getClass().newInstance());
    nu.xom.Document doc = builder.build(new StringReader(xmlData));
    System.out.println("Root element: " + doc.getRootElement().getLocalName());
}

public void good_case_9(HttpServletRequest request) throws Exception {
    // Secure implementation using Apache Commons Digester with HTTP input
    String xmlData = request.getParameter("xml");
    Digester digester = new Digester();
    
    // ok: java-xxe-in-document-builder-factory
    digester.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    digester.setFeature("http://xml.org/sax/features/external-general-entities", false);
    digester.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    
    Object result = digester.parse(new StringReader(xmlData));
    System.out.println("Parsed result: " + result);
}

public void good_case_10(HttpServletRequest request) throws Exception {
    // Secure implementation using JAXB with HTTP input
    String xmlData = request.getParameter("xml");
    JAXBContext jaxbContext = JAXBContext.newInstance(Object.class);
    Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
    
    // ok: java-xxe-in-document-builder-factory
    // Create a secure XMLInputFactory
    XMLInputFactory xif = XMLInputFactory.newInstance();
    xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
    xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
    
    // Use the secure factory with JAXB
    XMLStreamReader xsr = xif.createXMLStreamReader(new StringReader(xmlData));
    Object result = unmarshaller.unmarshal(xsr);
    System.out.println("Unmarshalled object: " + result);
}

public void good_case_11(HttpServletRequest request) throws Exception {
    // Secure implementation using Apache Axiom with HTTP input
    String xmlData = request.getParameter("xml");
    
    // ok: java-xxe-in-document-builder-factory
    // Create a secure XMLInputFactory
    XMLInputFactory factory = XMLInputFactory.newInstance();
    factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
    factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
    
    // Use the secure factory with Axiom
    OMXMLParserWrapper builder = OMXMLBuilderFactory.createOMBuilder(factory, new StringReader(xmlData));
    System.out.println("Root element: " + builder.getDocumentElement().getLocalName());
}

public void good_case_12(HttpServletRequest request) throws Exception {
    // Secure implementation using TransformerFactory with HTTP input
    String xmlData = request.getParameter("xml");
    
    // Create secure DocumentBuilderFactory
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
    dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    DocumentBuilder builder = dbf.newDocumentBuilder();
    Document doc = builder.parse(new ByteArrayInputStream(xmlData.getBytes()));
    
    // ok: java-xxe-in-document-builder-factory
    TransformerFactory transformerFactory = TransformerFactory.newInstance();
    transformerFactory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
    transformerFactory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
    
    Transformer transformer = transformerFactory.newTransformer();
    StringWriter writer = new StringWriter();
    transformer.transform(new DOMSource(doc), new StreamResult(writer));
    System.out.println(writer.toString());
}

public void good_case_13(HttpServletRequest request) throws ConfigurationException {
    // Secure implementation using Apache Commons Configuration with HTTP input
    String configPath = request.getParameter("configPath");
    
    // ok: java-xxe-in-document-builder-factory
    XMLConfiguration config = new XMLConfiguration();
    config.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    config.setFeature("http://xml.org/sax/features/external-general-entities", false);
    config.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    config.load(configPath);
    
    String value = config.getString("property.key");
    System.out.println("Config value: " + value);
}

public void good_case_14(HttpServletRequest request) throws Exception {
    // Secure implementation using XPathFactory with HTTP input
    String xmlData = request.getParameter("xml");
    String xpathExpr = request.getParameter("xpath");
    
    // Create secure DocumentBuilderFactory
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
    dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    DocumentBuilder builder = dbf.newDocumentBuilder();
    Document doc = builder.parse(new ByteArrayInputStream(xmlData.getBytes()));
    
    // ok: java-xxe-in-document-builder-factory
    XPathFactory xPathFactory = XPathFactory.newInstance();
    XPath xpath = xPathFactory.newXPath();
    XPathExpression expr = xpath.compile(xpathExpr);
    String result = expr.evaluate(doc);
    System.out.println("XPath result: " + result);
}

public void good_case_15(HttpServletRequest request) throws Exception {
    // Secure implementation using SAX InputSource with HTTP input
    String xmlData = request.getParameter("xml");
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    
    // ok: java-xxe-in-document-builder-factory
    dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
    dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    dbf.setXIncludeAware(false);
    dbf.setExpandEntityReferences(false);
    
    DocumentBuilder builder = dbf.newDocumentBuilder();
    InputSource inputSource = new InputSource(new StringReader(xmlData));
    Document doc = builder.parse(inputSource);
    System.out.println("Root element: " + doc.getDocumentElement().getNodeName());
}