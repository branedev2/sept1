import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;
import org.xml.sax.InputSource;
import java.io.IOException;
import java.io.StringReader;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.*;
import org.apache.struts2.interceptor.ServletRequestAware;
import org.apache.commons.io.IOUtils;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import org.jdom2.input.SAXBuilder;
import org.jdom2.JDOMException;
import org.dom4j.io.SAXReader;
import org.dom4j.DocumentException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.stream.StreamSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.TransformerException;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Schema;
import javax.xml.XMLConstants;
import org.xml.sax.helpers.XMLReaderFactory;
import org.xml.sax.XMLReader;
import javax.xml.xpath.XPathFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import org.apache.commons.digester3.Digester;
import nu.xom.Builder;
import nu.xom.ParsingException;
import org.apache.xerces.parsers.SAXParser;
import org.apache.xerces.parsers.DOMParser;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.JAXBException;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import spark.Request;
import spark.Response;
import spark.Route;
import io.javalin.http.Context;
import io.javalin.Javalin;
import com.sun.org.apache.xerces.internal.parsers.XMLParser;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;

// Security Issue: XML External Entity (XXE) Injection

// True Positive Examples (Vulnerable/Insecure Code)
public class XXEVulnerableExamples {

// {fact rule=xml-external-entity@v1.0 defects=1}
    public static void bad_case_1(HttpServletRequest request) {
        try {
            String xmlData = request.getParameter("xml");
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // ruleid: java-xml-external-entity-injection
            dbf.setXIncludeAware(true);
            DocumentBuilder builder = dbf.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(xmlData)));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_2(HttpServletRequest request) {
        try {
            String xmlData = IOUtils.toString(request.getInputStream(), StandardCharsets.UTF_8);
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // ruleid: java-xml-external-entity-injection
            dbf.setExpandEntityReferences(true);
            DocumentBuilder builder = dbf.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(xmlData)));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @PostMapping("/parse-xml")
    public static void bad_case_3(@RequestBody String xmlData) {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // No security features enabled
            // ruleid: java-xml-external-entity-injection
            DocumentBuilder builder = dbf.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(xmlData)));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_4(HttpServletRequest request) {
        try {
            String xmlData = request.getParameter("xml");
            XMLInputFactory factory = XMLInputFactory.newInstance();
            // ruleid: java-xml-external-entity-injection
            factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, true);
            XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlData));
        } catch (XMLStreamException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_5(HttpServletRequest request) {
        try {
            String xmlData = request.getParameter("xml");
            SAXBuilder saxBuilder = new SAXBuilder();
            // ruleid: java-xml-external-entity-injection
            saxBuilder.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
            org.jdom2.Document document = saxBuilder.build(new StringReader(xmlData));
        } catch (JDOMException | IOException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_6(HttpServletRequest request) {
        try {
            String xmlData = request.getParameter("xml");
            SAXReader reader = new SAXReader();
            // No security features enabled
            // ruleid: java-xml-external-entity-injection
            org.dom4j.Document document = reader.read(new StringReader(xmlData));
        } catch (DocumentException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_7(HttpServletRequest request) {
        try {
            String xmlData = request.getParameter("xml");
            TransformerFactory factory = TransformerFactory.newInstance();
            // ruleid: java-xml-external-entity-injection
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, false);
            Transformer transformer = factory.newTransformer();
            transformer.transform(
                new StreamSource(new StringReader(xmlData)),
                new StreamResult(System.out)
            );
        } catch (TransformerException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_8(HttpServletRequest request) {
        try {
            String xmlData = request.getParameter("xml");
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            // ruleid: java-xml-external-entity-injection
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "all");
            Schema schema = factory.newSchema(new StreamSource(new StringReader(xmlData)));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_9(HttpServletRequest request) {
        try {
            String xmlData = request.getParameter("xml");
            XMLReader xmlReader = XMLReaderFactory.createXMLReader();
            // ruleid: java-xml-external-entity-injection
            xmlReader.setFeature("http://xml.org/sax/features/external-general-entities", true);
            xmlReader.parse(new InputSource(new StringReader(xmlData)));
        } catch (SAXException | IOException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_10(HttpServletRequest request) {
        try {
            String xmlData = request.getParameter("xml");
            XPathFactory xPathFactory = XPathFactory.newInstance();
            // No security features enabled
            // ruleid: java-xml-external-entity-injection
            XPath xpath = xPathFactory.newXPath();
            XPathExpression expr = xpath.compile("//user");
            expr.evaluate(new InputSource(new StringReader(xmlData)));
        } catch (XPathExpressionException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_11(HttpServletRequest request) {
        try {
            String xmlData = request.getParameter("xml");
            Digester digester = new Digester();
            // ruleid: java-xml-external-entity-injection
            digester.setValidating(false);
            digester.parse(new StringReader(xmlData));
        } catch (IOException | SAXException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_12(HttpServletRequest request) {
        try {
            String xmlData = request.getParameter("xml");
            Builder builder = new Builder();
            // No security features enabled
            // ruleid: java-xml-external-entity-injection
            nu.xom.Document doc = builder.build(new StringReader(xmlData));
        } catch (ParsingException | IOException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_13(HttpServletRequest request) {
        try {
            String xmlData = request.getParameter("xml");
            SAXParser parser = new SAXParser();
            // ruleid: java-xml-external-entity-injection
            parser.setFeature("http://xml.org/sax/features/external-general-entities", true);
            parser.parse(new InputSource(new StringReader(xmlData)));
        } catch (SAXException | IOException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_14(HttpServletRequest request) {
        try {
            String xmlData = request.getParameter("xml");
            DOMParser parser = new DOMParser();
            // ruleid: java-xml-external-entity-injection
            parser.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", true);
            parser.parse(new InputSource(new StringReader(xmlData)));
        } catch (SAXException | IOException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_15(HttpServletRequest request) {
        try {
            String xmlData = request.getParameter("xml");
            JAXBContext jaxbContext = JAXBContext.newInstance(Object.class);
            Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
            // No security features enabled
            // ruleid: java-xml-external-entity-injection
            Object obj = unmarshaller.unmarshal(new StringReader(xmlData));
        } catch (JAXBException e) {
            e.printStackTrace();
        }
    }

    // True Negative Examples (Safe/Secure Code)
    public static void good_case_1(HttpServletRequest request) {
        try {
            String xmlData = request.getParameter("xml");
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // ok: java-xml-external-entity-injection
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setXIncludeAware(false);
            dbf.setExpandEntityReferences(false);
            DocumentBuilder builder = dbf.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(xmlData)));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void good_case_2(HttpServletRequest request) {
        try {
            String xmlData = IOUtils.toString(request.getInputStream(), StandardCharsets.UTF_8);
            XMLInputFactory factory = XMLInputFactory.newInstance();
            // ok: java-xml-external-entity-injection
            factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
            factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
            XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlData));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @PostMapping("/parse-xml-secure")
    public static void good_case_3(@RequestBody String xmlData) {
        try {
            SAXBuilder saxBuilder = new SAXBuilder();
            // ok: java-xml-external-entity-injection
            saxBuilder.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            saxBuilder.setFeature("http://xml.org/sax/features/external-general-entities", false);
            saxBuilder.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            saxBuilder.setExpandEntities(false);
            org.jdom2.Document document = saxBuilder.build(new StringReader(xmlData));
        } catch (JDOMException | IOException e) {
            e.printStackTrace();
        }
    }

    public static void good_case_4(HttpServletRequest request) {
        try {
            String xmlData = request.getParameter("xml");
            SAXReader reader = new SAXReader();
            // ok: java-xml-external-entity-injection
            reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
            reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            org.dom4j.Document document = reader.read(new StringReader(xmlData));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void good_case_5(HttpServletRequest request) {
        try {
            String xmlData = request.getParameter("xml");
            TransformerFactory factory = TransformerFactory.newInstance();
            // ok: java-xml-external-entity-injection
            factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            Transformer transformer = factory.newTransformer();
            transformer.transform(
                new StreamSource(new StringReader(xmlData)),
                new StreamResult(System.out)
            );
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void good_case_6(HttpServletRequest request) {
        try {
            String xmlData = request.getParameter("xml");
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            // ok: java-xml-external-entity-injection
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            Schema schema = factory.newSchema(new StreamSource(new StringReader(xmlData)));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void good_case_7(HttpServletRequest request) {
        try {
            String xmlData = request.getParameter("xml");
            XMLReader xmlReader = XMLReaderFactory.createXMLReader();
            // ok: java-xml-external-entity-injection
            xmlReader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            xmlReader.setFeature("http://xml.org/sax/features/external-general-entities", false);
            xmlReader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            xmlReader.parse(new InputSource(new StringReader(xmlData)));
        } catch (SAXException | IOException e) {
            e.printStackTrace();
        }
    }

    public static void good_case_8(HttpServletRequest request) {
        try {
            String xmlData = request.getParameter("xml");
            XPathFactory xPathFactory = XPathFactory.newInstance();
            // ok: java-xml-external-entity-injection
            xPathFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            XPath xpath = xPathFactory.newXPath();
            XPathExpression expr = xpath.compile("//user");
            expr.evaluate(new InputSource(new StringReader(xmlData)));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void good_case_9(HttpServletRequest request) {
        try {
            String xmlData = request.getParameter("xml");
            Digester digester = new Digester();
            // ok: java-xml-external-entity-injection
            digester.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            digester.setFeature("http://xml.org/sax/features/external-general-entities", false);
            digester.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            digester.parse(new StringReader(xmlData));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void good_case_10(HttpServletRequest request) {
        try {
            String xmlData = request.getParameter("xml");
            // First check for DOCTYPE to prevent XXE
            if (xmlData.contains("<!DOCTYPE")) {
                throw new SecurityException("DOCTYPE is not allowed");
            }
            
            Builder builder = new Builder(false);
            // ok: java-xml-external-entity-injection
            nu.xom.Document doc = builder.build(new StringReader(xmlData));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void good_case_11(HttpServletRequest request) {
        try {
            String xmlData = request.getParameter("xml");
            SAXParser parser = new SAXParser();
            // ok: java-xml-external-entity-injection
            parser.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            parser.setFeature("http://xml.org/sax/features/external-general-entities", false);
            parser.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            parser.parse(new InputSource(new StringReader(xmlData)));
        } catch (SAXException | IOException e) {
            e.printStackTrace();
        }
    }

    public static void good_case_12(HttpServletRequest request) {
        try {
            String xmlData = request.getParameter("xml");
            DOMParser parser = new DOMParser();
            // ok: java-xml-external-entity-injection
            parser.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            parser.setFeature("http://xml.org/sax/features/external-general-entities", false);
            parser.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            parser.parse(new InputSource(new StringReader(xmlData)));
        } catch (SAXException | IOException e) {
            e.printStackTrace();
        }
    }

    public static void good_case_13(HttpServletRequest request) {
        try {
            String xmlData = request.getParameter("xml");
            JAXBContext jaxbContext = JAXBContext.newInstance(Object.class);
            Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
            
            // Create a secure XMLInputFactory
            XMLInputFactory xif = XMLInputFactory.newFactory();
            // ok: java-xml-external-entity-injection
            xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
            xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
            
            // Use the secure XMLInputFactory with JAXB
            XMLStreamReader xsr = xif.createXMLStreamReader(new StringReader(xmlData));
            Object obj = unmarshaller.unmarshal(xsr);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void good_case_14(spark.Request request, spark.Response response) {
        try {
            String xmlData = request.body();
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // ok: java-xml-external-entity-injection
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            dbf.setXIncludeAware(false);
            dbf.setExpandEntityReferences(false);
            
            DocumentBuilder builder = dbf.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(xmlData)));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void good_case_15(Context ctx) {
        try {
            String xmlData = ctx.body();
            // Pre-process XML to check for DTD
            if (xmlData.contains("<!DOCTYPE") || xmlData.contains("<!ENTITY")) {
                ctx.status(400).result("XML with DTD or ENTITY is not allowed");
                return;
            }
            
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // ok: java-xml-external-entity-injection
            dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            dbf.setXIncludeAware(false);
            dbf.setExpandEntityReferences(false);
            
            DocumentBuilder builder = dbf.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(xmlData)));
        } catch (Exception e) {
            ctx.status(500).result("Error processing XML");
        }
    }
}
// {/fact}