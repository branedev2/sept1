import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.net.URL;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;
import org.apache.commons.digester.Digester;

public class XXEVulnerabilityTestCases {

    // True Positive Examples (Vulnerable Code)

// {fact rule=missing-xml-validation@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) {
        try {
            String xmlData = request.getParameter("xml");
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            // ruleid: java-xml-validation
            Document doc = db.parse(new InputSource(new StringReader(xmlData)));
            response.getWriter().println("XML processed successfully");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_2(HttpServletRequest request, HttpServletResponse response) {
        try {
            String xmlData = request.getParameter("data");
            SAXParserFactory factory = SAXParserFactory.newInstance();
            SAXParser saxParser = factory.newSAXParser();
            // ruleid: java-xml-validation
            saxParser.parse(new InputSource(new StringReader(xmlData)), new DefaultHandler());
            response.getWriter().println("XML parsed successfully");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_3(HttpServletRequest request, HttpServletResponse response) {
        try {
            String xmlData = request.getHeader("X-XML-Data");
            XMLInputFactory factory = XMLInputFactory.newInstance();
            // ruleid: java-xml-validation
            XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlData));
            while (reader.hasNext()) {
                reader.next();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_4(HttpServletRequest request, HttpServletResponse response) {
        try {
            InputStream xmlStream = request.getInputStream();
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            Transformer transformer = transformerFactory.newTransformer();
            Source source = new StreamSource(xmlStream);
            // ruleid: java-xml-validation
            transformer.transform(source, new StreamResult(response.getOutputStream()));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_5(HttpServletRequest request, HttpServletResponse response) {
        try {
            String xmlData = request.getParameter("xml");
            SchemaFactory factory = SchemaFactory.newInstance("http://www.w3.org/2001/XMLSchema");
            Schema schema = factory.newSchema(new File("schema.xsd"));
            Validator validator = schema.newValidator();
            // ruleid: java-xml-validation
            validator.validate(new StreamSource(new StringReader(xmlData)));
            response.getWriter().println("XML is valid");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_6(HttpServletRequest request, HttpServletResponse response) {
        try {
            String xmlFile = request.getParameter("file");
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            // ruleid: java-xml-validation
            Document doc = db.parse(new File(xmlFile));
            response.getWriter().println("XML file processed");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_7(HttpServletRequest request, HttpServletResponse response) {
        try {
            String xmlUrl = request.getParameter("url");
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            // ruleid: java-xml-validation
            Document doc = db.parse(new URL(xmlUrl).openStream());
            response.getWriter().println("XML from URL processed");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_8(HttpServletRequest request, HttpServletResponse response) {
        try {
            byte[] xmlBytes = request.getParameter("xml").getBytes();
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            // ruleid: java-xml-validation
            Document doc = db.parse(new ByteArrayInputStream(xmlBytes));
            response.getWriter().println("XML processed");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_9(HttpServletRequest request, HttpServletResponse response) {
        try {
            String xmlData = request.getParameter("xml");
            Digester digester = new Digester();
            // ruleid: java-xml-validation
            Object result = digester.parse(new StringReader(xmlData));
            response.getWriter().println("XML digested");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_10(HttpServletRequest request, HttpServletResponse response) {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            DocumentBuilder db = dbf.newDocumentBuilder();
            String xml = request.getParameter("xml");
            // ruleid: java-xml-validation
            Document doc = db.parse(new InputSource(new StringReader(xml)));
            response.getWriter().println("XML processed with namespaces");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_11(HttpServletRequest request, HttpServletResponse response) {
        try {
            String xml = request.getParameter("xml");
            SAXParserFactory spf = SAXParserFactory.newInstance();
            spf.setValidating(true);
            SAXParser parser = spf.newSAXParser();
            // ruleid: java-xml-validation
            parser.parse(new InputSource(new StringReader(xml)), new DefaultHandler());
            response.getWriter().println("XML validated and parsed");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_12(HttpServletRequest request, HttpServletResponse response) {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setXIncludeAware(true);
            DocumentBuilder db = dbf.newDocumentBuilder();
            String xml = request.getParameter("xml");
            // ruleid: java-xml-validation
            Document doc = db.parse(new InputSource(new StringReader(xml)));
            response.getWriter().println("XML processed with XInclude");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_13(HttpServletRequest request, HttpServletResponse response) {
        try {
            String xml = request.getParameter("xml");
            XMLInputFactory xif = XMLInputFactory.newFactory();
            // ruleid: java-xml-validation
            XMLStreamReader reader = xif.createXMLStreamReader(new StringReader(xml));
            while (reader.hasNext()) {
                reader.next();
            }
            response.getWriter().println("XML stream processed");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_14(HttpServletRequest request, HttpServletResponse response) {
        try {
            String xml = request.getParameter("xml");
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setExpandEntityReferences(true);
            DocumentBuilder db = dbf.newDocumentBuilder();
            // ruleid: java-xml-validation
            Document doc = db.parse(new InputSource(new StringReader(xml)));
            response.getWriter().println("XML processed with entity expansion");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_15(HttpServletRequest request, HttpServletResponse response) {
        try {
            String xml = request.getParameter("xml");
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer transformer = tf.newTransformer();
            StreamSource source = new StreamSource(new StringReader(xml));
            StreamResult result = new StreamResult(response.getOutputStream());
            // ruleid: java-xml-validation
            transformer.transform(source, result);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // True Negative Examples (Secure Code)

    public void good_case_1(HttpServletRequest request, HttpServletResponse response) {
        try {
            String xmlData = request.getParameter("xml");
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // ok: java-xml-validation
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new InputSource(new StringReader(xmlData)));
            response.getWriter().println("XML processed securely");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_2(HttpServletRequest request, HttpServletResponse response) {
        try {
            String xmlData = request.getParameter("data");
            SAXParserFactory factory = SAXParserFactory.newInstance();
            // ok: java-xml-validation
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            SAXParser saxParser = factory.newSAXParser();
            saxParser.parse(new InputSource(new StringReader(xmlData)), new DefaultHandler());
            response.getWriter().println("XML parsed securely");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_3(HttpServletRequest request, HttpServletResponse response) {
        try {
            String xmlData = request.getHeader("X-XML-Data");
            XMLInputFactory factory = XMLInputFactory.newInstance();
            // ok: java-xml-validation
            factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
            factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
            XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlData));
            while (reader.hasNext()) {
                reader.next();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_4(HttpServletRequest request, HttpServletResponse response) {
        try {
            InputStream xmlStream = request.getInputStream();
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            // ok: java-xml-validation
            transformerFactory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            transformerFactory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
            Transformer transformer = transformerFactory.newTransformer();
            Source source = new StreamSource(xmlStream);
            transformer.transform(source, new StreamResult(response.getOutputStream()));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_5(HttpServletRequest request, HttpServletResponse response) {
        try {
            String xmlData = request.getParameter("xml");
            SchemaFactory factory = SchemaFactory.newInstance("http://www.w3.org/2001/XMLSchema");
            // ok: java-xml-validation
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setProperty(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_SCHEMA, "");
            Schema schema = factory.newSchema(new File("schema.xsd"));
            Validator validator = schema.newValidator();
            validator.validate(new StreamSource(new StringReader(xmlData)));
            response.getWriter().println("XML is valid");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_6(HttpServletRequest request, HttpServletResponse response) {
        try {
            String xmlFile = request.getParameter("file");
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // ok: java-xml-validation
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setExpandEntityReferences(false);
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new File(xmlFile));
            response.getWriter().println("XML file processed securely");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_7(HttpServletRequest request, HttpServletResponse response) {
        try {
            String xmlUrl = request.getParameter("url");
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // ok: java-xml-validation
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            dbf.setXIncludeAware(false);
            dbf.setExpandEntityReferences(false);
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new URL(xmlUrl).openStream());
            response.getWriter().println("XML from URL processed securely");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_8(HttpServletRequest request, HttpServletResponse response) {
        try {
            byte[] xmlBytes = request.getParameter("xml").getBytes();
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // ok: java-xml-validation
            dbf.setFeature("http://javax.xml.XMLConstants/feature/secure-processing", true);
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new ByteArrayInputStream(xmlBytes));
            response.getWriter().println("XML processed securely");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_9(HttpServletRequest request, HttpServletResponse response) {
        try {
            String xmlData = request.getParameter("xml");
            Digester digester = new Digester();
            // ok: java-xml-validation
            digester.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            digester.setFeature("http://xml.org/sax/features/external-general-entities", false);
            digester.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            Object result = digester.parse(new StringReader(xmlData));
            response.getWriter().println("XML digested securely");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_10(HttpServletRequest request, HttpServletResponse response) {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            // ok: java-xml-validation
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            DocumentBuilder db = dbf.newDocumentBuilder();
            String xml = request.getParameter("xml");
            Document doc = db.parse(new InputSource(new StringReader(xml)));
            response.getWriter().println("XML processed with namespaces securely");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_11(HttpServletRequest request, HttpServletResponse response) {
        try {
            String xml = request.getParameter("xml");
            SAXParserFactory spf = SAXParserFactory.newInstance();
            spf.setValidating(true);
            // ok: java-xml-validation
            spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            SAXParser parser = spf.newSAXParser();
            parser.parse(new InputSource(new StringReader(xml)), new DefaultHandler());
            response.getWriter().println("XML validated and parsed securely");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_12(HttpServletRequest request, HttpServletResponse response) {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setXIncludeAware(true);
            // ok: java-xml-validation
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            DocumentBuilder db = dbf.newDocumentBuilder();
            String xml = request.getParameter("xml");
            Document doc = db.parse(new InputSource(new StringReader(xml)));
            response.getWriter().println("XML processed with XInclude securely");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_13(HttpServletRequest request, HttpServletResponse response) {
        try {
            String xml = request.getParameter("xml");
            XMLInputFactory xif = XMLInputFactory.newFactory();
            // ok: java-xml-validation
            xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
            xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
            xif.setProperty(XMLInputFactory.IS_REPLAC_REDACTED_TWILIO_ID_ENTITY_REFERENCES, false);
            XMLStreamReader reader = xif.createXMLStreamReader(new StringReader(xml));
            while (reader.hasNext()) {
                reader.next();
            }
            response.getWriter().println("XML stream processed securely");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_14(HttpServletRequest request, HttpServletResponse response) {
        try {
            String xml = request.getParameter("xml");
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setExpandEntityReferences(false);
            // ok: java-xml-validation
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new InputSource(new StringReader(xml)));
            response.getWriter().println("XML processed without entity expansion");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_15(HttpServletRequest request, HttpServletResponse response) {
        try {
            String xml = request.getParameter("xml");
            TransformerFactory tf = TransformerFactory.newInstance();
            // ok: java-xml-validation
            tf.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            tf.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
            tf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            Transformer transformer = tf.newTransformer();
            StreamSource source = new StreamSource(new StringReader(xml));
            StreamResult result = new StreamResult(response.getOutputStream());
            transformer.transform(source, result);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
// {/fact}