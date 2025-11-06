import java.io.*;
import javax.xml.parsers.*;
import org.xml.sax.*;
import org.xml.sax.helpers.*;
import javax.xml.transform.*;
import javax.xml.transform.dom.*;
import javax.xml.transform.stream.*;
import org.w3c.dom.*;
import javax.xml.validation.*;
import javax.xml.XMLConstants;
import javax.servlet.*;
import javax.servlet.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.*;
import org.springframework.http.*;
import org.jdom2.*;
import org.jdom2.input.*;
import org.dom4j.*;
import org.dom4j.io.*;
import nu.xom.*;
import javax.xml.stream.*;
import org.apache.commons.digester3.*;
import org.apache.commons.digester3.xmlrules.*;
import org.apache.struts2.ServletActionContext;
import org.apache.xerces.parsers.SAXParser;
import org.apache.xerces.parsers.DOMParser;
import org.apache.commons.configuration.*;
import org.apache.commons.configuration.tree.xpath.*;
import org.apache.commons.jxpath.*;
import org.apache.axiom.om.*;
import org.apache.axiom.om.impl.builder.*;
import org.apache.batik.anim.dom.*;
import org.apache.batik.dom.util.*;
import org.apache.commons.betwixt.*;
import org.apache.commons.betwixt.io.*;
import org.apache.commons.digester.*;
import org.apache.commons.digester.xmlrules.*;
import org.apache.xml.security.utils.*;
import org.apache.xml.security.signature.*;
import org.apache.xml.security.c14n.*;
import org.apache.xmlbeans.*;
import org.apache.spark.sql.*;
import org.apache.spark.sql.types.*;
import org.apache.spark.sql.functions.*;
import org.apache.camel.builder.*;
import org.apache.camel.model.*;
import org.apache.camel.*;
import java.net.http.*;
import java.net.*;
import org.json.*;

// Security Issue: XML External Entity (XXE) vulnerability detection

// True Positive Examples (Vulnerable/Insecure Code)

public class XXEVulnerabilities extends HttpServlet {

// {fact rule=missing-xml-validation@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using javax.xml.parsers.DocumentBuilder without disabling external entities
        String xmlData = request.getParameter("xml");
        
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // ruleid: java-xml-validation
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.parse(new InputSource(new StringReader(xmlData)));
        
        // Process the document
        Element root = doc.getDocumentElement();
        response.getWriter().println("Processed XML with root: " + root.getNodeName());
    }
    
    public void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using SAXParser without disabling external entities
        String xmlData = request.getParameter("xml");
        
        SAXParserFactory factory = SAXParserFactory.newInstance();
        // ruleid: java-xml-validation
        SAXParser saxParser = factory.newSAXParser();
        DefaultHandler handler = new DefaultHandler();
        saxParser.parse(new InputSource(new StringReader(xmlData)), handler);
        
        response.getWriter().println("XML processed successfully");
    }
    
    public void bad_case_3(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using JDOM2 SAXBuilder without disabling external entities
        String xmlData = request.getParameter("xml");
        
        // ruleid: java-xml-validation
        SAXBuilder saxBuilder = new SAXBuilder();
        org.jdom2.Document document = saxBuilder.build(new StringReader(xmlData));
        
        response.getWriter().println("Root element: " + document.getRootElement().getName());
    }
    
    public void bad_case_4(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using DOM4J SAXReader without disabling external entities
        String xmlData = request.getParameter("xml");
        
        // ruleid: java-xml-validation
        SAXReader saxReader = new SAXReader();
        org.dom4j.Document document = saxReader.read(new StringReader(xmlData));
        
        response.getWriter().println("Root element: " + document.getRootElement().getName());
    }
    
    public void bad_case_5(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using XMLReader without disabling external entities
        String xmlData = request.getParameter("xml");
        
        // ruleid: java-xml-validation
        XMLReader reader = XMLReaderFactory.createXMLReader();
        InputSource source = new InputSource(new StringReader(xmlData));
        reader.parse(source);
        
        response.getWriter().println("XML processed successfully");
    }
    
    public void bad_case_6(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using XOM Builder without disabling external entities
        String xmlData = request.getParameter("xml");
        
        // ruleid: java-xml-validation
        Builder builder = new Builder();
        nu.xom.Document doc = builder.build(new StringReader(xmlData));
        
        response.getWriter().println("Root element: " + doc.getRootElement().getLocalName());
    }
    
    public void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using XMLStreamReader without disabling external entities
        String xmlData = request.getParameter("xml");
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ruleid: java-xml-validation
        XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlData));
        
        while(reader.hasNext()) {
            reader.next();
        }
        response.getWriter().println("XML processed successfully");
    }
    
    public void bad_case_8(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using Apache Digester without disabling external entities
        String xmlData = request.getParameter("xml");
        
        // ruleid: java-xml-validation
        Digester digester = new Digester();
        Object result = digester.parse(new StringReader(xmlData));
        
        response.getWriter().println("XML processed successfully");
    }
    
    public void bad_case_9(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using Xerces DOMParser without disabling external entities
        String xmlData = request.getParameter("xml");
        
        // ruleid: java-xml-validation
        DOMParser parser = new DOMParser();
        parser.parse(new InputSource(new StringReader(xmlData)));
        org.w3c.dom.Document document = parser.getDocument();
        
        response.getWriter().println("Root element: " + document.getDocumentElement().getNodeName());
    }
    
    public void bad_case_10(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using Apache Commons Configuration XMLConfiguration without disabling external entities
        String xmlData = request.getParameter("xml");
        
        // ruleid: java-xml-validation
        XMLConfiguration config = new XMLConfiguration();
        config.load(new StringReader(xmlData));
        
        String value = config.getString("property[@name='test']");
        response.getWriter().println("Property value: " + value);
    }
    
    public void bad_case_11(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using Apache Axiom OMXMLBuilderFactory without disabling external entities
        String xmlData = request.getParameter("xml");
        
        // ruleid: java-xml-validation
        OMXMLParserWrapper builder = OMXMLBuilderFactory.createOMBuilder(new StringReader(xmlData));
        OMElement documentElement = builder.getDocumentElement();
        
        response.getWriter().println("Root element: " + documentElement.getLocalName());
    }
    
    public void bad_case_12(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using Apache Batik DOM Parser without disabling external entities
        String xmlData = request.getParameter("xml");
        
        // ruleid: java-xml-validation
        SAXDocumentFactory factory = new SAXDocumentFactory(new GenericDOMImplementation(), "http://www.w3.org/TR/REC-xml");
        org.w3c.dom.Document document = factory.createDocument("http://example.org", "root", new InputSource(new StringReader(xmlData)));
        
        response.getWriter().println("Root element: " + document.getDocumentElement().getNodeName());
    }
    
    public void bad_case_13(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using Apache Commons Betwixt without disabling external entities
        String xmlData = request.getParameter("xml");
        
        // ruleid: java-xml-validation
        BeanReader beanReader = new BeanReader();
        beanReader.registerBeanClass("root", Object.class);
        Object result = beanReader.parse(new StringReader(xmlData));
        
        response.getWriter().println("Bean created successfully");
    }
    
    public void bad_case_14(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using Apache XML Security without disabling external entities
        String xmlData = request.getParameter("xml");
        
        // ruleid: java-xml-validation
        DocumentBuilderFactory dfactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder documentBuilder = dfactory.newDocumentBuilder();
        Document doc = documentBuilder.parse(new InputSource(new StringReader(xmlData)));
        
        XMLSignature signature = new XMLSignature(doc, "");
        response.getWriter().println("Signature processed");
    }
    
    public void bad_case_15(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using Apache XMLBeans without disabling external entities
        String xmlData = request.getParameter("xml");
        
        // ruleid: java-xml-validation
        XmlObject xmlObject = XmlObject.Factory.parse(xmlData);
        
        response.getWriter().println("XML processed successfully");
    }
    
    // True Negative Examples (Safe/Secure Code)
    
    public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using javax.xml.parsers.DocumentBuilder with external entities disabled
        String xmlData = request.getParameter("xml");
        
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        // ok: java-xml-validation
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.parse(new InputSource(new StringReader(xmlData)));
        
        // Process the document
        Element root = doc.getDocumentElement();
        response.getWriter().println("Processed XML with root: " + root.getNodeName());
    }
    
    public void good_case_2(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using SAXParser with external entities disabled
        String xmlData = request.getParameter("xml");
        
        SAXParserFactory factory = SAXParserFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setXIncludeAware(false);
        // ok: java-xml-validation
        SAXParser saxParser = factory.newSAXParser();
        DefaultHandler handler = new DefaultHandler();
        saxParser.parse(new InputSource(new StringReader(xmlData)), handler);
        
        response.getWriter().println("XML processed successfully");
    }
    
    public void good_case_3(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using JDOM2 SAXBuilder with external entities disabled
        String xmlData = request.getParameter("xml");
        
        SAXBuilder saxBuilder = new SAXBuilder();
        saxBuilder.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        saxBuilder.setFeature("http://xml.org/sax/features/external-general-entities", false);
        saxBuilder.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        saxBuilder.setExpandEntities(false);
        // ok: java-xml-validation
        org.jdom2.Document document = saxBuilder.build(new StringReader(xmlData));
        
        response.getWriter().println("Root element: " + document.getRootElement().getName());
    }
    
    public void good_case_4(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using DOM4J SAXReader with external entities disabled
        String xmlData = request.getParameter("xml");
        
        SAXReader saxReader = new SAXReader();
        saxReader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        saxReader.setFeature("http://xml.org/sax/features/external-general-entities", false);
        saxReader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        // ok: java-xml-validation
        org.dom4j.Document document = saxReader.read(new StringReader(xmlData));
        
        response.getWriter().println("Root element: " + document.getRootElement().getName());
    }
    
    public void good_case_5(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using XMLReader with external entities disabled
        String xmlData = request.getParameter("xml");
        
        XMLReader reader = XMLReaderFactory.createXMLReader();
        reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
        reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        // ok: java-xml-validation
        InputSource source = new InputSource(new StringReader(xmlData));
        reader.parse(source);
        
        response.getWriter().println("XML processed successfully");
    }
    
    public void good_case_6(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using XOM Builder with external entities disabled
        String xmlData = request.getParameter("xml");
        
        XMLReader xmlReader = XMLReaderFactory.createXMLReader();
        xmlReader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        xmlReader.setFeature("http://xml.org/sax/features/external-general-entities", false);
        xmlReader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        // ok: java-xml-validation
        Builder builder = new Builder(xmlReader);
        nu.xom.Document doc = builder.build(new StringReader(xmlData));
        
        response.getWriter().println("Root element: " + doc.getRootElement().getLocalName());
    }
    
    public void good_case_7(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using XMLStreamReader with external entities disabled
        String xmlData = request.getParameter("xml");
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        // ok: java-xml-validation
        XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlData));
        
        while(reader.hasNext()) {
            reader.next();
        }
        response.getWriter().println("XML processed successfully");
    }
    
    public void good_case_8(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using Apache Digester with external entities disabled
        String xmlData = request.getParameter("xml");
        
        Digester digester = new Digester();
        digester.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        digester.setFeature("http://xml.org/sax/features/external-general-entities", false);
        digester.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        // ok: java-xml-validation
        Object result = digester.parse(new StringReader(xmlData));
        
        response.getWriter().println("XML processed successfully");
    }
    
    public void good_case_9(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using Xerces DOMParser with external entities disabled
        String xmlData = request.getParameter("xml");
        
        DOMParser parser = new DOMParser();
        parser.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        parser.setFeature("http://xml.org/sax/features/external-general-entities", false);
        parser.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        // ok: java-xml-validation
        parser.parse(new InputSource(new StringReader(xmlData)));
        org.w3c.dom.Document document = parser.getDocument();
        
        response.getWriter().println("Root element: " + document.getDocumentElement().getNodeName());
    }
    
    public void good_case_10(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using Apache Commons Configuration XMLConfiguration with secure processing
        String xmlData = request.getParameter("xml");
        
        XMLConfiguration config = new XMLConfiguration();
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(new InputSource(new StringReader(xmlData)));
        // ok: java-xml-validation
        config.load(new DOMSource(document));
        
        String value = config.getString("property[@name='test']");
        response.getWriter().println("Property value: " + value);
    }
    
    public void good_case_11(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using Apache Axiom with secure processing
        String xmlData = request.getParameter("xml");
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        // ok: java-xml-validation
        StAXOMBuilder builder = new StAXOMBuilder(factory.createXMLStreamReader(new StringReader(xmlData)));
        OMElement documentElement = builder.getDocumentElement();
        
        response.getWriter().println("Root element: " + documentElement.getLocalName());
    }
    
    public void good_case_12(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using Apache Batik DOM Parser with secure processing
        String xmlData = request.getParameter("xml");
        
        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        SAXParser parser = spf.newSAXParser();
        XMLReader xmlReader = parser.getXMLReader();
        
        // ok: java-xml-validation
        SAXDocumentFactory factory = new SAXDocumentFactory(new GenericDOMImplementation(), "http://www.w3.org/TR/REC-xml", xmlReader);
        org.w3c.dom.Document document = factory.createDocument("http://example.org", "root", new InputSource(new StringReader(xmlData)));
        
        response.getWriter().println("Root element: " + document.getDocumentElement().getNodeName());
    }
    
    public void good_case_13(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using Apache Commons Betwixt with secure processing
        String xmlData = request.getParameter("xml");
        
        BeanReader beanReader = new BeanReader();
        beanReader.registerBeanClass("root", Object.class);
        
        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        SAXParser parser = spf.newSAXParser();
        XMLReader xmlReader = parser.getXMLReader();
        beanReader.setXMLReader(xmlReader);
        
        // ok: java-xml-validation
        Object result = beanReader.parse(new StringReader(xmlData));
        
        response.getWriter().println("Bean created successfully");
    }
    
    public void good_case_14(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using Apache XML Security with secure processing
        String xmlData = request.getParameter("xml");
        
        DocumentBuilderFactory dfactory = DocumentBuilderFactory.newInstance();
        dfactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dfactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dfactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dfactory.setXIncludeAware(false);
        dfactory.setExpandEntityReferences(false);
        DocumentBuilder documentBuilder = dfactory.newDocumentBuilder();
        // ok: java-xml-validation
        Document doc = documentBuilder.parse(new InputSource(new StringReader(xmlData)));
        
        XMLSignature signature = new XMLSignature(doc, "");
        response.getWriter().println("Signature processed");
    }
    
    public void good_case_15(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using Apache XMLBeans with secure processing
        String xmlData = request.getParameter("xml");
        
        XmlOptions options = new XmlOptions();
        options.setLoadReplaceDocumentElement(null);
        options.setLoadDisallowDocTypeDeclaration(true);
        // ok: java-xml-validation
        XmlObject xmlObject = XmlObject.Factory.parse(xmlData, options);
        
        response.getWriter().println("XML processed successfully");
    }
}
// {/fact}