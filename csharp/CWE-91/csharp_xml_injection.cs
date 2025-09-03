using System;
using System.IO;
using System.Net;
using System.Security;
using System.Text;
using System.Web;
using System.Xml;
using System.Xml.Linq;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace XmlInjectionExamples
{
    public class XmlInjectionSamples
    {
// {fact rule=xml-injection@v1.0 defects=1}
        // True Positive Examples (Vulnerable Code)

        public void bad_case_1(HttpContext context)
        {
            string username = context.Request.Query["username"];
            
            // Creating XML with string concatenation
            string xmlContent = "<user><name>" + username + "</name></user>";
            
            // ruleid: csharp_xml_injection
            XmlDocument doc = new XmlDocument();
            doc.LoadXml(xmlContent);
            
            // Process the XML document
            string name = doc.SelectSingleNode("//name").InnerText;
            context.Response.WriteAsync("Hello, " + name);
        }
// {/fact}
// {fact rule=xml-injection@v1.0 defects=1}

        public void bad_case_2([FromBody] UserModel model)
        {
            string userComment = model.Comment;
            
            // Creating XML with string interpolation
            string xmlData = $"<feedback><comment>{userComment}</comment></feedback>";
            
            // ruleid: csharp_xml_injection
            XDocument xdoc = XDocument.Parse(xmlData);
            
            // Save the XML to a file
            xdoc.Save("feedback.xml");
        }
// {/fact}
// {fact rule=xml-injection@v1.0 defects=1}

        public void bad_case_3(HttpContext context)
        {
            string productId = context.Request.Form["productId"];
            
            StringBuilder xmlBuilder = new StringBuilder();
            xmlBuilder.Append("<product>");
            xmlBuilder.Append("<id>");
            xmlBuilder.Append(productId);
            xmlBuilder.Append("</id>");
            xmlBuilder.Append("</product>");
            
            // ruleid: csharp_xml_injection
            XmlReader reader = XmlReader.Create(new StringReader(xmlBuilder.ToString()));
            
            while (reader.Read())
            {
                // Process the XML
            }
        }
// {/fact}
// {fact rule=xml-injection@v1.0 defects=1}

        public void bad_case_4(HttpContext context)
        {
            string searchTerm = context.Request.Query["search"];
            
            // Using string format to create XML
            string xmlQuery = string.Format("<query><term>{0}</term></query>", searchTerm);
            
            // ruleid: csharp_xml_injection
            XmlDocument doc = new XmlDocument();
            doc.InnerXml = xmlQuery;
            
            // Use the document for searching
            context.Response.WriteAsync("Search results for: " + doc.SelectSingleNode("//term").InnerText);
        }
// {/fact}
// {fact rule=xml-injection@v1.0 defects=1}

        public void bad_case_5(HttpContext context)
        {
            string categoryName = context.Request.Headers["X-Category"];
            
            XmlWriterSettings settings = new XmlWriterSettings();
            settings.Indent = true;
            
            using (MemoryStream ms = new MemoryStream())
            {
                using (XmlWriter writer = XmlWriter.Create(ms, settings))
                {
                    writer.WriteStartDocument();
                    writer.WriteStartElement("categories");
                    writer.WriteStartElement("category");
                    
                    // ruleid: csharp_xml_injection
                    writer.WriteRaw("<name>" + categoryName + "</name>");
                    
                    writer.WriteEndElement();
                    writer.WriteEndElement();
                    writer.WriteEndDocument();
                }
                
                string result = Encoding.UTF8.GetString(ms.ToArray());
                context.Response.WriteAsync(result);
            }
        }
// {/fact}
// {fact rule=xml-injection@v1.0 defects=1}

        public void bad_case_6(HttpContext context)
        {
            string userRole = context.Request.Query["role"];
            
            XmlDocument doc = new XmlDocument();
            doc.LoadXml("<users><user></user></users>");
            XmlElement userElement = (XmlElement)doc.SelectSingleNode("//user");
            
            // ruleid: csharp_xml_injection
            userElement.InnerXml = "<role>" + userRole + "</role>";
            
            // Save or process the document
            context.Response.WriteAsync(doc.OuterXml);
        }
// {/fact}
// {fact rule=xml-injection@v1.0 defects=1}

        public void bad_case_7(HttpContext context)
        {
            string tagName = context.Request.Query["tag"];
            string tagValue = context.Request.Query["value"];
            
            XDocument doc = new XDocument(new XElement("root"));
            XElement root = doc.Root;
            
            // ruleid: csharp_xml_injection
            root.Add(new XElement(tagName, tagValue));
            
            context.Response.WriteAsync(doc.ToString());
        }
// {/fact}
// {fact rule=xml-injection@v1.0 defects=1}

        public void bad_case_8(HttpContext context)
        {
            string attributeName = context.Request.Form["attrName"];
            string attributeValue = context.Request.Form["attrValue"];
            
            XmlDocument doc = new XmlDocument();
            doc.LoadXml("<item></item>");
            XmlElement element = doc.DocumentElement;
            
            // ruleid: csharp_xml_injection
            element.SetAttribute(attributeName, attributeValue);
            
            context.Response.WriteAsync(doc.OuterXml);
        }
// {/fact}
// {fact rule=xml-injection@v1.0 defects=1}

        public void bad_case_9(HttpContext context)
        {
            string xmlFragment = context.Request.Query["fragment"];
            
            XmlDocument doc = new XmlDocument();
            doc.LoadXml("<root></root>");
            
            XmlDocumentFragment fragment = doc.CreateDocumentFragment();
            // ruleid: csharp_xml_injection
            fragment.InnerXml = xmlFragment;
            
            doc.DocumentElement.AppendChild(fragment);
            context.Response.WriteAsync(doc.OuterXml);
        }
// {/fact}
// {fact rule=xml-injection@v1.0 defects=1}

        public void bad_case_10(HttpContext context)
        {
            string nodeName = context.Request.Query["node"];
            string nodeValue = context.Request.Query["value"];
            
            // Using string concatenation to build XML
            string xml = "<data><" + nodeName + ">" + nodeValue + "</" + nodeName + "></data>";
            
            // ruleid: csharp_xml_injection
            XmlDocument doc = new XmlDocument();
            doc.LoadXml(xml);
            
            context.Response.WriteAsync(doc.OuterXml);
        }
// {/fact}
// {fact rule=xml-injection@v1.0 defects=1}

        public void bad_case_11(HttpContext context)
        {
            string userInput = context.Request.Query["input"];
            
            // Creating a CDATA section with user input
            string xmlData = "<![CDATA[" + userInput + "]]>";
            
            XmlDocument doc = new XmlDocument();
            doc.LoadXml("<root></root>");
            
            // ruleid: csharp_xml_injection
            doc.DocumentElement.InnerXml = xmlData;
            
            context.Response.WriteAsync(doc.OuterXml);
        }
// {/fact}
// {fact rule=xml-injection@v1.0 defects=1}

        public void bad_case_12(HttpContext context)
        {
            string xpath = context.Request.Query["xpath"];
            
            XmlDocument doc = new XmlDocument();
            doc.Load("data.xml");
            
            // ruleid: csharp_xml_injection
            XmlNodeList nodes = doc.SelectNodes(xpath);
            
            foreach (XmlNode node in nodes)
            {
                context.Response.WriteAsync(node.OuterXml);
            }
        }
// {/fact}
// {fact rule=xml-injection@v1.0 defects=1}

        public void bad_case_13(HttpContext context)
        {
            string elementName = context.Request.Query["element"];
            
            XmlDocument doc = new XmlDocument();
            // ruleid: csharp_xml_injection
            XmlElement element = doc.CreateElement(elementName);
            
            doc.AppendChild(element);
            context.Response.WriteAsync(doc.OuterXml);
        }
// {/fact}
// {fact rule=xml-injection@v1.0 defects=1}

        public void bad_case_14(HttpContext context)
        {
            string userId = context.Request.Query["id"];
            string userName = context.Request.Query["name"];
            
            StringBuilder xmlBuilder = new StringBuilder();
            xmlBuilder.Append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
            xmlBuilder.Append("<users>");
            xmlBuilder.Append("<user>");
            xmlBuilder.Append("<id>" + userId + "</id>");
            xmlBuilder.Append("<name>" + userName + "</name>");
            xmlBuilder.Append("</user>");
            xmlBuilder.Append("</users>");
            
            // ruleid: csharp_xml_injection
            XmlDocument doc = new XmlDocument();
            doc.LoadXml(xmlBuilder.ToString());
            
            // Process the document
            context.Response.WriteAsync("User added: " + doc.SelectSingleNode("//name").InnerText);
        }
// {/fact}
// {fact rule=xml-injection@v1.0 defects=1}

        public void bad_case_15(HttpContext context)
        {
            string namespace1 = context.Request.Query["ns"];
            string localName = context.Request.Query["name"];
            
            XmlDocument doc = new XmlDocument();
            // ruleid: csharp_xml_injection
            XmlElement element = doc.CreateElement(namespace1, localName, "http://example.org");
            
            doc.AppendChild(element);
            context.Response.WriteAsync(doc.OuterXml);
        }
// {/fact}
// {fact rule=xml-injection@v1.0 defects=0}

        // True Negative Examples (Secure Code)

        public void good_case_1(HttpContext context)
        {
            string username = context.Request.Query["username"];
            
            // ok: csharp_xml_injection
            string safeUsername = SecurityElement.Escape(username);
            
            string xmlContent = "<user><name>" + safeUsername + "</name></user>";
            
            XmlDocument doc = new XmlDocument();
            doc.LoadXml(xmlContent);
            
            string name = doc.SelectSingleNode("//name").InnerText;
            context.Response.WriteAsync("Hello, " + name);
        }
// {/fact}
// {fact rule=xml-injection@v1.0 defects=0}

        public void good_case_2([FromBody] UserModel model)
        {
            string userComment = model.Comment;
            
            // ok: csharp_xml_injection
            string safeComment = SecurityElement.Escape(userComment);
            
            string xmlData = $"<feedback><comment>{safeComment}</comment></feedback>";
            
            XDocument xdoc = XDocument.Parse(xmlData);
            xdoc.Save("feedback.xml");
        }
// {/fact}
// {fact rule=xml-injection@v1.0 defects=0}

        public void good_case_3(HttpContext context)
        {
            string productId = context.Request.Form["productId"];
            
            // ok: csharp_xml_injection
            string safeProductId = SecurityElement.Escape(productId);
            
            StringBuilder xmlBuilder = new StringBuilder();
            xmlBuilder.Append("<product>");
            xmlBuilder.Append("<id>");
            xmlBuilder.Append(safeProductId);
            xmlBuilder.Append("</id>");
            xmlBuilder.Append("</product>");
            
            XmlReader reader = XmlReader.Create(new StringReader(xmlBuilder.ToString()));
            
            while (reader.Read())
            {
                // Process the XML
            }
        }
// {/fact}
// {fact rule=xml-injection@v1.0 defects=0}

        public void good_case_4(HttpContext context)
        {
            string searchTerm = context.Request.Query["search"];
            
            // ok: csharp_xml_injection
            XmlDocument doc = new XmlDocument();
            XmlElement rootElement = doc.CreateElement("query");
            doc.AppendChild(rootElement);
            
            XmlElement termElement = doc.CreateElement("term");
            termElement.InnerText = searchTerm; // Safe - InnerText automatically escapes XML
            rootElement.AppendChild(termElement);
            
            context.Response.WriteAsync("Search results for: " + doc.SelectSingleNode("//term").InnerText);
        }
// {/fact}
// {fact rule=xml-injection@v1.0 defects=0}

        public void good_case_5(HttpContext context)
        {
            string categoryName = context.Request.Headers["X-Category"];
            
            XmlWriterSettings settings = new XmlWriterSettings();
            settings.Indent = true;
            
            using (MemoryStream ms = new MemoryStream())
            {
                using (XmlWriter writer = XmlWriter.Create(ms, settings))
                {
                    writer.WriteStartDocument();
                    writer.WriteStartElement("categories");
                    writer.WriteStartElement("category");
                    
                    // ok: csharp_xml_injection
                    writer.WriteElementString("name", categoryName); // Safe - WriteElementString handles escaping
                    
                    writer.WriteEndElement();
                    writer.WriteEndElement();
                    writer.WriteEndDocument();
                }
                
                string result = Encoding.UTF8.GetString(ms.ToArray());
                context.Response.WriteAsync(result);
            }
        }
// {/fact}
// {fact rule=xml-injection@v1.0 defects=0}

        public void good_case_6(HttpContext context)
        {
            string userRole = context.Request.Query["role"];
            
            XmlDocument doc = new XmlDocument();
            doc.LoadXml("<users><user></user></users>");
            XmlElement userElement = (XmlElement)doc.SelectSingleNode("//user");
            
            // ok: csharp_xml_injection
            XmlElement roleElement = doc.CreateElement("role");
            roleElement.InnerText = userRole; // Safe - InnerText automatically escapes XML
            userElement.AppendChild(roleElement);
            
            context.Response.WriteAsync(doc.OuterXml);
        }
// {/fact}
// {fact rule=xml-injection@v1.0 defects=0}

        public void good_case_7(HttpContext context)
        {
            string tagValue = context.Request.Query["value"];
            
            // Using a fixed, known tag name instead of user input
            string tagName = "userInput";
            
            XDocument doc = new XDocument(new XElement("root"));
            XElement root = doc.Root;
            
            // ok: csharp_xml_injection
            root.Add(new XElement(tagName, tagValue)); // Safe - XElement constructor handles escaping of values
            
            context.Response.WriteAsync(doc.ToString());
        }
// {/fact}
// {fact rule=xml-injection@v1.0 defects=0}

        public void good_case_8(HttpContext context)
        {
            string attributeValue = context.Request.Form["attrValue"];
            
            // Using a fixed, known attribute name instead of user input
            string attributeName = "userAttribute";
            
            XmlDocument doc = new XmlDocument();
            doc.LoadXml("<item></item>");
            XmlElement element = doc.DocumentElement;
            
            // ok: csharp_xml_injection
            element.SetAttribute(attributeName, attributeValue); // Safe when attribute name is not from user input
            
            context.Response.WriteAsync(doc.OuterXml);
        }
// {/fact}
// {fact rule=xml-injection@v1.0 defects=0}

        public void good_case_9(HttpContext context)
        {
            string content = context.Request.Query["content"];
            
            // ok: csharp_xml_injection
            string safeContent = SecurityElement.Escape(content);
            
            XmlDocument doc = new XmlDocument();
            doc.LoadXml("<root></root>");
            
            XmlElement newElement = doc.CreateElement("userContent");
            newElement.InnerText = content; // Safe - InnerText automatically escapes XML
            doc.DocumentElement.AppendChild(newElement);
            
            context.Response.WriteAsync(doc.OuterXml);
        }
// {/fact}
// {fact rule=xml-injection@v1.0 defects=0}

        public void good_case_10(HttpContext context)
        {
            string nodeValue = context.Request.Query["value"];
            
            // Using a fixed, known node name instead of user input
            string nodeName = "data";
            
            // ok: csharp_xml_injection
            XDocument doc = new XDocument(
                new XElement("data",
                    new XElement(nodeName, nodeValue) // Safe - XElement constructor handles escaping of values
                )
            );
            
            context.Response.WriteAsync(doc.ToString());
        }
// {/fact}
// {fact rule=xml-injection@v1.0 defects=0}

        public void good_case_11(HttpContext context)
        {
            string userInput = context.Request.Query["input"];
            
            XmlDocument doc = new XmlDocument();
            doc.LoadXml("<root></root>");
            
            // ok: csharp_xml_injection
            XmlCDataSection cdata = doc.CreateCDataSection(userInput); // Safe - CDATA properly encapsulates content
            doc.DocumentElement.AppendChild(cdata);
            
            context.Response.WriteAsync(doc.OuterXml);
        }
// {/fact}
// {fact rule=xml-injection@v1.0 defects=0}

        public void good_case_12(HttpContext context)
        {
            string searchParam = context.Request.Query["search"];
            
            // ok: csharp_xml_injection
            // Using parameterized XPath query with known structure
            XmlDocument doc = new XmlDocument();
            doc.Load("data.xml");
            
            // Using a fixed XPath pattern with parameter value
            XmlNodeList nodes = doc.SelectNodes($"//user[name='{SecurityElement.Escape(searchParam)}']");
            
            foreach (XmlNode node in nodes)
            {
                context.Response.WriteAsync(node.OuterXml);
            }
        }
// {/fact}
// {fact rule=xml-injection@v1.0 defects=0}

        public void good_case_13(HttpContext context)
        {
            string elementContent = context.Request.Query["content"];
            
            // Using a fixed, known element name instead of user input
            string elementName = "userContent";
            
            XmlDocument doc = new XmlDocument();
            // ok: csharp_xml_injection
            XmlElement element = doc.CreateElement(elementName);
            element.InnerText = elementContent; // Safe - InnerText automatically escapes XML
            
            doc.AppendChild(element);
            context.Response.WriteAsync(doc.OuterXml);
        }
// {/fact}
// {fact rule=xml-injection@v1.0 defects=0}

        public void good_case_14(HttpContext context)
        {
            string userId = context.Request.Query["id"];
            string userName = context.Request.Query["name"];
            
            // ok: csharp_xml_injection
            XmlDocument doc = new XmlDocument();
            
            XmlElement rootElement = doc.CreateElement("users");
            doc.AppendChild(rootElement);
            
            XmlElement userElement = doc.CreateElement("user");
            rootElement.AppendChild(userElement);
            
            XmlElement idElement = doc.CreateElement("id");
            idElement.InnerText = userId; // Safe - InnerText automatically escapes XML
            userElement.AppendChild(idElement);
            
            XmlElement nameElement = doc.CreateElement("name");
            nameElement.InnerText = userName; // Safe - InnerText automatically escapes XML
            userElement.AppendChild(nameElement);
            
            context.Response.WriteAsync("User added: " + nameElement.InnerText);
        }
// {/fact}
// {fact rule=xml-injection@v1.0 defects=0}

        public void good_case_15(HttpContext context)
        {
            string localName = context.Request.Query["name"];
            
            // Using a fixed, known namespace instead of user input
            string namespace1 = "example";
            
            XmlDocument doc = new XmlDocument();
            // ok: csharp_xml_injection
            XmlElement element = doc.CreateElement(namespace1, "element", "http://example.org");
            element.InnerText = localName; // Safe - InnerText automatically escapes XML
            
            doc.AppendChild(element);
            context.Response.WriteAsync(doc.OuterXml);
        }
// {/fact}
    }

    public class UserModel
    {
        public string Comment { get; set; }
    }
}