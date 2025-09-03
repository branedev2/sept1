import com.google.gwt.core.client.EntryPoint;
import com.google.gwt.dom.client.Document;
import com.google.gwt.dom.client.Element;
import com.google.gwt.http.client.Request;
import com.google.gwt.http.client.RequestBuilder;
import com.google.gwt.http.client.RequestCallback;
import com.google.gwt.http.client.Response;
import com.google.gwt.http.client.URL;
import com.google.gwt.safehtml.shared.SafeHtml;
import com.google.gwt.safehtml.shared.SafeHtmlBuilder;
import com.google.gwt.safehtml.shared.SafeHtmlUtils;
import com.google.gwt.safehtml.shared.UriUtils;
import com.google.gwt.user.client.Window;
import com.google.gwt.user.client.ui.*;
import com.google.gwt.event.dom.client.ClickEvent;
import com.google.gwt.event.dom.client.ClickHandler;
import com.google.gwt.user.client.rpc.AsyncCallback;
import com.google.gwt.user.client.ui.HTML;
import com.google.gwt.user.client.ui.RootPanel;
import com.google.gwt.user.client.ui.TextBox;
import com.google.gwt.xhr.client.XMLHttpRequest;
import com.google.gwt.http.client.UrlBuilder;
import com.google.gwt.user.client.ui.Anchor;
import com.google.gwt.user.client.ui.Label;
import com.google.gwt.user.client.ui.Button;
import com.google.gwt.user.client.ui.DialogBox;
import com.google.gwt.user.client.ui.VerticalPanel;
import com.google.gwt.user.client.ui.HorizontalPanel;
import com.google.gwt.user.client.ui.FlexTable;
import com.google.gwt.user.client.ui.RichTextArea;
import java.util.HashMap;
import java.util.Map;

// Security Issue: Cross-Site Scripting (XSS) in Google Web Toolkit (GWT) applications

// True Positive Examples (Vulnerable/Insecure Code)
public class GWTXSSVulnerabilities implements EntryPoint {
    
    public void onModuleLoad() {
        // Examples will be called here
    }
    
    // Using HTML widget with unsanitized user input
    private void bad_case_1() {
        RequestBuilder builder = new RequestBuilder(RequestBuilder.GET, "/api/userProfile");
        try {
            builder.sendRequest(null, new RequestCallback() {
                public void onResponseReceived(Request request, Response response) {
                    String userInput = response.getText();
                    // ruleid: java-cross-site-scripting-gwt
                    HTML userProfileHtml = new HTML("<div>Welcome, " + userInput + "!</div>");
                    RootPanel.get("userGreeting").add(userProfileHtml);
                }
                
                public void onError(Request request, Throwable exception) {
                    Window.alert("Error fetching user profile");
                }
            });
        } catch (Exception e) {
            Window.alert("Error: " + e.getMessage());
        }
    }
    
    // Using setHTML method with unsanitized user input
    private void bad_case_2() {
        final Label statusLabel = new Label();
        RequestBuilder builder = new RequestBuilder(RequestBuilder.GET, "/api/status");
        try {
            builder.sendRequest(null, new RequestCallback() {
                public void onResponseReceived(Request request, Response response) {
                    String statusMessage = response.getText();
                    // ruleid: java-cross-site-scripting-gwt
                    RootPanel.get("statusContainer").getElement().setInnerHTML("Status: " + statusMessage);
                }
                
                public void onError(Request request, Throwable exception) {
                    statusLabel.setText("Failed to load status");
                }
            });
        } catch (Exception e) {
            statusLabel.setText("Error: " + e.getMessage());
        }
    }
    
    // Using DOM API to set innerHTML with unsanitized user input
    private void bad_case_3() {
        XMLHttpRequest xhr = XMLHttpRequest.create();
        xhr.open("GET", "/api/notifications");
        xhr.setOnReadyStateChange(event -> {
            if (xhr.getReadyState() == XMLHttpRequest.DONE) {
                if (xhr.getStatus() == 200) {
                    String notificationData = xhr.getResponseText();
                    Element notificationElement = Document.get().getElementById("notificationArea");
                    // ruleid: java-cross-site-scripting-gwt
                    notificationElement.setInnerHTML("Latest notification: " + notificationData);
                }
            }
        });
        xhr.send();
    }
    
    // Using direct string concatenation in Anchor widget
    private void bad_case_4() {
        final TextBox searchBox = new TextBox();
        Button searchButton = new Button("Search");
        
        searchButton.addClickHandler(new ClickHandler() {
            @Override
            public void onClick(ClickEvent event) {
                String searchQuery = searchBox.getText();
                
                RequestBuilder builder = new RequestBuilder(RequestBuilder.GET, "/api/search?q=" + URL.encode(searchQuery));
                try {
                    builder.sendRequest(null, new RequestCallback() {
                        public void onResponseReceived(Request request, Response response) {
                            String searchResult = response.getText();
                            // ruleid: java-cross-site-scripting-gwt
                            HTML resultDisplay = new HTML("Results for: " + searchQuery + "<br/>" + searchResult);
                            RootPanel.get("searchResults").add(resultDisplay);
                        }
                        
                        public void onError(Request request, Throwable exception) {
                            Window.alert("Search failed");
                        }
                    });
                } catch (Exception e) {
                    Window.alert("Error: " + e.getMessage());
                }
            }
        });
    }
    
    // Using FlexTable with unsanitized user input
    private void bad_case_5() {
        final FlexTable userTable = new FlexTable();
        RequestBuilder builder = new RequestBuilder(RequestBuilder.GET, "/api/users");
        try {
            builder.sendRequest(null, new RequestCallback() {
                public void onResponseReceived(Request request, Response response) {
                    String userData = response.getText();
                    // Assume userData is JSON that we've parsed to get user info
                    String userName = userData; // Simplified for example
                    
                    userTable.setText(0, 0, "User");
                    // ruleid: java-cross-site-scripting-gwt
                    userTable.setHTML(0, 1, userName);
                    RootPanel.get("userTableContainer").add(userTable);
                }
                
                public void onError(Request request, Throwable exception) {
                    Window.alert("Failed to load user data");
                }
            });
        } catch (Exception e) {
            Window.alert("Error: " + e.getMessage());
        }
    }
    
    // Using direct DOM manipulation with unsanitized user input
    private void bad_case_6() {
        RequestBuilder builder = new RequestBuilder(RequestBuilder.GET, "/api/comments");
        try {
            builder.sendRequest(null, new RequestCallback() {
                public void onResponseReceived(Request request, Response response) {
                    String commentText = response.getText();
                    Element commentSection = Document.get().getElementById("commentSection");
                    // ruleid: java-cross-site-scripting-gwt
                    commentSection.setInnerHTML(commentText);
                }
                
                public void onError(Request request, Throwable exception) {
                    Window.alert("Failed to load comments");
                }
            });
        } catch (Exception e) {
            Window.alert("Error: " + e.getMessage());
        }
    }
    
    // Using DialogBox with unsanitized user input
    private void bad_case_7() {
        RequestBuilder builder = new RequestBuilder(RequestBuilder.GET, "/api/message");
        try {
            builder.sendRequest(null, new RequestCallback() {
                public void onResponseReceived(Request request, Response response) {
                    String message = response.getText();
                    DialogBox dialogBox = new DialogBox();
                    dialogBox.setText("Important Message");
                    
                    VerticalPanel dialogContent = new VerticalPanel();
                    // ruleid: java-cross-site-scripting-gwt
                    HTML messageHtml = new HTML(message);
                    dialogContent.add(messageHtml);
                    
                    Button closeButton = new Button("Close");
                    closeButton.addClickHandler(event -> dialogBox.hide());
                    dialogContent.add(closeButton);
                    
                    dialogBox.setWidget(dialogContent);
                    dialogBox.center();
                    dialogBox.show();
                }
                
                public void onError(Request request, Throwable exception) {
                    Window.alert("Failed to load message");
                }
            });
        } catch (Exception e) {
            Window.alert("Error: " + e.getMessage());
        }
    }
    
    // Using RichTextArea with unsanitized user input
    private void bad_case_8() {
        final RichTextArea richTextArea = new RichTextArea();
        RequestBuilder builder = new RequestBuilder(RequestBuilder.GET, "/api/content");
        try {
            builder.sendRequest(null, new RequestCallback() {
                public void onResponseReceived(Request request, Response response) {
                    String content = response.getText();
                    // ruleid: java-cross-site-scripting-gwt
                    richTextArea.setHTML(content);
                    RootPanel.get("editorContainer").add(richTextArea);
                }
                
                public void onError(Request request, Throwable exception) {
                    Window.alert("Failed to load content");
                }
            });
        } catch (Exception e) {
            Window.alert("Error: " + e.getMessage());
        }
    }
    
    // Using Anchor widget with unsanitized user input
    private void bad_case_9() {
        RequestBuilder builder = new RequestBuilder(RequestBuilder.GET, "/api/profile");
        try {
            builder.sendRequest(null, new RequestCallback() {
                public void onResponseReceived(Request request, Response response) {
                    String profileUrl = response.getText();
                    // ruleid: java-cross-site-scripting-gwt
                    Anchor profileLink = new Anchor("View Profile", profileUrl);
                    profileLink.setHTML("View <b>Profile</b> for " + profileUrl);
                    RootPanel.get("profileLinkContainer").add(profileLink);
                }
                
                public void onError(Request request, Throwable exception) {
                    Window.alert("Failed to load profile");
                }
            });
        } catch (Exception e) {
            Window.alert("Error: " + e.getMessage());
        }
    }
    
    // Using setTitle with unsanitized user input
    private void bad_case_10() {
        RequestBuilder builder = new RequestBuilder(RequestBuilder.GET, "/api/tooltip");
        try {
            builder.sendRequest(null, new RequestCallback() {
                public void onResponseReceived(Request request, Response response) {
                    String tooltipText = response.getText();
                    Button infoButton = new Button("Info");
                    // ruleid: java-cross-site-scripting-gwt
                    infoButton.getElement().setAttribute("title", tooltipText);
                    RootPanel.get("tooltipContainer").add(infoButton);
                }
                
                public void onError(Request request, Throwable exception) {
                    Window.alert("Failed to load tooltip");
                }
            });
        } catch (Exception e) {
            Window.alert("Error: " + e.getMessage());
        }
    }
    
    // Using JavaScript native method with unsanitized user input
    private void bad_case_11() {
        RequestBuilder builder = new RequestBuilder(RequestBuilder.GET, "/api/script");
        try {
            builder.sendRequest(null, new RequestCallback() {
                public void onResponseReceived(Request request, Response response) {
                    String scriptContent = response.getText();
                    // ruleid: java-cross-site-scripting-gwt
                    executeJavaScript("document.getElementById('scriptOutput').innerHTML = '" + scriptContent + "';");
                }
                
                public void onError(Request request, Throwable exception) {
                    Window.alert("Failed to load script");
                }
            });
        } catch (Exception e) {
            Window.alert("Error: " + e.getMessage());
        }
    }
    
    private native void executeJavaScript(String js) /*-{
        eval(js);
    }-*/;
    
    // Using FormPanel with unsanitized user input
    private void bad_case_12() {
        RequestBuilder builder = new RequestBuilder(RequestBuilder.GET, "/api/formData");
        try {
            builder.sendRequest(null, new RequestCallback() {
                public void onResponseReceived(Request request, Response response) {
                    String formTitle = response.getText();
                    FormPanel form = new FormPanel();
                    VerticalPanel panel = new VerticalPanel();
                    form.setWidget(panel);
                    
                    // ruleid: java-cross-site-scripting-gwt
                    HTML formHeader = new HTML("<h2>" + formTitle + "</h2>");
                    panel.add(formHeader);
                    
                    TextBox nameBox = new TextBox();
                    panel.add(new HTML("Name:"));
                    panel.add(nameBox);
                    
                    Button submitButton = new Button("Submit");
                    panel.add(submitButton);
                    
                    RootPanel.get("formContainer").add(form);
                }
                
                public void onError(Request request, Throwable exception) {
                    Window.alert("Failed to load form data");
                }
            });
        } catch (Exception e) {
            Window.alert("Error: " + e.getMessage());
        }
    }
    
    // Using direct string concatenation with URL parameters
    private void bad_case_13() {
        Map<String, String> params = Window.Location.getParameterMap();
        String username = params.get("username");
        
        if (username != null) {
            // ruleid: java-cross-site-scripting-gwt
            HTML welcomeMessage = new HTML("<div>Welcome back, " + username + "!</div>");
            RootPanel.get("welcomeContainer").add(welcomeMessage);
        }
    }
    
    // Using innerHTML with query parameters
    private void bad_case_14() {
        String searchTerm = Window.Location.getParameter("q");
        
        if (searchTerm != null && !searchTerm.isEmpty()) {
            Element searchResultElement = Document.get().getElementById("searchResults");
            // ruleid: java-cross-site-scripting-gwt
            searchResultElement.setInnerHTML("Search results for: " + searchTerm);
            
            // Perform search...
        }
    }
    
    // Using unsanitized header values from HTTP request
    private void bad_case_15() {
        RequestBuilder builder = new RequestBuilder(RequestBuilder.GET, "/api/headers");
        try {
            builder.sendRequest(null, new RequestCallback() {
                public void onResponseReceived(Request request, Response response) {
                    String userAgent = response.getHeader("User-Agent");
                    // ruleid: java-cross-site-scripting-gwt
                    HTML headerInfo = new HTML("<div>Your browser: " + userAgent + "</div>");
                    RootPanel.get("browserInfo").add(headerInfo);
                }
                
                public void onError(Request request, Throwable exception) {
                    Window.alert("Failed to get headers");
                }
            });
        } catch (Exception e) {
            Window.alert("Error: " + e.getMessage());
        }
    }
    
    // True Negative Examples (Safe/Secure Code)
    
    // Using SafeHtmlUtils.fromString() for HTML widget
    private void good_case_1() {
        RequestBuilder builder = new RequestBuilder(RequestBuilder.GET, "/api/userProfile");
        try {
            builder.sendRequest(null, new RequestCallback() {
                public void onResponseReceived(Request request, Response response) {
                    String userInput = response.getText();
                    // ok: java-cross-site-scripting-gwt
                    HTML userProfileHtml = new HTML(SafeHtmlUtils.fromString("Welcome, " + userInput + "!").asString());
                    RootPanel.get("userGreeting").add(userProfileHtml);
                }
                
                public void onError(Request request, Throwable exception) {
                    Window.alert("Error fetching user profile");
                }
            });
        } catch (Exception e) {
            Window.alert("Error: " + e.getMessage());
        }
    }
    
    // Using SafeHtml for setHTML
    private void good_case_2() {
        final Label statusLabel = new Label();
        RequestBuilder builder = new RequestBuilder(RequestBuilder.GET, "/api/status");
        try {
            builder.sendRequest(null, new RequestCallback() {
                public void onResponseReceived(Request request, Response response) {
                    String statusMessage = response.getText();
                    SafeHtml safeStatus = SafeHtmlUtils.fromString("Status: " + statusMessage);
                    // ok: java-cross-site-scripting-gwt
                    RootPanel.get("statusContainer").getElement().setInnerHTML(safeStatus.asString());
                }
                
                public void onError(Request request, Throwable exception) {
                    statusLabel.setText("Failed to load status");
                }
            });
        } catch (Exception e) {
            statusLabel.setText("Error: " + e.getMessage());
        }
    }
    
    // Using SafeHtmlBuilder for DOM API
    private void good_case_3() {
        XMLHttpRequest xhr = XMLHttpRequest.create();
        xhr.open("GET", "/api/notifications");
        xhr.setOnReadyStateChange(event -> {
            if (xhr.getReadyState() == XMLHttpRequest.DONE) {
                if (xhr.getStatus() == 200) {
                    String notificationData = xhr.getResponseText();
                    Element notificationElement = Document.get().getElementById("notificationArea");
                    SafeHtmlBuilder builder = new SafeHtmlBuilder();
                    builder.appendEscaped("Latest notification: ");
                    builder.appendEscaped(notificationData);
                    // ok: java-cross-site-scripting-gwt
                    notificationElement.setInnerHTML(builder.toSafeHtml().asString());
                }
            }
        });
        xhr.send();
    }
    
    // Using SafeHtmlUtils for search results
    private void good_case_4() {
        final TextBox searchBox = new TextBox();
        Button searchButton = new Button("Search");
        
        searchButton.addClickHandler(new ClickHandler() {
            @Override
            public void onClick(ClickEvent event) {
                String searchQuery = searchBox.getText();
                
                RequestBuilder builder = new RequestBuilder(RequestBuilder.GET, "/api/search?q=" + URL.encode(searchQuery));
                try {
                    builder.sendRequest(null, new RequestCallback() {
                        public void onResponseReceived(Request request, Response response) {
                            String searchResult = response.getText();
                            SafeHtmlBuilder htmlBuilder = new SafeHtmlBuilder();
                            htmlBuilder.appendEscaped("Results for: " + searchQuery);
                            htmlBuilder.appendHtmlConstant("<br/>");
                            htmlBuilder.appendEscaped(searchResult);
                            // ok: java-cross-site-scripting-gwt
                            HTML resultDisplay = new HTML(htmlBuilder.toSafeHtml());
                            RootPanel.get("searchResults").add(resultDisplay);
                        }
                        
                        public void onError(Request request, Throwable exception) {
                            Window.alert("Search failed");
                        }
                    });
                } catch (Exception e) {
                    Window.alert("Error: " + e.getMessage());
                }
            }
        });
    }
    
    // Using setText instead of setHTML for FlexTable
    private void good_case_5() {
        final FlexTable userTable = new FlexTable();
        RequestBuilder builder = new RequestBuilder(RequestBuilder.GET, "/api/users");
        try {
            builder.sendRequest(null, new RequestCallback() {
                public void onResponseReceived(Request request, Response response) {
                    String userData = response.getText();
                    // Assume userData is JSON that we've parsed to get user info
                    String userName = userData; // Simplified for example
                    
                    userTable.setText(0, 0, "User");
                    // ok: java-cross-site-scripting-gwt
                    userTable.setText(0, 1, userName);
                    RootPanel.get("userTableContainer").add(userTable);
                }
                
                public void onError(Request request, Throwable exception) {
                    Window.alert("Failed to load user data");
                }
            });
        } catch (Exception e) {
            Window.alert("Error: " + e.getMessage());
        }
    }
    
    // Using SafeHtmlUtils for DOM manipulation
    private void good_case_6() {
        RequestBuilder builder = new RequestBuilder(RequestBuilder.GET, "/api/comments");
        try {
            builder.sendRequest(null, new RequestCallback() {
                public void onResponseReceived(Request request, Response response) {
                    String commentText = response.getText();
                    Element commentSection = Document.get().getElementById("commentSection");
                    // ok: java-cross-site-scripting-gwt
                    commentSection.setInnerHTML(SafeHtmlUtils.fromString(commentText).asString());
                }
                
                public void onError(Request request, Throwable exception) {
                    Window.alert("Failed to load comments");
                }
            });
        } catch (Exception e) {
            Window.alert("Error: " + e.getMessage());
        }
    }
    
    // Using SafeHtml for DialogBox
    private void good_case_7() {
        RequestBuilder builder = new RequestBuilder(RequestBuilder.GET, "/api/message");
        try {
            builder.sendRequest(null, new RequestCallback() {
                public void onResponseReceived(Request request, Response response) {
                    String message = response.getText();
                    DialogBox dialogBox = new DialogBox();
                    dialogBox.setText("Important Message");
                    
                    VerticalPanel dialogContent = new VerticalPanel();
                    // ok: java-cross-site-scripting-gwt
                    HTML messageHtml = new HTML(SafeHtmlUtils.fromString(message));
                    dialogContent.add(messageHtml);
                    
                    Button closeButton = new Button("Close");
                    closeButton.addClickHandler(event -> dialogBox.hide());
                    dialogContent.add(closeButton);
                    
                    dialogBox.setWidget(dialogContent);
                    dialogBox.center();
                    dialogBox.show();
                }
                
                public void onError(Request request, Throwable exception) {
                    Window.alert("Failed to load message");
                }
            });
        } catch (Exception e) {
            Window.alert("Error: " + e.getMessage());
        }
    }
    
    // Using SafeHtml for RichTextArea
    private void good_case_8() {
        final RichTextArea richTextArea = new RichTextArea();
        RequestBuilder builder = new RequestBuilder(RequestBuilder.GET, "/api/content");
        try {
            builder.sendRequest(null, new RequestCallback() {
                public void onResponseReceived(Request request, Response response) {
                    String content = response.getText();
                    // ok: java-cross-site-scripting-gwt
                    richTextArea.setHTML(SafeHtmlUtils.fromString(content).asString());
                    RootPanel.get("editorContainer").add(richTextArea);
                }
                
                public void onError(Request request, Throwable exception) {
                    Window.alert("Failed to load content");
                }
            });
        } catch (Exception e) {
            Window.alert("Error: " + e.getMessage());
        }
    }
    
    // Using UriUtils for Anchor widget
    private void good_case_9() {
        RequestBuilder builder = new RequestBuilder(RequestBuilder.GET, "/api/profile");
        try {
            builder.sendRequest(null, new RequestCallback() {
                public void onResponseReceived(Request request, Response response) {
                    String profileUrl = response.getText();
                    String safeUrl = UriUtils.sanitizeUri(profileUrl);
                    Anchor profileLink = new Anchor("View Profile", safeUrl);
                    
                    SafeHtmlBuilder htmlBuilder = new SafeHtmlBuilder();
                    htmlBuilder.appendHtmlConstant("View <b>Profile</b> for ");
                    htmlBuilder.appendEscaped(profileUrl);
                    // ok: java-cross-site-scripting-gwt
                    profileLink.setHTML(htmlBuilder.toSafeHtml());
                    
                    RootPanel.get("profileLinkContainer").add(profileLink);
                }
                
                public void onError(Request request, Throwable exception) {
                    Window.alert("Failed to load profile");
                }
            });
        } catch (Exception e) {
            Window.alert("Error: " + e.getMessage());
        }
    }
    
    // Using SafeHtmlUtils for title attribute
    private void good_case_10() {
        RequestBuilder builder = new RequestBuilder(RequestBuilder.GET, "/api/tooltip");
        try {
            builder.sendRequest(null, new RequestCallback() {
                public void onResponseReceived(Request request, Response response) {
                    String tooltipText = response.getText();
                    Button infoButton = new Button("Info");
                    // ok: java-cross-site-scripting-gwt
                    infoButton.getElement().setAttribute("title", SafeHtmlUtils.htmlEscape(tooltipText));
                    RootPanel.get("tooltipContainer").add(infoButton);
                }
                
                public void onError(Request request, Throwable exception) {
                    Window.alert("Failed to load tooltip");
                }
            });
        } catch (Exception e) {
            Window.alert("Error: " + e.getMessage());
        }
    }
    
    // Using SafeHtmlUtils for JavaScript execution
    private void good_case_11() {
        RequestBuilder builder = new RequestBuilder(RequestBuilder.GET, "/api/script");
        try {
            builder.sendRequest(null, new RequestCallback() {
                public void onResponseReceived(Request request, Response response) {
                    String scriptContent = response.getText();
                    String escapedContent = SafeHtmlUtils.htmlEscape(scriptContent);
                    // ok: java-cross-site-scripting-gwt
                    executeJavaScriptSafely("document.getElementById('scriptOutput').textContent = '" + escapedContent + "';");
                }
                
                public void onError(Request request, Throwable exception) {
                    Window.alert("Failed to load script");
                }
            });
        } catch (Exception e) {
            Window.alert("Error: " + e.getMessage());
        }
    }
    
    private native void executeJavaScriptSafely(String js) /*-{
        eval(js);
    }-*/;
    
    // Using SafeHtmlBuilder for FormPanel
    private void good_case_12() {
        RequestBuilder builder = new RequestBuilder(RequestBuilder.GET, "/api/formData");
        try {
            builder.sendRequest(null, new RequestCallback() {
                public void onResponseReceived(Request request, Response response) {
                    String formTitle = response.getText();
                    FormPanel form = new FormPanel();
                    VerticalPanel panel = new VerticalPanel();
                    form.setWidget(panel);
                    
                    SafeHtmlBuilder htmlBuilder = new SafeHtmlBuilder();
                    htmlBuilder.appendHtmlConstant("<h2>");
                    htmlBuilder.appendEscaped(formTitle);
                    htmlBuilder.appendHtmlConstant("</h2>");
                    // ok: java-cross-site-scripting-gwt
                    HTML formHeader = new HTML(htmlBuilder.toSafeHtml());
                    panel.add(formHeader);
                    
                    TextBox nameBox = new TextBox();
                    panel.add(new HTML("Name:"));
                    panel.add(nameBox);
                    
                    Button submitButton = new Button("Submit");
                    panel.add(submitButton);
                    
                    RootPanel.get("formContainer").add(form);
                }
                
                public void onError(Request request, Throwable exception) {
                    Window.alert("Failed to load form data");
                }
            });
        } catch (Exception e) {
            Window.alert("Error: " + e.getMessage());
        }
    }
    
    // Using SafeHtmlUtils for URL parameters
    private void good_case_13() {
        Map<String, String> params = Window.Location.getParameterMap();
        String username = params.get("username");
        
        if (username != null) {
            SafeHtml safeWelcome = SafeHtmlUtils.fromTrustedString("<div>Welcome back, ")
                .concat(SafeHtmlUtils.fromString(username))
                .concat(SafeHtmlUtils.fromTrustedString("!</div>"));
            // ok: java-cross-site-scripting-gwt
            HTML welcomeMessage = new HTML(safeWelcome);
            RootPanel.get("welcomeContainer").add(welcomeMessage);
        }
    }
    
    // Using SafeHtmlUtils for query parameters
    private void good_case_14() {
        String searchTerm = Window.Location.getParameter("q");
        
        if (searchTerm != null && !searchTerm.isEmpty()) {
            Element searchResultElement = Document.get().getElementById("searchResults");
            // ok: java-cross-site-scripting-gwt
            searchResultElement.setInnerHTML(SafeHtmlUtils.fromString("Search results for: " + searchTerm).asString());
            
            // Perform search...
        }
    }
    
    // Using SafeHtmlUtils for header values
    private void good_case_15() {
        RequestBuilder builder = new RequestBuilder(RequestBuilder.GET, "/api/headers");
        try {
            builder.sendRequest(null, new RequestCallback() {
                public void onResponseReceived(Request request, Response response) {
                    String userAgent = response.getHeader("User-Agent");
                    SafeHtmlBuilder htmlBuilder = new SafeHtmlBuilder();
                    htmlBuilder.appendHtmlConstant("<div>Your browser: ");
                    htmlBuilder.appendEscaped(userAgent);
                    htmlBuilder.appendHtmlConstant("</div>");
                    // ok: java-cross-site-scripting-gwt
                    HTML headerInfo = new HTML(htmlBuilder.toSafeHtml());
                    RootPanel.get("browserInfo").add(headerInfo);
                }
                
                public void onError(Request request, Throwable exception) {
                    Window.alert("Failed to get headers");
                }
            });
        } catch (Exception e) {
            Window.alert("Error: " + e.getMessage());
        }
    }
}