package com.example.gwt.xss;

import com.google.gwt.core.client.EntryPoint;
import com.google.gwt.dom.client.Document;
import com.google.gwt.dom.client.Element;
import com.google.gwt.http.client.Request;
import com.google.gwt.http.client.RequestBuilder;
import com.google.gwt.http.client.RequestCallback;
import com.google.gwt.http.client.RequestException;
import com.google.gwt.http.client.Response;
import com.google.gwt.http.client.URL;
import com.google.gwt.safehtml.shared.SafeHtml;
import com.google.gwt.safehtml.shared.SafeHtmlBuilder;
import com.google.gwt.safehtml.shared.SafeHtmlUtils;
import com.google.gwt.safehtml.shared.UriUtils;
import com.google.gwt.user.client.Window;
import com.google.gwt.user.client.ui.HTML;
import com.google.gwt.user.client.ui.Label;
import com.google.gwt.user.client.ui.RootPanel;
import com.google.gwt.user.client.ui.TextBox;
import com.google.gwt.user.client.ui.Button;
import com.google.gwt.event.dom.client.ClickEvent;
import com.google.gwt.event.dom.client.ClickHandler;
import com.google.gwt.user.client.ui.FlowPanel;
import java.util.Map;
import java.util.HashMap;

public class GwtXssExamples implements EntryPoint {

    @Override
    public void onModuleLoad() {
        // This method is called when the GWT module loads
    }

    // True Positive Examples (Vulnerable Code)

    public void bad_case_1() {
        String userInput = Window.Location.getParameter("username");
        HTML html = new HTML();
        // ruleid: java-cross-site-scripting-gwt
        html.setHTML("<div>Welcome, " + userInput + "!</div>");
        RootPanel.get().add(html);
    }

    public void bad_case_2() {
        final TextBox inputBox = new TextBox();
        Button button = new Button("Submit");
        button.addClickHandler(new ClickHandler() {
            @Override
            public void onClick(ClickEvent event) {
                String userInput = inputBox.getText();
                HTML outputHtml = new HTML();
                // ruleid: java-cross-site-scripting-gwt
                outputHtml.setHTML("<p>Your comment: " + userInput + "</p>");
                RootPanel.get().add(outputHtml);
            }
        });
    }

    public void bad_case_3() {
        String searchQuery = Window.Location.getParameter("q");
        HTML resultsDiv = new HTML();
        // ruleid: java-cross-site-scripting-gwt
        resultsDiv.setHTML("<h2>Search results for: " + searchQuery + "</h2>");
        RootPanel.get("results").add(resultsDiv);
    }

    public void bad_case_4() {
        RequestBuilder builder = new RequestBuilder(RequestBuilder.GET, "/api/user");
        try {
            builder.sendRequest(null, new RequestCallback() {
                @Override
                public void onResponseReceived(Request request, Response response) {
                    String userData = response.getText();
                    HTML profileDiv = new HTML();
                    // ruleid: java-cross-site-scripting-gwt
                    profileDiv.setHTML("<div class='profile'>" + userData + "</div>");
                    RootPanel.get("profile").add(profileDiv);
                }
                
                @Override
                public void onError(Request request, Throwable exception) {
                    // Error handling
                }
            });
        } catch (RequestException e) {
            // Exception handling
        }
    }

    public void bad_case_5() {
        String errorMsg = Window.Location.getParameter("error");
        Element errorElement = Document.get().getElementById("errorContainer");
        if (errorElement != null && errorMsg != null) {
            // ruleid: java-cross-site-scripting-gwt
            errorElement.setInnerHTML("<div class='error'>" + errorMsg + "</div>");
        }
    }

    public void bad_case_6() {
        Map<String, String> formData = parseFormData(Window.Location.getHash().substring(1));
        String userName = formData.get("name");
        String userBio = formData.get("bio");
        
        HTML profileSection = new HTML();
        // ruleid: java-cross-site-scripting-gwt
        profileSection.setHTML("<h1>" + userName + "</h1><div>" + userBio + "</div>");
        RootPanel.get("profile").add(profileSection);
    }

    private Map<String, String> parseFormData(String data) {
        Map<String, String> result = new HashMap<>();
        String[] pairs = data.split("&");
        for (String pair : pairs) {
            String[] keyValue = pair.split("=");
            if (keyValue.length == 2) {
                result.put(keyValue[0], keyValue[1]);
            }
        }
        return result;
    }

    public void bad_case_7() {
        final TextBox titleBox = new TextBox();
        final TextBox contentBox = new TextBox();
        Button submitButton = new Button("Create Post");
        
        submitButton.addClickHandler(new ClickHandler() {
            @Override
            public void onClick(ClickEvent event) {
                String title = titleBox.getText();
                String content = contentBox.getText();
                
                FlowPanel postPanel = new FlowPanel();
                HTML postContent = new HTML();
                // ruleid: java-cross-site-scripting-gwt
                postContent.setHTML("<article><h2>" + title + "</h2><div>" + content + "</div></article>");
                postPanel.add(postContent);
                RootPanel.get("posts").add(postPanel);
            }
        });
    }

    public void bad_case_8() {
        String referrer = Window.Location.getParameter("ref");
        if (referrer != null) {
            HTML referrerNotice = new HTML();
            // ruleid: java-cross-site-scripting-gwt
            referrerNotice.setHTML("You were referred by: <a href='" + referrer + "'>" + referrer + "</a>");
            RootPanel.get("referrer").add(referrerNotice);
        }
    }

    public void bad_case_9() {
        RequestBuilder builder = new RequestBuilder(RequestBuilder.GET, "/api/comments?postId=123");
        try {
            builder.sendRequest(null, new RequestCallback() {
                @Override
                public void onResponseReceived(Request request, Response response) {
                    String[] comments = response.getText().split("\n");
                    HTML commentsSection = new HTML();
                    StringBuilder htmlBuilder = new StringBuilder("<ul>");
                    
                    for (String comment : comments) {
                        // ruleid: java-cross-site-scripting-gwt
                        htmlBuilder.append("<li>").append(comment).append("</li>");
                    }
                    htmlBuilder.append("</ul>");
                    commentsSection.setHTML(htmlBuilder.toString());
                    RootPanel.get("comments").add(commentsSection);
                }
                
                @Override
                public void onError(Request request, Throwable exception) {
                    // Error handling
                }
            });
        } catch (RequestException e) {
            // Exception handling
        }
    }

    public void bad_case_10() {
        String customCss = Window.Location.getParameter("theme");
        if (customCss != null) {
            HTML styleTag = new HTML();
            // ruleid: java-cross-site-scripting-gwt
            styleTag.setHTML("<style>" + customCss + "</style>");
            RootPanel.get().add(styleTag);
        }
    }

    public void bad_case_11() {
        String userId = Window.Location.getParameter("id");
        Element userProfileDiv = Document.get().getElementById("userProfile");
        
        RequestBuilder builder = new RequestBuilder(RequestBuilder.GET, "/api/user/" + userId);
        try {
            builder.sendRequest(null, new RequestCallback() {
                @Override
                public void onResponseReceived(Request request, Response response) {
                    String userData = response.getText();
                    // ruleid: java-cross-site-scripting-gwt
                    userProfileDiv.setInnerHTML(userData);
                }
                
                @Override
                public void onError(Request request, Throwable exception) {
                    // Error handling
                }
            });
        } catch (RequestException e) {
            // Exception handling
        }
    }

    public void bad_case_12() {
        String scriptToExecute = Window.Location.getParameter("callback");
        if (scriptToExecute != null) {
            HTML scriptTag = new HTML();
            // ruleid: java-cross-site-scripting-gwt
            scriptTag.setHTML("<script>" + scriptToExecute + "</script>");
            RootPanel.get().add(scriptTag);
        }
    }

    public void bad_case_13() {
        String htmlFragment = Window.Location.getParameter("content");
        Element contentDiv = Document.get().getElementById("dynamicContent");
        if (contentDiv != null && htmlFragment != null) {
            // ruleid: java-cross-site-scripting-gwt
            contentDiv.setInnerHTML(htmlFragment);
        }
    }

    public void bad_case_14() {
        final TextBox messageBox = new TextBox();
        Button sendButton = new Button("Send Message");
        
        sendButton.addClickHandler(new ClickHandler() {
            @Override
            public void onClick(ClickEvent event) {
                String message = messageBox.getText();
                Element chatWindow = Document.get().getElementById("chatWindow");
                String currentContent = chatWindow.getInnerHTML();
                // ruleid: java-cross-site-scripting-gwt
                chatWindow.setInnerHTML(currentContent + "<div class='message'>" + message + "</div>");
            }
        });
    }

    public void bad_case_15() {
        String notificationMessage = Window.Location.getParameter("notification");
        if (notificationMessage != null && !notificationMessage.isEmpty()) {
            HTML notification = new HTML();
            // ruleid: java-cross-site-scripting-gwt
            notification.setHTML("<div class='notification'>" + notificationMessage + "</div>");
            RootPanel.get("notifications").add(notification);
        }
    }

    // True Negative Examples (Safe Code)

    public void good_case_1() {
        String userInput = Window.Location.getParameter("username");
        HTML html = new HTML();
        // ok: java-cross-site-scripting-gwt
        html.setHTML("<div>Welcome, " + SafeHtmlUtils.fromString(userInput).asString() + "!</div>");
        RootPanel.get().add(html);
    }

    public void good_case_2() {
        final TextBox inputBox = new TextBox();
        Button button = new Button("Submit");
        button.addClickHandler(new ClickHandler() {
            @Override
            public void onClick(ClickEvent event) {
                String userInput = inputBox.getText();
                HTML outputHtml = new HTML();
                // ok: java-cross-site-scripting-gwt
                SafeHtmlBuilder builder = new SafeHtmlBuilder()
                    .appendHtmlConstant("<p>Your comment: ")
                    .appendEscaped(userInput)
                    .appendHtmlConstant("</p>");
                outputHtml.setHTML(builder.toSafeHtml());
                RootPanel.get().add(outputHtml);
            }
        });
    }

    public void good_case_3() {
        String searchQuery = Window.Location.getParameter("q");
        HTML resultsDiv = new HTML();
        // ok: java-cross-site-scripting-gwt
        SafeHtml safeHtml = SafeHtmlUtils.fromTrustedString("<h2>Search results for: " + 
                            SafeHtmlUtils.htmlEscape(searchQuery) + "</h2>");
        resultsDiv.setHTML(safeHtml);
        RootPanel.get("results").add(resultsDiv);
    }

    public void good_case_4() {
        RequestBuilder builder = new RequestBuilder(RequestBuilder.GET, "/api/user");
        try {
            builder.sendRequest(null, new RequestCallback() {
                @Override
                public void onResponseReceived(Request request, Response response) {
                    String userData = response.getText();
                    HTML profileDiv = new HTML();
                    // ok: java-cross-site-scripting-gwt
                    SafeHtmlBuilder safeHtmlBuilder = new SafeHtmlBuilder()
                        .appendHtmlConstant("<div class='profile'>")
                        .appendEscaped(userData)
                        .appendHtmlConstant("</div>");
                    profileDiv.setHTML(safeHtmlBuilder.toSafeHtml());
                    RootPanel.get("profile").add(profileDiv);
                }
                
                @Override
                public void onError(Request request, Throwable exception) {
                    // Error handling
                }
            });
        } catch (RequestException e) {
            // Exception handling
        }
    }

    public void good_case_5() {
        String errorMsg = Window.Location.getParameter("error");
        Element errorElement = Document.get().getElementById("errorContainer");
        if (errorElement != null && errorMsg != null) {
            // ok: java-cross-site-scripting-gwt
            SafeHtml safeErrorHtml = SafeHtmlUtils.fromTrustedString("<div class='error'>")
                .concat(SafeHtmlUtils.fromString(errorMsg))
                .concat(SafeHtmlUtils.fromTrustedString("</div>"));
            errorElement.setInnerHTML(safeErrorHtml.asString());
        }
    }

    public void good_case_6() {
        Map<String, String> formData = parseFormData(Window.Location.getHash().substring(1));
        String userName = formData.get("name");
        String userBio = formData.get("bio");
        
        HTML profileSection = new HTML();
        // ok: java-cross-site-scripting-gwt
        SafeHtmlBuilder profileBuilder = new SafeHtmlBuilder()
            .appendHtmlConstant("<h1>")
            .appendEscaped(userName)
            .appendHtmlConstant("</h1><div>")
            .appendEscaped(userBio)
            .appendHtmlConstant("</div>");
        profileSection.setHTML(profileBuilder.toSafeHtml());
        RootPanel.get("profile").add(profileSection);
    }

    public void good_case_7() {
        final TextBox titleBox = new TextBox();
        final TextBox contentBox = new TextBox();
        Button submitButton = new Button("Create Post");
        
        submitButton.addClickHandler(new ClickHandler() {
            @Override
            public void onClick(ClickEvent event) {
                String title = titleBox.getText();
                String content = contentBox.getText();
                
                FlowPanel postPanel = new FlowPanel();
                HTML postContent = new HTML();
                // ok: java-cross-site-scripting-gwt
                SafeHtmlBuilder postBuilder = new SafeHtmlBuilder()
                    .appendHtmlConstant("<article><h2>")
                    .appendEscaped(title)
                    .appendHtmlConstant("</h2><div>")
                    .appendEscaped(content)
                    .appendHtmlConstant("</div></article>");
                postContent.setHTML(postBuilder.toSafeHtml());
                postPanel.add(postContent);
                RootPanel.get("posts").add(postPanel);
            }
        });
    }

    public void good_case_8() {
        String referrer = Window.Location.getParameter("ref");
        if (referrer != null) {
            HTML referrerNotice = new HTML();
            // ok: java-cross-site-scripting-gwt
            SafeHtmlBuilder builder = new SafeHtmlBuilder()
                .appendHtmlConstant("You were referred by: <a href='")
                .append(UriUtils.fromString(referrer))
                .appendHtmlConstant("'>")
                .appendEscaped(referrer)
                .appendHtmlConstant("</a>");
            referrerNotice.setHTML(builder.toSafeHtml());
            RootPanel.get("referrer").add(referrerNotice);
        }
    }

    public void good_case_9() {
        RequestBuilder builder = new RequestBuilder(RequestBuilder.GET, "/api/comments?postId=123");
        try {
            builder.sendRequest(null, new RequestCallback() {
                @Override
                public void onResponseReceived(Request request, Response response) {
                    String[] comments = response.getText().split("\n");
                    HTML commentsSection = new HTML();
                    // ok: java-cross-site-scripting-gwt
                    SafeHtmlBuilder htmlBuilder = new SafeHtmlBuilder().appendHtmlConstant("<ul>");
                    
                    for (String comment : comments) {
                        htmlBuilder.appendHtmlConstant("<li>")
                                  .appendEscaped(comment)
                                  .appendHtmlConstant("</li>");
                    }
                    htmlBuilder.appendHtmlConstant("</ul>");
                    commentsSection.setHTML(htmlBuilder.toSafeHtml());
                    RootPanel.get("comments").add(commentsSection);
                }
                
                @Override
                public void onError(Request request, Throwable exception) {
                    // Error handling
                }
            });
        } catch (RequestException e) {
            // Exception handling
        }
    }

    public void good_case_10() {
        String customCss = Window.Location.getParameter("theme");
        if (customCss != null) {
            // ok: java-cross-site-scripting-gwt
            // Instead of injecting user CSS directly, use predefined themes
            String safeTheme = validateTheme(customCss);
            if (safeTheme != null) {
                HTML styleTag = new HTML();
                styleTag.setHTML(SafeHtmlUtils.fromTrustedString("<style>" + safeTheme + "</style>"));
                RootPanel.get().add(styleTag);
            }
        }
    }
    
    private String validateTheme(String theme) {
        // Validate against a whitelist of allowed themes
        Map<String, String> allowedThemes = new HashMap<>();
        allowedThemes.put("dark", "body { background-color: #333; color: #fff; }");
        allowedThemes.put("light", "body { background-color: #fff; color: #333; }");
        return allowedThemes.get(theme);
    }

    public void good_case_11() {
        String userId = Window.Location.getParameter("id");
        Element userProfileDiv = Document.get().getElementById("userProfile");
        
        RequestBuilder builder = new RequestBuilder(RequestBuilder.GET, "/api/user/" + URL.encodeQueryString(userId));
        try {
            builder.sendRequest(null, new RequestCallback() {
                @Override
                public void onResponseReceived(Request request, Response response) {
                    String userData = response.getText();
                    // ok: java-cross-site-scripting-gwt
                    userProfileDiv.setInnerHTML(SafeHtmlUtils.fromString(userData).asString());
                }
                
                @Override
                public void onError(Request request, Throwable exception) {
                    // Error handling
                }
            });
        } catch (RequestException e) {
            // Exception handling
        }
    }

    public void good_case_12() {
        String scriptToExecute = Window.Location.getParameter("callback");
        if (scriptToExecute != null) {
            // ok: java-cross-site-scripting-gwt
            // Instead of executing arbitrary script, use a whitelist approach
            if (isAllowedCallback(scriptToExecute)) {
                // Execute the allowed callback function by name, not by injecting script
                executeCallback(scriptToExecute);
            }
        }
    }
    
    private boolean isAllowedCallback(String callback) {
        // Whitelist of allowed callbacks
        return "onDataLoad".equals(callback) || "onUserLogin".equals(callback);
    }
    
    private void executeCallback(String callbackName) {
        // Safe execution of whitelisted callbacks
        if ("onDataLoad".equals(callbackName)) {
            // Execute onDataLoad logic
        } else if ("onUserLogin".equals(callbackName)) {
            // Execute onUserLogin logic
        }
    }

    public void good_case_13() {
        String htmlFragment = Window.Location.getParameter("content");
        Element contentDiv = Document.get().getElementById("dynamicContent");
        if (contentDiv != null && htmlFragment != null) {
            // ok: java-cross-site-scripting-gwt
            // Instead of setting raw HTML, create a Label which automatically escapes content
            Label safeLabel = new Label(htmlFragment);
            RootPanel.get("dynamicContent").add(safeLabel);
        }
    }

    public void good_case_14() {
        final TextBox messageBox = new TextBox();
        Button sendButton = new Button("Send Message");
        
        sendButton.addClickHandler(new ClickHandler() {
            @Override
            public void onClick(ClickEvent event) {
                String message = messageBox.getText();
                Element chatWindow = Document.get().getElementById("chatWindow");
                String currentContent = chatWindow.getInnerHTML();
                // ok: java-cross-site-scripting-gwt
                SafeHtml safeMessage = SafeHtmlUtils.fromTrustedString(currentContent)
                    .concat(SafeHtmlUtils.fromTrustedString("<div class='message'>"))
                    .concat(SafeHtmlUtils.fromString(message))
                    .concat(SafeHtmlUtils.fromTrustedString("</div>"));
                chatWindow.setInnerHTML(safeMessage.asString());
            }
        });
    }

    public void good_case_15() {
        String notificationMessage = Window.Location.getParameter("notification");
        if (notificationMessage != null && !notificationMessage.isEmpty()) {
            HTML notification = new HTML();
            // ok: java-cross-site-scripting-gwt
            SafeHtmlBuilder notificationBuilder = new SafeHtmlBuilder()
                .appendHtmlConstant("<div class='notification'>")
                .appendEscaped(notificationMessage)
                .appendHtmlConstant("</div>");
            notification.setHTML(notificationBuilder.toSafeHtml());
            RootPanel.get("notifications").add(notification);
        }
    }
}