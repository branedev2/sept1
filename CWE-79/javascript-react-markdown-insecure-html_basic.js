import React from 'react';
import ReactMarkdown from 'react-markdown';
import rehypeRaw from 'rehype-raw';

// TRUE POSITIVES (Vulnerable Code)

// Example 1: Disabling escapeHtml
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1() {
  const userInput = "<script>alert('XSS')</script>";
  
  return (
    <div>
      {/* ruleid: javascript-react-markdown-insecure-html */}
      <ReactMarkdown escapeHtml={false}>
        {userInput}
      </ReactMarkdown>
    </div>
  );
}
// {/fact}

// Example 2: Using allowDangerousHtml
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2() {
  const userInput = "<img src='x' onerror='alert(\"XSS\")'>";
  
  return (
    <div>
      {/* ruleid: javascript-react-markdown-insecure-html */}
      <ReactMarkdown allowDangerousHtml>
        {userInput}
      </ReactMarkdown>
    </div>
  );
}
// {/fact}

// Example 3: Insecure transformImageUri that doesn't validate URLs
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3() {
  const userInput = "![Image](x)";
  
  return (
    <div>
      {/* ruleid: javascript-react-markdown-insecure-html */}
      <ReactMarkdown
        transformImageUri={(uri) => {
          // No validation, could allow javascript: URLs
          return uri;
        }}
      >
        {userInput}
      </ReactMarkdown>
    </div>
  );
}
// {/fact}

// Example 4: Insecure transformLinkUri that allows javascript: URLs
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4() {
  const userInput = "[Click me](javascript:alert('XSS'))";
  
  return (
    <div>
      {/* ruleid: javascript-react-markdown-insecure-html */}
      <ReactMarkdown
        transformLinkUri={(uri) => {
          // Explicitly allowing javascript: URLs
          return uri;
        }}
      >
        {userInput}
      </ReactMarkdown>
    </div>
  );
}
// {/fact}

// Example 5: Using rehype-raw plugin without proper sanitization
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5() {
  const userInput = "<div onclick='alert(\"XSS\")'>Click me</div>";
  
  return (
    <div>
      {/* ruleid: javascript-react-markdown-insecure-html */}
      <ReactMarkdown rehypePlugins={[rehypeRaw]}>
        {userInput}
      </ReactMarkdown>
    </div>
  );
}
// {/fact}

// Example 6: Setting both allowDangerousHtml and using rehype-raw
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6() {
  const userInput = "<img src='x' onerror='alert(\"XSS\")'>";
  
  return (
    <div>
      {/* ruleid: javascript-react-markdown-insecure-html */}
      <ReactMarkdown 
        allowDangerousHtml 
        rehypePlugins={[rehypeRaw]}
      >
        {userInput}
      </ReactMarkdown>
    </div>
  );
}
// {/fact}

// Example 7: Using transformLinkUri to allow data: URLs
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7() {
  const userInput = "[Click me](data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=)";
  
  return (
    <div>
      {/* ruleid: javascript-react-markdown-insecure-html */}
      <ReactMarkdown
        transformLinkUri={(uri) => {
          // Allowing data: URLs which can contain malicious HTML/JS
          if (uri.startsWith('data:')) {
            return uri;
          }
          return uri;
        }}
      >
        {userInput}
      </ReactMarkdown>
    </div>
  );
}
// {/fact}

// Example 8: Using transformImageUri to allow javascript: URLs in images
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8() {
  const userInput = "![Image](javascript:alert('XSS'))";
  
  return (
    <div>
      {/* ruleid: javascript-react-markdown-insecure-html */}
      <ReactMarkdown
        transformImageUri={(uri) => {
          // Explicitly allowing javascript: URLs in images
          if (uri.startsWith('javascript:')) {
            return uri;
          }
          return `https://example.com/images/${uri}`;
        }}
      >
        {userInput}
      </ReactMarkdown>
    </div>
  );
}
// {/fact}

// Example 9: Setting skipHtml to false (allows HTML)
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9() {
  const userInput = "<script>alert('XSS')</script>";
  
  return (
    <div>
      {/* ruleid: javascript-react-markdown-insecure-html */}
      <ReactMarkdown skipHtml={false}>
        {userInput}
      </ReactMarkdown>
    </div>
  );
}
// {/fact}

// Example 10: Using transformLinkUri that returns null (disables sanitization)
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10() {
  const userInput = "[Click me](javascript:alert('XSS'))";
  
  return (
    <div>
      {/* ruleid: javascript-react-markdown-insecure-html */}
      <ReactMarkdown
        transformLinkUri={() => null}
      >
        {userInput}
      </ReactMarkdown>
    </div>
  );
}
// {/fact}

// Example 11: Disabling URL sanitization
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11() {
  const userInput = "[Click me](javascript:alert('XSS'))";
  
  return (
    <div>
      {/* ruleid: javascript-react-markdown-insecure-html */}
      <ReactMarkdown
        urlTransform={(url) => url}
      >
        {userInput}
      </ReactMarkdown>
    </div>
  );
}
// {/fact}

// Example 12: Using both escapeHtml=false and transformLinkUri
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12() {
  const userInput = "<a href='javascript:alert(\"XSS\")'>Click me</a>";
  
  return (
    <div>
      {/* ruleid: javascript-react-markdown-insecure-html */}
      <ReactMarkdown
        escapeHtml={false}
        transformLinkUri={(uri) => uri}
      >
        {userInput}
      </ReactMarkdown>
    </div>
  );
}
// {/fact}

// Example 13: Using allowElement to permit script tags
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13() {
  const userInput = "<script>alert('XSS')</script>";
  
  return (
    <div>
      {/* ruleid: javascript-react-markdown-insecure-html */}
      <ReactMarkdown
        allowElement={(element) => {
          // Allowing script elements
          return true;
        }}
      >
        {userInput}
      </ReactMarkdown>
    </div>
  );
}
// {/fact}

// Example 14: Using components to render raw HTML
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14() {
  const userInput = "# Title\n<div onclick='alert(\"XSS\")'>Click me</div>";
  
  return (
    <div>
      {/* ruleid: javascript-react-markdown-insecure-html */}
      <ReactMarkdown
        components={{
          div: ({node, ...props}) => <div {...props} dangerouslySetInnerHTML={{__html: node.children[0].value}} />
        }}
      >
        {userInput}
      </ReactMarkdown>
    </div>
  );
}
// {/fact}

// Example 15: Using rehypePlugins with insecure configuration
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15() {
  const userInput = "<img src='x' onerror='alert(\"XSS\")'>";
  
  return (
    <div>
      {/* ruleid: javascript-react-markdown-insecure-html */}
      <ReactMarkdown
        rehypePlugins={[
          [rehypeRaw, { passThrough: ['script', 'onclick'] }]
        ]}
      >
        {userInput}
      </ReactMarkdown>
    </div>
  );
}
// {/fact}

// TRUE NEGATIVES (Secure Code)

// Example 1: Default configuration (escapeHtml is true by default)
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1() {
  const userInput = "<script>alert('XSS')</script>";
  
  return (
    <div>
      {/* ok: javascript-react-markdown-insecure-html */}
      <ReactMarkdown>
        {userInput}
      </ReactMarkdown>
    </div>
  );
}
// {/fact}

// Example 2: Explicitly setting escapeHtml to true
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2() {
  const userInput = "<img src='x' onerror='alert(\"XSS\")'>";
  
  return (
    <div>
      {/* ok: javascript-react-markdown-insecure-html */}
      <ReactMarkdown escapeHtml={true}>
        {userInput}
      </ReactMarkdown>
    </div>
  );
}
// {/fact}

// Example 3: Secure transformImageUri that validates URLs
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3() {
  const userInput = "![Image](x)";
  
  return (
    <div>
      {/* ok: javascript-react-markdown-insecure-html */}
      <ReactMarkdown
        transformImageUri={(uri) => {
          // Validate and only allow specific URL patterns
          if (uri.match(/^[a-zA-Z0-9-_/]+\.(jpg|png|gif)$/)) {
            return `https://example.com/images/${uri}`;
          }
          return 'https://example.com/images/placeholder.png';
        }}
      >
        {userInput}
      </ReactMarkdown>
    </div>
  );
}
// {/fact}

// Example 4: Secure transformLinkUri that blocks javascript: URLs
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4() {
  const userInput = "[Click me](javascript:alert('XSS'))";
  
  return (
    <div>
      {/* ok: javascript-react-markdown-insecure-html */}
      <ReactMarkdown
        transformLinkUri={(uri) => {
          // Block javascript: URLs
          if (uri.startsWith('javascript:')) {
            return '#';
          }
          return uri;
        }}
      >
        {userInput}
      </ReactMarkdown>
    </div>
  );
}
// {/fact}

// Example 5: Using rehype-sanitize plugin for proper sanitization
import rehypeSanitize from 'rehype-sanitize';

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5() {
  const userInput = "<div onclick='alert(\"XSS\")'>Click me</div>";
  
  return (
    <div>
      {/* ok: javascript-react-markdown-insecure-html */}
      <ReactMarkdown rehypePlugins={[rehypeSanitize]}>
        {userInput}
      </ReactMarkdown>
    </div>
  );
}
// {/fact}

// Example 6: Using default transformLinkUri (which is secure)
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6() {
  const userInput = "[Click me](javascript:alert('XSS'))";
  
  return (
    <div>
      {/* ok: javascript-react-markdown-insecure-html */}
      <ReactMarkdown>
        {userInput}
      </ReactMarkdown>
    </div>
  );
}
// {/fact}

// Example 7: Using skipHtml set to true
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7() {
  const userInput = "<script>alert('XSS')</script>";
  
  return (
    <div>
      {/* ok: javascript-react-markdown-insecure-html */}
      <ReactMarkdown skipHtml={true}>
        {userInput}
      </ReactMarkdown>
    </div>
  );
}
// {/fact}

// Example 8: Using a custom sanitization function for links
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8() {
  const userInput = "[Click me](javascript:alert('XSS'))";
  
  return (
    <div>
      {/* ok: javascript-react-markdown-insecure-html */}
      <ReactMarkdown
        transformLinkUri={(uri) => {
          // Whitelist approach - only allow http/https URLs
          if (uri.match(/^https?:\/\//)) {
            return uri;
          }
          return '#';
        }}
      >
        {userInput}
      </ReactMarkdown>
    </div>
  );
}
// {/fact}

// Example 9: Using a custom sanitization function for images
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9() {
  const userInput = "![Image](javascript:alert('XSS'))";
  
  return (
    <div>
      {/* ok: javascript-react-markdown-insecure-html */}
      <ReactMarkdown
        transformImageUri={(uri) => {
          // Only allow specific image extensions
          if (uri.match(/\.(jpg|jpeg|png|gif)$/i)) {
            return uri;
          }
          return '/placeholder.png';
        }}
      >
        {userInput}
      </ReactMarkdown>
    </div>
  );
}
// {/fact}

// Example 10: Using rehype-sanitize with custom schema
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10() {
  const userInput = "<div class='user-content'>Some content</div>";
  
  return (
    <div>
      {/* ok: javascript-react-markdown-insecure-html */}
      <ReactMarkdown
        rehypePlugins={[
          [rehypeSanitize, {
            attributes: {
              div: ['className']
            }
          }]
        ]}
      >
        {userInput}
      </ReactMarkdown>
    </div>
  );
}
// {/fact}

// Example 11: Using allowElement to filter out dangerous elements
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11() {
  const userInput = "<script>alert('XSS')</script><div>Safe content</div>";
  
  return (
    <div>
      {/* ok: javascript-react-markdown-insecure-html */}
      <ReactMarkdown
        allowElement={(element) => {
          // Block script elements
          return element.tagName !== 'script';
        }}
      >
        {userInput}
      </ReactMarkdown>
    </div>
  );
}
// {/fact}

// Example 12: Using components to safely render custom elements
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12() {
  const userInput = "# Title\n<custom>Some content</custom>";
  
  return (
    <div>
      {/* ok: javascript-react-markdown-insecure-html */}
      <ReactMarkdown
        components={{
          custom: ({node, ...props}) => <div className="safe-custom" {...props} />
        }}
      >
        {userInput}
      </ReactMarkdown>
    </div>
  );
}
// {/fact}

// Example 13: Using DOMPurify for additional sanitization
import DOMPurify from 'dompurify';

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13() {
  const userInput = "<div onclick='alert(\"XSS\")'>Click me</div>";
  const sanitizedInput = DOMPurify.sanitize(userInput);
  
  return (
    <div>
      {/* ok: javascript-react-markdown-insecure-html */}
      <ReactMarkdown>
        {sanitizedInput}
      </ReactMarkdown>
    </div>
  );
}
// {/fact}

// Example 14: Using rehypePlugins with secure configuration
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14() {
  const userInput = "<img src='x' onerror='alert(\"XSS\")'>";
  
  return (
    <div>
      {/* ok: javascript-react-markdown-insecure-html */}
      <ReactMarkdown
        rehypePlugins={[
          rehypeSanitize
        ]}
      >
        {userInput}
      </ReactMarkdown>
    </div>
  );
}
// {/fact}

// Example 15: Using a combination of secure practices
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15() {
  const userInput = "<script>alert('XSS')</script>[Link](javascript:alert('XSS'))";
  
  return (
    <div>
      {/* ok: javascript-react-markdown-insecure-html */}
      <ReactMarkdown
        skipHtml={true}
        transformLinkUri={(uri) => {
          if (uri.startsWith('javascript:') || uri.startsWith('data:')) {
            return '#';
          }
          return uri;
        }}
        rehypePlugins={[rehypeSanitize]}
      >
        {userInput}
      </ReactMarkdown>
    </div>
  );
}
// {/fact}