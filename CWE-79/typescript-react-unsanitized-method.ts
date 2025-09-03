import React, { useState, useEffect } from 'react';
import DOMPurify from 'dompurify';
import axios from 'axios';

// True Positive Examples (Vulnerable Code)

// Example 1: Directly setting innerHTML with user input
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1() {
  const [userInput, setUserInput] = useState('');
  
  useEffect(() => {
    // Fetch user input from an API
    axios.get('/api/user-content')
      .then(response => {
        setUserInput(response.data.content);
      });
  }, []);

  return (
    <div 
      // ruleid: typescript-react-unsanitized-method
      dangerouslySetInnerHTML={{ __html: userInput }} 
    />
  );
}
// {/fact}

// Example 2: Using template literals with user input in dangerouslySetInnerHTML
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2() {
  const [username, setUsername] = useState('');
  
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    setUsername(params.get('username') || '');
  }, []);

  // ruleid: typescript-react-unsanitized-method
  return <div dangerouslySetInnerHTML={{ __html: `<h1>Welcome ${username}!</h1>` }} />;
}
// {/fact}

// Example 3: Using state variable in dangerouslySetInnerHTML
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3() {
  const [htmlContent, setHtmlContent] = useState('');
  
  const handleSubmit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const formData = new FormData(event.currentTarget);
    const content = formData.get('content') as string;
    setHtmlContent(content);
  };

  return (
    <>
      <form onSubmit={handleSubmit}>
        <textarea name="content" />
        <button type="submit">Submit</button>
      </form>
      {/* ruleid: typescript-react-unsanitized-method */}
      <div dangerouslySetInnerHTML={{ __html: htmlContent }} />
    </>
  );
}
// {/fact}

// Example 4: Using props in dangerouslySetInnerHTML
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4(props: { content: string }) {
// {/fact}

  // The content could come from user input
  return (
    // ruleid: typescript-react-unsanitized-method
    <div dangerouslySetInnerHTML={{ __html: props.content }} />
  );
}

// Example 5: Using fetch API to get user content
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5() {
  const [content, setContent] = useState('');
  
  useEffect(() => {
    fetch('/api/comments')
      .then(response => response.json())
      .then(data => {
        setContent(data.latestComment);
      });
  }, []);

  return (
    // ruleid: typescript-react-unsanitized-method
    <div dangerouslySetInnerHTML={{ __html: content }} />
  );
}
// {/fact}

// Example 6: Using data from localStorage
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6() {
  const [savedHtml, setSavedHtml] = useState('');
  
  useEffect(() => {
    const storedHtml = localStorage.getItem('userGeneratedContent');
    if (storedHtml) {
      setSavedHtml(storedHtml);
    }
  }, []);

  return (
    // ruleid: typescript-react-unsanitized-method
    <div dangerouslySetInnerHTML={{ __html: savedHtml }} />
  );
}
// {/fact}

// Example 7: Using data from cookies
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7() {
  const [cookieContent, setCookieContent] = useState('');
  
  useEffect(() => {
    const cookies = document.cookie.split(';');
    for (const cookie of cookies) {
      const [name, value] = cookie.trim().split('=');
      if (name === 'userHtmlContent') {
        setCookieContent(decodeURIComponent(value));
        break;
      }
    }
  }, []);

  return (
    // ruleid: typescript-react-unsanitized-method
    <div dangerouslySetInnerHTML={{ __html: cookieContent }} />
  );
}
// {/fact}

// Example 8: Using data from URL hash
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8() {
  const [hashContent, setHashContent] = useState('');
  
  useEffect(() => {
    const hashValue = window.location.hash.substring(1);
    if (hashValue) {
      setHashContent(decodeURIComponent(hashValue));
    }
  }, []);

  return (
    // ruleid: typescript-react-unsanitized-method
    <div dangerouslySetInnerHTML={{ __html: hashContent }} />
  );
}
// {/fact}

// Example 9: Using data from WebSocket
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9() {
  const [wsMessage, setWsMessage] = useState('');
  
  useEffect(() => {
    const socket = new WebSocket('ws://example.com/socket');
    socket.onmessage = (event) => {
      const data = JSON.parse(event.data);
      setWsMessage(data.htmlContent);
    };
    
    return () => {
      socket.close();
    };
  }, []);

  return (
    // ruleid: typescript-react-unsanitized-method
    <div dangerouslySetInnerHTML={{ __html: wsMessage }} />
  );
}
// {/fact}

// Example 10: Using data from IndexedDB
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10() {
  const [dbContent, setDbContent] = useState('');
  
  useEffect(() => {
    const request = indexedDB.open('userDatabase', 1);
    
    request.onsuccess = (event) => {
      const db = request.result;
      const transaction = db.transaction(['userContent'], 'readonly');
      const objectStore = transaction.objectStore('userContent');
      const getRequest = objectStore.get('html');
      
      getRequest.onsuccess = () => {
        if (getRequest.result) {
          setDbContent(getRequest.result.content);
        }
      };
    };
  }, []);

  return (
    // ruleid: typescript-react-unsanitized-method
    <div dangerouslySetInnerHTML={{ __html: dbContent }} />
  );
}
// {/fact}

// Example 11: Using data from sessionStorage
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11() {
  const [sessionContent, setSessionContent] = useState('');
  
  useEffect(() => {
    const content = sessionStorage.getItem('userHtml');
    if (content) {
      setSessionContent(content);
    }
  }, []);

  return (
    // ruleid: typescript-react-unsanitized-method
    <div dangerouslySetInnerHTML={{ __html: sessionContent }} />
  );
}
// {/fact}

// Example 12: Using data from postMessage
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12() {
  const [messageContent, setMessageContent] = useState('');
  
  useEffect(() => {
    const handleMessage = (event: MessageEvent) => {
      if (event.origin === 'https://trusted-source.com') {
        setMessageContent(event.data.html);
      }
    };
    
    window.addEventListener('message', handleMessage);
    return () => {
      window.removeEventListener('message', handleMessage);
    };
  }, []);

  return (
    // ruleid: typescript-react-unsanitized-method
    <div dangerouslySetInnerHTML={{ __html: messageContent }} />
  );
}
// {/fact}

// Example 13: Using data from a custom event
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13() {
  const [eventContent, setEventContent] = useState('');
  
  useEffect(() => {
    const handleCustomEvent = (event: CustomEvent) => {
      setEventContent(event.detail.htmlContent);
    };
    
    window.addEventListener('customHtmlEvent', handleCustomEvent as EventListener);
    return () => {
      window.removeEventListener('customHtmlEvent', handleCustomEvent as EventListener);
    };
  }, []);

  return (
    // ruleid: typescript-react-unsanitized-method
    <div dangerouslySetInnerHTML={{ __html: eventContent }} />
  );
}
// {/fact}

// Example 14: Using data from a third-party API
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14() {
  const [apiContent, setApiContent] = useState('');
  
  useEffect(() => {
    axios.get('https://third-party-api.com/content')
      .then(response => {
        setApiContent(response.data.htmlContent);
      });
  }, []);

  return (
    // ruleid: typescript-react-unsanitized-method
    <div dangerouslySetInnerHTML={{ __html: apiContent }} />
  );
}
// {/fact}

// Example 15: Using data from URL search params with string manipulation
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15() {
  const [processedContent, setProcessedContent] = useState('');
  
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const rawContent = params.get('content') || '';
    // Even with some processing, it's still unsafe
    const processed = rawContent.replace(/script/gi, '').replace(/onerror/gi, '');
    setProcessedContent(processed);
  }, []);

  return (
    // ruleid: typescript-react-unsanitized-method
    <div dangerouslySetInnerHTML={{ __html: processedContent }} />
  );
}
// {/fact}

// True Negative Examples (Safe Code)

// Example 1: Using DOMPurify to sanitize user input
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1() {
  const [userInput, setUserInput] = useState('');
  
  useEffect(() => {
    axios.get('/api/user-content')
      .then(response => {
        setUserInput(response.data.content);
      });
  }, []);

  return (
    <div 
      // ok: typescript-react-unsanitized-method
      dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userInput) }} 
    />
  );
}
// {/fact}

// Example 2: Using constant HTML (not user input)
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2() {
  const staticHtml = '<h1>Welcome to our site!</h1>';
  
  return (
    // ok: typescript-react-unsanitized-method
    <div dangerouslySetInnerHTML={{ __html: staticHtml }} />
  );
}
// {/fact}

// Example 3: Using sanitized state variable
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3() {
  const [htmlContent, setHtmlContent] = useState('');
  
  const handleSubmit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const formData = new FormData(event.currentTarget);
    const content = formData.get('content') as string;
    setHtmlContent(content);
  };

  return (
    <>
      <form onSubmit={handleSubmit}>
        <textarea name="content" />
        <button type="submit">Submit</button>
      </form>
      {/* ok: typescript-react-unsanitized-method */}
      <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(htmlContent) }} />
    </>
  );
}
// {/fact}

// Example 4: Using sanitized props
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4(props: { content: string }) {
// {/fact}

  return (
    // ok: typescript-react-unsanitized-method
    <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(props.content) }} />
  );
}

// Example 5: Using fetch API with sanitization
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5() {
  const [content, setContent] = useState('');
  
  useEffect(() => {
    fetch('/api/comments')
      .then(response => response.json())
      .then(data => {
        setContent(data.latestComment);
      });
  }, []);

  return (
    // ok: typescript-react-unsanitized-method
    <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(content) }} />
  );
}
// {/fact}

// Example 6: Using sanitized data from localStorage
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6() {
  const [savedHtml, setSavedHtml] = useState('');
  
  useEffect(() => {
    const storedHtml = localStorage.getItem('userGeneratedContent');
    if (storedHtml) {
      setSavedHtml(storedHtml);
    }
  }, []);

  return (
    // ok: typescript-react-unsanitized-method
    <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(savedHtml) }} />
  );
}
// {/fact}

// Example 7: Using safe HTML rendering without dangerouslySetInnerHTML
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7() {
  const [userContent, setUserContent] = useState('');
  
  useEffect(() => {
    axios.get('/api/user-content')
      .then(response => {
        setUserContent(response.data.content);
      });
  }, []);

  // ok: typescript-react-unsanitized-method
  return <div>{userContent}</div>; // React escapes content by default
}
// {/fact}

// Example 8: Using a custom sanitizer function
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8() {
  const [content, setContent] = useState('');
  
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    setContent(params.get('content') || '');
  }, []);

  const sanitizeHtml = (html: string): string => {
    // Using DOMPurify with custom configuration
    return DOMPurify.sanitize(html, {
      ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p'],
      ALLOWED_ATTR: ['href']
    });
  };

  return (
    // ok: typescript-react-unsanitized-method
    <div dangerouslySetInnerHTML={{ __html: sanitizeHtml(content) }} />
  );
}
// {/fact}

// Example 9: Using a third-party sanitization library
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9() {
  const [htmlContent, setHtmlContent] = useState('');
  
  useEffect(() => {
    fetch('/api/content')
      .then(response => response.json())
      .then(data => {
        setHtmlContent(data.html);
      });
  }, []);

  // Assuming sanitizeHtml is another sanitization library
  const sanitizeHtml = (html: string): string => {
    // Implementation of sanitization using a library
    return DOMPurify.sanitize(html);
  };

  return (
    // ok: typescript-react-unsanitized-method
    <div dangerouslySetInnerHTML={{ __html: sanitizeHtml(htmlContent) }} />
  );
}
// {/fact}

// Example 10: Using React's built-in escaping
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10() {
  const [message, setMessage] = useState('');
  
  useEffect(() => {
    const socket = new WebSocket('ws://example.com/socket');
    socket.onmessage = (event) => {
      const data = JSON.parse(event.data);
      setMessage(data.message);
    };
    
    return () => {
      socket.close();
    };
  }, []);

  // ok: typescript-react-unsanitized-method
  return (
    <div>
      <p>{message}</p> {/* React automatically escapes this */}
    </div>
  );
}
// {/fact}

// Example 11: Using a constant with template literals (safe)
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11() {
  const username = "Admin"; // Hardcoded, not user input
  
  // ok: typescript-react-unsanitized-method
  return <div dangerouslySetInnerHTML={{ __html: `<h1>Welcome ${username}!</h1>` }} />;
}
// {/fact}

// Example 12: Using sanitized data from sessionStorage
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12() {
  const [sessionContent, setSessionContent] = useState('');
  
  useEffect(() => {
    const content = sessionStorage.getItem('userHtml');
    if (content) {
      setSessionContent(content);
    }
  }, []);

  return (
    // ok: typescript-react-unsanitized-method
    <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(sessionContent) }} />
  );
}
// {/fact}

// Example 13: Using a markdown parser instead of raw HTML
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13() {
  const [markdownContent, setMarkdownContent] = useState('');
  
  useEffect(() => {
    axios.get('/api/markdown-content')
      .then(response => {
        setMarkdownContent(response.data.content);
      });
  }, []);

  // Simulating a markdown parser that outputs safe HTML
  const parseMarkdown = (markdown: string): string => {
    // In a real app, you'd use a proper markdown parser
    const html = markdown
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/\*(.*?)\*/g, '<em>$1</em>');
    
    // Still sanitize the output to be safe
    return DOMPurify.sanitize(html);
  };

  return (
    // ok: typescript-react-unsanitized-method
    <div dangerouslySetInnerHTML={{ __html: parseMarkdown(markdownContent) }} />
  );
}
// {/fact}

// Example 14: Using a whitelist approach for HTML tags
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14() {
  const [userHtml, setUserHtml] = useState('');
  
  useEffect(() => {
    fetch('/api/user-content')
      .then(response => response.json())
      .then(data => {
        setUserHtml(data.html);
      });
  }, []);

  const sanitizeWithWhitelist = (html: string): string => {
    return DOMPurify.sanitize(html, {
      ALLOWED_TAGS: ['h1', 'h2', 'p', 'a', 'ul', 'ol', 'li', 'strong', 'em'],
      ALLOWED_ATTR: ['href', 'title'],
      ALLOW_DATA_ATTR: false
    });
  };

  return (
    // ok: typescript-react-unsanitized-method
    <div dangerouslySetInnerHTML={{ __html: sanitizeWithWhitelist(userHtml) }} />
  );
}
// {/fact}

// Example 15: Using server-side sanitized content
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15() {
  const [serverSanitizedHtml, setServerSanitizedHtml] = useState('');
  
  useEffect(() => {
    // Assuming the server has already sanitized this content
    axios.get('/api/sanitized-content')
      .then(response => {
        // We still sanitize on the client side as a defense in depth measure
        setServerSanitizedHtml(DOMPurify.sanitize(response.data.sanitizedHtml));
      });
  }, []);

  return (
    // ok: typescript-react-unsanitized-method
    <div dangerouslySetInnerHTML={{ __html: serverSanitizedHtml }} />
  );
}
// {/fact}