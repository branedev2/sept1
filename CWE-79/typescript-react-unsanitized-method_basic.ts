import React, { useState, useEffect } from 'react';
import DOMPurify from 'dompurify';
import axios from 'axios';

// TRUE POSITIVES (Vulnerable Code)

// Example 1: Using dangerouslySetInnerHTML with user input directly
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1() {
  const [userData, setUserData] = useState('');
  
  useEffect(() => {
    // Fetch user data from API
    axios.get('/api/user-profile')
      .then(response => {
        setUserData(response.data.bio);
      });
  }, []);
  
  return (
    <div>
      {/* ruleid: typescript-react-unsanitized-method */}
      <div dangerouslySetInnerHTML={{ __html: userData }} />
    </div>
  );
}
// {/fact}

// Example 2: Using dangerouslySetInnerHTML with URL parameter
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2() {
  const [content, setContent] = useState('');
  
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const htmlContent = urlParams.get('content');
    setContent(htmlContent || '');
  }, []);
  
  return (
    <div>
      {/* ruleid: typescript-react-unsanitized-method */}
      <div dangerouslySetInnerHTML={{ __html: content }} />
    </div>
  );
}
// {/fact}

// Example 3: Using innerHTML in a ref with user input
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3() {
  const divRef = React.useRef<HTMLDivElement>(null);
  const [message, setMessage] = useState('');
  
  useEffect(() => {
    axios.get('/api/messages')
      .then(response => {
        setMessage(response.data.message);
      });
  }, []);
  
  useEffect(() => {
    if (divRef.current && message) {
      // ruleid: typescript-react-unsanitized-method
      divRef.current.innerHTML = message;
    }
  }, [message]);
  
  return <div ref={divRef}></div>;
}
// {/fact}

// Example 4: Using state from form input directly in dangerouslySetInnerHTML
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4() {
  const [comment, setComment] = useState('');
  
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    // Process the comment...
  };
  
  return (
    <div>
      <form onSubmit={handleSubmit}>
        <textarea 
          value={comment} 
          onChange={(e) => setComment(e.target.value)} 
          placeholder="Enter your comment with HTML formatting"
        />
        <button type="submit">Submit</button>
      </form>
      <div className="preview">
        <h3>Preview:</h3>
        {/* ruleid: typescript-react-unsanitized-method */}
        <div dangerouslySetInnerHTML={{ __html: comment }} />
      </div>
    </div>
  );
}
// {/fact}

// Example 5: Using dangerouslySetInnerHTML with data from localStorage
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5() {
  const [savedContent, setSavedContent] = useState('');
  
  useEffect(() => {
    const content = localStorage.getItem('userGeneratedContent');
    if (content) {
      setSavedContent(content);
    }
  }, []);
  
  return (
    <div>
      <h2>Your saved content:</h2>
      {/* ruleid: typescript-react-unsanitized-method */}
      <div dangerouslySetInnerHTML={{ __html: savedContent }} />
    </div>
  );
}
// {/fact}

// Example 6: Using template literals with user input in dangerouslySetInnerHTML
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6() {
  const [username, setUsername] = useState('');
  
  useEffect(() => {
    axios.get('/api/current-user')
      .then(response => {
        setUsername(response.data.username);
      });
  }, []);
  
  return (
    <div>
      {/* ruleid: typescript-react-unsanitized-method */}
      <div dangerouslySetInnerHTML={{ __html: `<h1>Welcome back, ${username}!</h1>` }} />
    </div>
  );
}
// {/fact}

// Example 7: Using dangerouslySetInnerHTML with data from sessionStorage
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7() {
  const [notificationHtml, setNotificationHtml] = useState('');
  
  useEffect(() => {
    const notification = sessionStorage.getItem('notification');
    if (notification) {
      setNotificationHtml(notification);
    }
  }, []);
  
  return (
    <div className="notification-area">
      {/* ruleid: typescript-react-unsanitized-method */}
      <div dangerouslySetInnerHTML={{ __html: notificationHtml }} />
    </div>
  );
}
// {/fact}

// Example 8: Using dangerouslySetInnerHTML with data from a cookie
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8() {
  const [cookieContent, setCookieContent] = useState('');
  
  useEffect(() => {
    // Get content from cookie
    const cookies = document.cookie.split(';');
    const contentCookie = cookies.find(cookie => cookie.trim().startsWith('userContent='));
    if (contentCookie) {
      const content = contentCookie.split('=')[1];
      setCookieContent(decodeURIComponent(content));
    }
  }, []);
  
  return (
    <div>
      {/* ruleid: typescript-react-unsanitized-method */}
      <div dangerouslySetInnerHTML={{ __html: cookieContent }} />
    </div>
  );
}
// {/fact}

// Example 9: Using dangerouslySetInnerHTML with data from WebSocket
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9() {
  const [messageHtml, setMessageHtml] = useState('');
  
  useEffect(() => {
    const ws = new WebSocket('wss://example.com/chat');
    
    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      setMessageHtml(data.messageContent);
    };
    
    return () => {
      ws.close();
    };
  }, []);
  
  return (
    <div className="chat-message">
      {/* ruleid: typescript-react-unsanitized-method */}
      <div dangerouslySetInnerHTML={{ __html: messageHtml }} />
    </div>
  );
}
// {/fact}

// Example 10: Using innerHTML in a custom hook with user input
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10() {
  const containerRef = React.useRef<HTMLDivElement>(null);
  const [htmlData, setHtmlData] = useState('');
  
  useEffect(() => {
    axios.get('/api/html-content')
      .then(response => {
        setHtmlData(response.data.content);
      });
  }, []);
  
  useEffect(() => {
    if (containerRef.current && htmlData) {
      // ruleid: typescript-react-unsanitized-method
      containerRef.current.innerHTML = htmlData;
    }
  }, [htmlData]);
  
  return <div ref={containerRef}></div>;
}
// {/fact}

// Example 11: Using dangerouslySetInnerHTML with concatenated user input
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11() {
  const [title, setTitle] = useState('');
  const [body, setBody] = useState('');
  
  useEffect(() => {
    axios.get('/api/article')
      .then(response => {
        setTitle(response.data.title);
        setBody(response.data.body);
      });
  }, []);
  
  const fullContent = `<h1>${title}</h1><div>${body}</div>`;
  
  return (
    <article>
      {/* ruleid: typescript-react-unsanitized-method */}
      <div dangerouslySetInnerHTML={{ __html: fullContent }} />
    </article>
  );
}
// {/fact}

// Example 12: Using dangerouslySetInnerHTML with processed but unsanitized data
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12() {
  const [comment, setComment] = useState('');
  
  useEffect(() => {
    axios.get('/api/comments/latest')
      .then(response => {
        // Process the comment but don't sanitize
        const processedComment = response.data.text.replace(/\n/g, '<br>');
        setComment(processedComment);
      });
  }, []);
  
  return (
    <div className="comment">
      {/* ruleid: typescript-react-unsanitized-method */}
      <div dangerouslySetInnerHTML={{ __html: comment }} />
    </div>
  );
}
// {/fact}

// Example 13: Using dangerouslySetInnerHTML with data from IndexedDB
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13() {
  const [storedHtml, setStoredHtml] = useState('');
  
  useEffect(() => {
    const request = indexedDB.open('UserContent', 1);
    
    request.onsuccess = (event) => {
      const db = request.result;
      const transaction = db.transaction(['content'], 'readonly');
      const objectStore = transaction.objectStore('content');
      const getRequest = objectStore.get('savedHtml');
      
      getRequest.onsuccess = () => {
        if (getRequest.result) {
          setStoredHtml(getRequest.result.html);
        }
      };
    };
  }, []);
  
  return (
    <div>
      {/* ruleid: typescript-react-unsanitized-method */}
      <div dangerouslySetInnerHTML={{ __html: storedHtml }} />
    </div>
  );
}
// {/fact}

// Example 14: Using dangerouslySetInnerHTML with data from postMessage
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14() {
  const [messageContent, setMessageContent] = useState('');
  
  useEffect(() => {
    const handleMessage = (event: MessageEvent) => {
      // Validate origin in real code
      if (event.data && event.data.type === 'html-content') {
        setMessageContent(event.data.html);
      }
    };
    
    window.addEventListener('message', handleMessage);
    return () => window.removeEventListener('message', handleMessage);
  }, []);
  
  return (
    <div className="embedded-content">
      {/* ruleid: typescript-react-unsanitized-method */}
      <div dangerouslySetInnerHTML={{ __html: messageContent }} />
    </div>
  );
}
// {/fact}

// Example 15: Using dangerouslySetInnerHTML with data from a third-party API
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15() {
  const [externalContent, setExternalContent] = useState('');
  
  useEffect(() => {
    axios.get('https://external-api.example.com/widget-content')
      .then(response => {
        setExternalContent(response.data.html);
      });
  }, []);
  
  return (
    <div className="external-widget">
      {/* ruleid: typescript-react-unsanitized-method */}
      <div dangerouslySetInnerHTML={{ __html: externalContent }} />
    </div>
  );
}
// {/fact}

// TRUE NEGATIVES (Safe Code)

// Example 1: Using DOMPurify to sanitize HTML before using dangerouslySetInnerHTML
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1() {
  const [userData, setUserData] = useState('');
  
  useEffect(() => {
    axios.get('/api/user-profile')
      .then(response => {
        setUserData(response.data.bio);
      });
  }, []);
  
  return (
    <div>
      {/* ok: typescript-react-unsanitized-method */}
      <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userData) }} />
    </div>
  );
}
// {/fact}

// Example 2: Using DOMPurify to sanitize URL parameter content
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2() {
  const [content, setContent] = useState('');
  
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const htmlContent = urlParams.get('content');
    setContent(htmlContent || '');
  }, []);
  
  return (
    <div>
      {/* ok: typescript-react-unsanitized-method */}
      <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(content) }} />
    </div>
  );
}
// {/fact}

// Example 3: Using DOMPurify to sanitize HTML in a ref
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3() {
  const divRef = React.useRef<HTMLDivElement>(null);
  const [message, setMessage] = useState('');
  
  useEffect(() => {
    axios.get('/api/messages')
      .then(response => {
        setMessage(response.data.message);
      });
  }, []);
  
  useEffect(() => {
    if (divRef.current && message) {
      // ok: typescript-react-unsanitized-method
      divRef.current.innerHTML = DOMPurify.sanitize(message);
    }
  }, [message]);
  
  return <div ref={divRef}></div>;
}
// {/fact}

// Example 4: Using DOMPurify to sanitize form input for preview
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4() {
  const [comment, setComment] = useState('');
  
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    // Process the comment...
  };
  
  return (
    <div>
      <form onSubmit={handleSubmit}>
        <textarea 
          value={comment} 
          onChange={(e) => setComment(e.target.value)} 
          placeholder="Enter your comment with HTML formatting"
        />
        <button type="submit">Submit</button>
      </form>
      <div className="preview">
        <h3>Preview:</h3>
        {/* ok: typescript-react-unsanitized-method */}
        <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(comment) }} />
      </div>
    </div>
  );
}
// {/fact}

// Example 5: Using DOMPurify to sanitize content from localStorage
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5() {
  const [savedContent, setSavedContent] = useState('');
  
  useEffect(() => {
    const content = localStorage.getItem('userGeneratedContent');
    if (content) {
      setSavedContent(content);
    }
  }, []);
  
  return (
    <div>
      <h2>Your saved content:</h2>
      {/* ok: typescript-react-unsanitized-method */}
      <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(savedContent) }} />
    </div>
  );
}
// {/fact}

// Example 6: Using constant HTML (not user input)
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6() {
  const staticHtml = '<h1>Welcome to our site!</h1><p>This is a static message.</p>';
  
  return (
    <div>
      {/* ok: typescript-react-unsanitized-method */}
      <div dangerouslySetInnerHTML={{ __html: staticHtml }} />
    </div>
  );
}
// {/fact}

// Example 7: Using DOMPurify with configuration options
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7() {
  const [articleContent, setArticleContent] = useState('');
  
  useEffect(() => {
    axios.get('/api/article/content')
      .then(response => {
        setArticleContent(response.data.content);
      });
  }, []);
  
  // Configure DOMPurify to allow certain tags but forbid scripts
  const purifyConfig = {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'ul', 'ol', 'li'],
    ALLOWED_ATTR: ['href', 'target']
  };
  
  return (
    <article>
      {/* ok: typescript-react-unsanitized-method */}
      <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(articleContent, purifyConfig) }} />
    </article>
  );
}
// {/fact}

// Example 8: Using React's safe text rendering instead of HTML
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8() {
  const [message, setMessage] = useState('');
  
  useEffect(() => {
    axios.get('/api/messages/latest')
      .then(response => {
        setMessage(response.data.text);
      });
  }, []);
  
  // ok: typescript-react-unsanitized-method
  return <div>{message}</div>;
}
// {/fact}

// Example 9: Using a custom sanitization function
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9() {
  const [userHtml, setUserHtml] = useState('');
  
  useEffect(() => {
    axios.get('/api/user-content')
      .then(response => {
        setUserHtml(response.data.html);
      });
  }, []);
  
  const sanitizeHtml = (html: string): string => {
    // Using DOMPurify under the hood
    return DOMPurify.sanitize(html, {
      FORBID_TAGS: ['script', 'style', 'iframe'],
      FORBID_ATTR: ['onerror', 'onload', 'onclick']
    });
  };
  
  return (
    <div>
      {/* ok: typescript-react-unsanitized-method */}
      <div dangerouslySetInnerHTML={{ __html: sanitizeHtml(userHtml) }} />
    </div>
  );
}
// {/fact}

// Example 10: Using sanitized HTML with a loading state
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10() {
  const [content, setContent] = useState('');
  const [isLoading, setIsLoading] = useState(true);
  
  useEffect(() => {
    axios.get('/api/rich-content')
      .then(response => {
        setContent(response.data.html);
        setIsLoading(false);
      });
  }, []);
  
  if (isLoading) {
    return <div>Loading...</div>;
  }
  
  return (
    <div className="rich-content">
      {/* ok: typescript-react-unsanitized-method */}
      <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(content) }} />
    </div>
  );
}
// {/fact}

// Example 11: Using a third-party sanitization library (still DOMPurify in this case)
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11() {
  const [commentHtml, setCommentHtml] = useState('');
  
  useEffect(() => {
    const ws = new WebSocket('wss://example.com/comments');
    
    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      setCommentHtml(data.html);
    };
    
    return () => {
      ws.close();
    };
  }, []);
  
  // Sanitize with additional hooks for links
  const sanitizedHtml = DOMPurify.sanitize(commentHtml, {
    ADD_ATTR: ['target'],
    FORCE_BODY: true
  });
  
  return (
    <div className="comment">
      {/* ok: typescript-react-unsanitized-method */}
      <div dangerouslySetInnerHTML={{ __html: sanitizedHtml }} />
    </div>
  );
}
// {/fact}

// Example 12: Using server-side sanitized content (still sanitizing client-side for defense in depth)
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12() {
  const [serverSanitizedHtml, setServerSanitizedHtml] = useState('');
  
  useEffect(() => {
    axios.get('/api/pre-sanitized-content')
      .then(response => {
        // Even though server claims this is sanitized, we sanitize again
        setServerSanitizedHtml(response.data.sanitizedHtml);
      });
  }, []);
  
  return (
    <div>
      {/* ok: typescript-react-unsanitized-method */}
      <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(serverSanitizedHtml) }} />
    </div>
  );
}
// {/fact}

// Example 13: Using a custom React component to render sanitized HTML
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13() {
  const [htmlContent, setHtmlContent] = useState('');
  
  useEffect(() => {
    axios.get('/api/html-snippet')
      .then(response => {
        setHtmlContent(response.data.html);
      });
  }, []);
  
  // Custom component that sanitizes HTML
  const SafeHTML: React.FC<{ html: string }> = ({ html }) => {
    const sanitizedHtml = DOMPurify.sanitize(html);
    return <div dangerouslySetInnerHTML={{ __html: sanitizedHtml }} />;
  };
  
  return (
    <div className="content-container">
      {/* ok: typescript-react-unsanitized-method */}
      <SafeHTML html={htmlContent} />
    </div>
  );
}
// {/fact}

// Example 14: Using a memo to sanitize HTML only when content changes
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14() {
  const [rawHtml, setRawHtml] = useState('');
  
  useEffect(() => {
    axios.get('/api/dynamic-content')
      .then(response => {
        setRawHtml(response.data.html);
      });
  }, []);
  
  // Memoize the sanitized HTML to avoid unnecessary re-sanitization
  const sanitizedHtml = React.useMemo(() => {
    return DOMPurify.sanitize(rawHtml);
  }, [rawHtml]);
  
  return (
    <div>
      {/* ok: typescript-react-unsanitized-method */}
      <div dangerouslySetInnerHTML={{ __html: sanitizedHtml }} />
    </div>
  );
}
// {/fact}

// Example 15: Using sanitized HTML with error handling
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15() {
  const [content, setContent] = useState('');
  const [error, setError] = useState<string | null>(null);
  
  useEffect(() => {
    axios.get('/api/user-generated-content')
      .then(response => {
        setContent(response.data.html);
      })
      .catch(err => {
        setError('Failed to load content');
        console.error(err);
      });
  }, []);
  
  if (error) {
    return <div className="error">{error}</div>;
  }
  
  try {
    const sanitizedContent = DOMPurify.sanitize(content);
    return (
      <div>
        {/* ok: typescript-react-unsanitized-method */}
        <div dangerouslySetInnerHTML={{ __html: sanitizedContent }} />
      </div>
    );
  } catch (e) {
    return <div className="error">Error sanitizing content</div>;
  }
}
// {/fact}