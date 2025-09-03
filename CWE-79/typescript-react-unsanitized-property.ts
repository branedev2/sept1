import React, { useState, useEffect } from 'react';
import DOMPurify from 'dompurify';
import axios from 'axios';

// TRUE POSITIVES (Vulnerable code)

// Bad case 1: Directly using dangerouslySetInnerHTML with user input
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1() {
  const [userData, setUserData] = useState<string>('');
  
  useEffect(() => {
    axios.get('/api/user-profile')
      .then(response => {
        setUserData(response.data.bio);
      });
  }, []);

  return (
    <div 
      // ruleid: typescript-react-unsanitized-property
      dangerouslySetInnerHTML={{ __html: userData }} 
    />
  );
}
// {/fact}

// Bad case 2: Using dangerouslySetInnerHTML with URL parameter
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2() {
  const [content, setContent] = useState<string>('');
  
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const htmlContent = urlParams.get('content') || '';
    setContent(htmlContent);
  }, []);

  return (
    <div 
      // ruleid: typescript-react-unsanitized-property
      dangerouslySetInnerHTML={{ __html: content }}
    />
  );
}
// {/fact}

// Bad case 3: Using dangerouslySetInnerHTML with localStorage data
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3() {
  const [savedContent, setSavedContent] = useState<string>('');
  
  useEffect(() => {
    const content = localStorage.getItem('userGeneratedContent') || '';
    setSavedContent(content);
  }, []);

  return (
    <div 
      // ruleid: typescript-react-unsanitized-property
      dangerouslySetInnerHTML={{ __html: savedContent }}
    />
  );
}
// {/fact}

// Bad case 4: Using dangerouslySetInnerHTML with data from an API
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4() {
  const [articleContent, setArticleContent] = useState<string>('');
  
  useEffect(() => {
    axios.get('/api/articles/1')
      .then(response => {
        setArticleContent(response.data.content);
      });
  }, []);

  const ArticleBody = () => (
    <section 
      // ruleid: typescript-react-unsanitized-property
      dangerouslySetInnerHTML={{ __html: articleContent }}
    />
  );
  
  return <ArticleBody />;
}
// {/fact}

// Bad case 5: Using dangerouslySetInnerHTML with form input
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5() {
  const [commentText, setCommentText] = useState<string>('');
  const [comments, setComments] = useState<string[]>([]);
  
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setComments([...comments, commentText]);
    setCommentText('');
  };
  
  return (
    <>
      <form onSubmit={handleSubmit}>
        <textarea 
          value={commentText}
          onChange={(e) => setCommentText(e.target.value)}
        />
        <button type="submit">Post Comment</button>
      </form>
      
      {comments.map((comment, index) => (
        <div 
          key={index}
          // ruleid: typescript-react-unsanitized-property
          dangerouslySetInnerHTML={{ __html: comment }}
        />
      ))}
    </>
  );
}
// {/fact}

// Bad case 6: Using dangerouslySetInnerHTML with sessionStorage data
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6() {
  const [editorContent, setEditorContent] = useState<string>('');
  
  useEffect(() => {
    const savedContent = sessionStorage.getItem('editorContent') || '';
    setEditorContent(savedContent);
  }, []);
  
  return (
    <div className="preview-panel">
      <h2>Preview</h2>
      <div 
        // ruleid: typescript-react-unsanitized-property
        dangerouslySetInnerHTML={{ __html: editorContent }}
      />
    </div>
  );
}
// {/fact}

// Bad case 7: Using dangerouslySetInnerHTML with data from WebSocket
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7() {
  const [messageContent, setMessageContent] = useState<string>('');
  
  useEffect(() => {
    const ws = new WebSocket('wss://example.com/chat');
    
    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      setMessageContent(data.message);
    };
    
    return () => ws.close();
  }, []);
  
  return (
    <div className="message-container">
      <div 
        // ruleid: typescript-react-unsanitized-property
        dangerouslySetInnerHTML={{ __html: messageContent }}
      />
    </div>
  );
}
// {/fact}

// Bad case 8: Using dangerouslySetInnerHTML with cookie data
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8() {
  const [notificationHtml, setNotificationHtml] = useState<string>('');
  
  useEffect(() => {
    const getCookieValue = (name: string) => {
      const cookies = document.cookie.split(';');
      for (const cookie of cookies) {
        const [cookieName, cookieValue] = cookie.trim().split('=');
        if (cookieName === name) {
          return decodeURIComponent(cookieValue);
        }
      }
      return '';
    };
    
    setNotificationHtml(getCookieValue('notification_message'));
  }, []);
  
  return (
    <div className="notification-banner"
      // ruleid: typescript-react-unsanitized-property
      dangerouslySetInnerHTML={{ __html: notificationHtml }}
    />
  );
}
// {/fact}

// Bad case 9: Using dangerouslySetInnerHTML with data from IndexedDB
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9() {
  const [userNote, setUserNote] = useState<string>('');
  
  useEffect(() => {
    const request = indexedDB.open('NotesDB', 1);
    
    request.onsuccess = (event) => {
      const db = request.result;
      const transaction = db.transaction(['notes'], 'readonly');
      const objectStore = transaction.objectStore('notes');
      const noteRequest = objectStore.get(1);
      
      noteRequest.onsuccess = () => {
        if (noteRequest.result) {
          setUserNote(noteRequest.result.content);
        }
      };
    };
  }, []);
  
  return (
    <div className="note-display"
      // ruleid: typescript-react-unsanitized-property
      dangerouslySetInnerHTML={{ __html: userNote }}
    />
  );
}
// {/fact}

// Bad case 10: Using dangerouslySetInnerHTML with data from postMessage
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10() {
  const [iframeContent, setIframeContent] = useState<string>('');
  
  useEffect(() => {
    const handleMessage = (event: MessageEvent) => {
      // Normally you'd validate the origin, but this is intentionally vulnerable
      setIframeContent(event.data.html);
    };
    
    window.addEventListener('message', handleMessage);
    return () => window.removeEventListener('message', handleMessage);
  }, []);
  
  return (
    <div className="iframe-content"
      // ruleid: typescript-react-unsanitized-property
      dangerouslySetInnerHTML={{ __html: iframeContent }}
    />
  );
}
// {/fact}

// Bad case 11: Using dangerouslySetInnerHTML with data from file upload
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11() {
  const [fileContent, setFileContent] = useState<string>('');
  
  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (event) => {
        setFileContent(event.target?.result as string);
      };
      reader.readAsText(file);
    }
  };
  
  return (
    <>
      <input type="file" onChange={handleFileUpload} />
      <div 
        // ruleid: typescript-react-unsanitized-property
        dangerouslySetInnerHTML={{ __html: fileContent }}
      />
    </>
  );
}
// {/fact}

// Bad case 12: Using dangerouslySetInnerHTML with data from a third-party API
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12() {
  const [externalContent, setExternalContent] = useState<string>('');
  
  useEffect(() => {
    axios.get('https://external-api.example.com/widget-content')
      .then(response => {
        setExternalContent(response.data.html);
      });
  }, []);
  
  return (
    <div className="external-widget"
      // ruleid: typescript-react-unsanitized-property
      dangerouslySetInnerHTML={{ __html: externalContent }}
    />
  );
}
// {/fact}

// Bad case 13: Using dangerouslySetInnerHTML with data from URL hash fragment
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13() {
  const [hashContent, setHashContent] = useState<string>('');
  
  useEffect(() => {
    const handleHashChange = () => {
      const hash = window.location.hash.substring(1); // Remove the # character
      setHashContent(decodeURIComponent(hash));
    };
    
    window.addEventListener('hashchange', handleHashChange);
    handleHashChange(); // Initial call
    
    return () => window.removeEventListener('hashchange', handleHashChange);
  }, []);
  
  return (
    <div 
      // ruleid: typescript-react-unsanitized-property
      dangerouslySetInnerHTML={{ __html: hashContent }}
    />
  );
}
// {/fact}

// Bad case 14: Using dangerouslySetInnerHTML with data from a parent component via props
interface MarkupDisplayProps {
  htmlContent: string;
}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14() {
  const [dynamicHtml, setDynamicHtml] = useState<string>('');
  
  useEffect(() => {
    axios.get('/api/dynamic-content')
      .then(response => {
        setDynamicHtml(response.data.html);
      });
  }, []);
  
  const MarkupDisplay: React.FC<MarkupDisplayProps> = ({ htmlContent }) => (
    <div 
      // ruleid: typescript-react-unsanitized-property
      dangerouslySetInnerHTML={{ __html: htmlContent }}
    />
  );
  
  return <MarkupDisplay htmlContent={dynamicHtml} />;
}
// {/fact}

// Bad case 15: Using dangerouslySetInnerHTML with data from browser history state
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15() {
  const [historyContent, setHistoryContent] = useState<string>('');
  
  useEffect(() => {
    const handlePopState = (event: PopStateEvent) => {
      if (event.state && event.state.content) {
        setHistoryContent(event.state.content);
      }
    };
    
    window.addEventListener('popstate', handlePopState);
    
    // Initial check
    if (window.history.state && window.history.state.content) {
      setHistoryContent(window.history.state.content);
    }
    
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);
  
  return (
    <div 
      // ruleid: typescript-react-unsanitized-property
      dangerouslySetInnerHTML={{ __html: historyContent }}
    />
  );
}
// {/fact}

// TRUE NEGATIVES (Safe code)

// Good case 1: Using DOMPurify to sanitize user input
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1() {
  const [userData, setUserData] = useState<string>('');
  
  useEffect(() => {
    axios.get('/api/user-profile')
      .then(response => {
        setUserData(response.data.bio);
      });
  }, []);

  return (
    <div 
      // ok: typescript-react-unsanitized-property
      dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userData) }} 
    />
  );
}
// {/fact}

// Good case 2: Using DOMPurify to sanitize URL parameter
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2() {
  const [content, setContent] = useState<string>('');
  
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const htmlContent = urlParams.get('content') || '';
    setContent(htmlContent);
  }, []);

  return (
    <div 
      // ok: typescript-react-unsanitized-property
      dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(content) }}
    />
  );
}
// {/fact}

// Good case 3: Using DOMPurify to sanitize localStorage data
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3() {
  const [savedContent, setSavedContent] = useState<string>('');
  
  useEffect(() => {
    const content = localStorage.getItem('userGeneratedContent') || '';
    setSavedContent(content);
  }, []);

  return (
    <div 
      // ok: typescript-react-unsanitized-property
      dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(savedContent) }}
    />
  );
}
// {/fact}

// Good case 4: Using DOMPurify to sanitize API data
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4() {
  const [articleContent, setArticleContent] = useState<string>('');
  
  useEffect(() => {
    axios.get('/api/articles/1')
      .then(response => {
        setArticleContent(response.data.content);
      });
  }, []);

  const ArticleBody = () => (
    <section 
      // ok: typescript-react-unsanitized-property
      dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(articleContent) }}
    />
  );
  
  return <ArticleBody />;
}
// {/fact}

// Good case 5: Using DOMPurify to sanitize form input
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5() {
  const [commentText, setCommentText] = useState<string>('');
  const [comments, setComments] = useState<string[]>([]);
  
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setComments([...comments, commentText]);
    setCommentText('');
  };
  
  return (
    <>
      <form onSubmit={handleSubmit}>
        <textarea 
          value={commentText}
          onChange={(e) => setCommentText(e.target.value)}
        />
        <button type="submit">Post Comment</button>
      </form>
      
      {comments.map((comment, index) => (
        <div 
          key={index}
          // ok: typescript-react-unsanitized-property
          dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(comment) }}
        />
      ))}
    </>
  );
}
// {/fact}

// Good case 6: Using hardcoded HTML (safe)
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6() {
  const staticHtml = '<p>This is <strong>static</strong> HTML content</p>';
  
  return (
    <div 
      // ok: typescript-react-unsanitized-property
      dangerouslySetInnerHTML={{ __html: staticHtml }}
    />
  );
}
// {/fact}

// Good case 7: Using React's built-in escaping by rendering text directly
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7() {
  const [userData, setUserData] = useState<string>('');
  
  useEffect(() => {
    axios.get('/api/user-profile')
      .then(response => {
        setUserData(response.data.bio);
      });
  }, []);

  // ok: typescript-react-unsanitized-property
  return <div>{userData}</div>;
}
// {/fact}

// Good case 8: Using a custom sanitizer function
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8() {
  const [messageContent, setMessageContent] = useState<string>('');
  
  useEffect(() => {
    const ws = new WebSocket('wss://example.com/chat');
    
    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      setMessageContent(data.message);
    };
    
    return () => ws.close();
  }, []);
  
  const sanitizeHtml = (html: string): string => {
    return DOMPurify.sanitize(html, { 
      ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br'],
      ALLOWED_ATTR: ['href']
    });
  };
  
  return (
    <div className="message-container">
      <div 
        // ok: typescript-react-unsanitized-property
        dangerouslySetInnerHTML={{ __html: sanitizeHtml(messageContent) }}
      />
    </div>
  );
}
// {/fact}

// Good case 9: Using DOMPurify with configuration options
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9() {
  const [userNote, setUserNote] = useState<string>('');
  
  useEffect(() => {
    const request = indexedDB.open('NotesDB', 1);
    
    request.onsuccess = (event) => {
      const db = request.result;
      const transaction = db.transaction(['notes'], 'readonly');
      const objectStore = transaction.objectStore('notes');
      const noteRequest = objectStore.get(1);
      
      noteRequest.onsuccess = () => {
        if (noteRequest.result) {
          setUserNote(noteRequest.result.content);
        }
      };
    };
  }, []);
  
  return (
    <div className="note-display"
      // ok: typescript-react-unsanitized-property
      dangerouslySetInnerHTML={{ 
        __html: DOMPurify.sanitize(userNote, {
          FORBID_TAGS: ['script', 'style', 'iframe'],
          FORBID_ATTR: ['onerror', 'onload', 'onclick']
        }) 
      }}
    />
  );
}
// {/fact}

// Good case 10: Using a third-party sanitizer library
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10() {
  const [iframeContent, setIframeContent] = useState<string>('');
  
  useEffect(() => {
    const handleMessage = (event: MessageEvent) => {
      if (event.origin === 'https://trusted-source.com') {
        setIframeContent(event.data.html);
      }
    };
    
    window.addEventListener('message', handleMessage);
    return () => window.removeEventListener('message', handleMessage);
  }, []);
  
  // Simulating another sanitizer library
  const sanitizeWithExternalLibrary = (html: string): string => {
    // In a real app, this would be an actual third-party sanitizer
    return DOMPurify.sanitize(html);
  };
  
  return (
    <div className="iframe-content"
      // ok: typescript-react-unsanitized-property
      dangerouslySetInnerHTML={{ __html: sanitizeWithExternalLibrary(iframeContent) }}
    />
  );
}
// {/fact}

// Good case 11: Using server-side sanitized content
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11() {
  const [trustedContent, setTrustedContent] = useState<string>('');
  
  useEffect(() => {
    axios.get('/api/pre-sanitized-content')
      .then(response => {
        // This endpoint returns already sanitized HTML from the server
        setTrustedContent(response.data.sanitizedHtml);
      });
  }, []);
  
  // Using a verification function to double-check server sanitization
  const verifyTrustedContent = (html: string): string => {
    // Additional client-side verification
    if (html.includes('<script') || html.includes('javascript:')) {
      console.error('Server sanitization failed');
      return 'Sanitization error';
    }
    return html;
  };
  
  return (
    <div 
      // ok: typescript-react-unsanitized-property
      dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(verifyTrustedContent(trustedContent)) }}
    />
  );
}
// {/fact}

// Good case 12: Using a markdown parser instead of raw HTML
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12() {
  const [markdownContent, setMarkdownContent] = useState<string>('');
  
  useEffect(() => {
    axios.get('/api/markdown-content')
      .then(response => {
        setMarkdownContent(response.data.markdown);
      });
  }, []);
  
  // Simple markdown to HTML converter (in real app, use a proper library)
  const markdownToSafeHtml = (markdown: string): string => {
    // Convert markdown to HTML (simplified example)
    let html = markdown
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/\*(.*?)\*/g, '<em>$1</em>')
      .replace(/\n/g, '<br>');
    
    // Sanitize the resulting HTML to be extra safe
    return DOMPurify.sanitize(html);
  };
  
  return (
    <div 
      // ok: typescript-react-unsanitized-property
      dangerouslySetInnerHTML={{ __html: markdownToSafeHtml(markdownContent) }}
    />
  );
}
// {/fact}

// Good case 13: Using a whitelist approach for allowed HTML
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13() {
  const [userHtml, setUserHtml] = useState<string>('');
  
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const content = urlParams.get('content') || '';
    setUserHtml(content);
  }, []);
  
  const strictlySanitize = (html: string): string => {
    return DOMPurify.sanitize(html, {
      ALLOWED_TAGS: ['p', 'br', 'strong', 'em', 'ul', 'li'],
      ALLOWED_ATTR: [],
      ALLOW_DATA_ATTR: false
    });
  };
  
  return (
    <div className="user-content"
      // ok: typescript-react-unsanitized-property
      dangerouslySetInnerHTML={{ __html: strictlySanitize(userHtml) }}
    />
  );
}
// {/fact}

// Good case 14: Using a component that handles sanitization internally
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14() {
  const [htmlContent, setHtmlContent] = useState<string>('');
  
  useEffect(() => {
    axios.get('/api/content')
      .then(response => {
        setHtmlContent(response.data.html);
      });
  }, []);
  
  // A safe component that handles sanitization internally
  const SafeHtml: React.FC<{ html: string }> = ({ html }) => {
    const sanitizedHtml = DOMPurify.sanitize(html);
    
    // ok: typescript-react-unsanitized-property
    return <div dangerouslySetInnerHTML={{ __html: sanitizedHtml }} />;
  };
  
  return <SafeHtml html={htmlContent} />;
}
// {/fact}

// Good case 15: Using DOMPurify with hooks pattern
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15() {
  const [content, setContent] = useState<string>('');
  
  useEffect(() => {
    axios.get('/api/rich-content')
      .then(response => {
        setContent(response.data.html);
      });
  }, []);
  
  // Custom hook for sanitized HTML
  const useSanitizedHtml = (dirtyHtml: string) => {
    const [sanitizedHtml, setSanitizedHtml] = useState('');
    
    useEffect(() => {
      setSanitizedHtml(DOMPurify.sanitize(dirtyHtml));
    }, [dirtyHtml]);
    
    return sanitizedHtml;
  };
  
  const cleanHtml = useSanitizedHtml(content);
  
  return (
    <div 
      // ok: typescript-react-unsanitized-property
      dangerouslySetInnerHTML={{ __html: cleanHtml }}
    />
  );
}
// {/fact}