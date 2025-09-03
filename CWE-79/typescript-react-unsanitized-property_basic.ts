import React, { useState, useEffect } from 'react';
import axios from 'axios';
import DOMPurify from 'dompurify';

// True Positives (Vulnerable Code)

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1() {
  const [userData, setUserData] = useState({ name: '', bio: '' });

  useEffect(() => {
    axios.get('/api/user-profile')
      .then(response => {
        setUserData(response.data);
      })
      .catch(error => console.error('Error fetching user data:', error));
  }, []);

  return (
    <div>
      <h1>{userData.name}</h1>
      {/* ruleid: typescript-react-unsanitized-property */}
      <div dangerouslySetInnerHTML={{ __html: userData.bio }} />
    </div>
  );
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2() {
  const [comment, setComment] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const userInput = (document.getElementById('commentInput') as HTMLInputElement).value;
    setComment(userInput);
  };

  return (
    <div>
      <form onSubmit={handleSubmit}>
        <input id="commentInput" type="text" placeholder="Leave a comment" />
        <button type="submit">Post</button>
      </form>
      {/* ruleid: typescript-react-unsanitized-property */}
      <div dangerouslySetInnerHTML={{ __html: comment }} />
    </div>
  );
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3() {
  const [productDescription, setProductDescription] = useState('');

  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const productId = urlParams.get('id');
    
    axios.get(`/api/products/${productId}`)
      .then(response => {
        setProductDescription(response.data.description);
      })
      .catch(error => console.error('Error fetching product:', error));
  }, []);

  return (
    <div className="product-page">
      {/* ruleid: typescript-react-unsanitized-property */}
      <div dangerouslySetInnerHTML={{ __html: productDescription }} />
    </div>
  );
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4() {
  const [articleContent, setArticleContent] = useState('');

  useEffect(() => {
    const fetchArticle = async () => {
      try {
        const response = await fetch('/api/articles/latest');
        const data = await response.json();
        setArticleContent(data.content);
      } catch (error) {
        console.error('Error fetching article:', error);
      }
    };
    
    fetchArticle();
  }, []);

  return (
    <article>
      {/* ruleid: typescript-react-unsanitized-property */}
      <div dangerouslySetInnerHTML={{ __html: articleContent }} />
    </article>
  );
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5() {
  const [notificationHtml, setNotificationHtml] = useState('');
  
  useEffect(() => {
    axios.get('/api/notifications')
      .then(response => {
        setNotificationHtml(response.data.message);
      })
      .catch(error => console.error('Error fetching notification:', error));
  }, []);

  return (
    <div className="notification-panel">
      {/* ruleid: typescript-react-unsanitized-property */}
      <div dangerouslySetInnerHTML={{ __html: notificationHtml }} />
    </div>
  );
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6() {
  const [helpText, setHelpText] = useState('');

  const loadHelpText = () => {
    const helpId = (document.getElementById('helpTopic') as HTMLSelectElement).value;
    
    axios.get(`/api/help/${helpId}`)
      .then(response => {
        setHelpText(response.data.content);
      })
      .catch(error => console.error('Error loading help text:', error));
  };

  return (
    <div>
      <select id="helpTopic" onChange={loadHelpText}>
        <option value="account">Account</option>
        <option value="billing">Billing</option>
      </select>
      {/* ruleid: typescript-react-unsanitized-property */}
      <div dangerouslySetInnerHTML={{ __html: helpText }} />
    </div>
  );
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7() {
  const [reviewContent, setReviewContent] = useState('');

  useEffect(() => {
    const headers = new Headers();
    headers.append('Content-Type', 'application/json');
    
    fetch('/api/reviews/featured', { headers })
      .then(response => response.json())
      .then(data => {
        setReviewContent(data.content);
      })
      .catch(error => console.error('Error fetching review:', error));
  }, []);

  return (
    <section className="featured-review">
      {/* ruleid: typescript-react-unsanitized-property */}
      <div dangerouslySetInnerHTML={{ __html: reviewContent }} />
    </section>
  );
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8() {
  const [faqAnswer, setFaqAnswer] = useState('');

  const handleFaqClick = (questionId: string) => {
    axios.get(`/api/faq/${questionId}`)
      .then(response => {
        setFaqAnswer(response.data.answer);
      })
      .catch(error => console.error('Error fetching FAQ answer:', error));
  };

  return (
    <div className="faq-section">
      <button onClick={() => handleFaqClick('q1')}>What is your return policy?</button>
      {/* ruleid: typescript-react-unsanitized-property */}
      <div className="answer" dangerouslySetInnerHTML={{ __html: faqAnswer }} />
    </div>
  );
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9() {
  const [termsContent, setTermsContent] = useState('');

  useEffect(() => {
    const fetchTerms = async () => {
      try {
        const response = await axios.get('/api/legal/terms', {
          headers: { 'Accept-Language': navigator.language }
        });
        setTermsContent(response.data.content);
      } catch (error) {
        console.error('Error fetching terms:', error);
      }
    };
    
    fetchTerms();
  }, []);

  return (
    <div className="legal-terms">
      {/* ruleid: typescript-react-unsanitized-property */}
      <div dangerouslySetInnerHTML={{ __html: termsContent }} />
    </div>
  );
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10() {
  const [messageContent, setMessageContent] = useState('');

  useEffect(() => {
    const socket = new WebSocket('wss://example.com/chat');
    
    socket.onmessage = (event) => {
      const data = JSON.parse(event.data);
      setMessageContent(data.message);
    };
    
    return () => socket.close();
  }, []);

  return (
    <div className="chat-message">
      {/* ruleid: typescript-react-unsanitized-property */}
      <div dangerouslySetInnerHTML={{ __html: messageContent }} />
    </div>
  );
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11() {
  const [tutorialSteps, setTutorialSteps] = useState<Array<{title: string, content: string}>>([]);
  const [currentStep, setCurrentStep] = useState(0);

  useEffect(() => {
    axios.get('/api/tutorial')
      .then(response => {
        setTutorialSteps(response.data.steps);
      })
      .catch(error => console.error('Error fetching tutorial:', error));
  }, []);

  return (
    <div className="tutorial">
      {tutorialSteps.length > 0 && (
        <>
          <h2>{tutorialSteps[currentStep].title}</h2>
          {/* ruleid: typescript-react-unsanitized-property */}
          <div dangerouslySetInnerHTML={{ __html: tutorialSteps[currentStep].content }} />
        </>
      )}
    </div>
  );
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12() {
  const [emailTemplate, setEmailTemplate] = useState('');

  const loadTemplate = (templateId: string) => {
    axios.get(`/api/email-templates/${templateId}`)
      .then(response => {
        setEmailTemplate(response.data.html);
      })
      .catch(error => console.error('Error loading template:', error));
  };

  return (
    <div className="email-preview">
      <button onClick={() => loadTemplate('welcome')}>Preview Welcome Email</button>
      {/* ruleid: typescript-react-unsanitized-property */}
      <div dangerouslySetInnerHTML={{ __html: emailTemplate }} />
    </div>
  );
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13() {
  const [widgetContent, setWidgetContent] = useState('');

  useEffect(() => {
    const widgetId = new URLSearchParams(window.location.search).get('widgetId');
    
    if (widgetId) {
      fetch(`/api/widgets/${widgetId}`)
        .then(response => response.json())
        .then(data => {
          setWidgetContent(data.html);
        })
        .catch(error => console.error('Error loading widget:', error));
    }
  }, []);

  return (
    <div className="widget-container">
      {/* ruleid: typescript-react-unsanitized-property */}
      <div dangerouslySetInnerHTML={{ __html: widgetContent }} />
    </div>
  );
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14() {
  const [adContent, setAdContent] = useState('');

  useEffect(() => {
    axios.get('/api/advertisements/current', {
      headers: {
        'User-Agent': navigator.userAgent
      }
    })
      .then(response => {
        setAdContent(response.data.html);
      })
      .catch(error => console.error('Error fetching advertisement:', error));
  }, []);

  return (
    <aside className="sidebar-ad">
      {/* ruleid: typescript-react-unsanitized-property */}
      <div dangerouslySetInnerHTML={{ __html: adContent }} />
    </aside>
  );
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15() {
  const [commentThreadHtml, setCommentThreadHtml] = useState('');

  const loadComments = (postId: string) => {
    axios.get(`/api/posts/${postId}/comments`)
      .then(response => {
        // The API returns pre-formatted HTML for the entire comment thread
        setCommentThreadHtml(response.data.threadHtml);
      })
      .catch(error => console.error('Error loading comments:', error));
  };

  return (
    <section className="comments">
      <button onClick={() => loadComments('post123')}>Load Comments</button>
      {/* ruleid: typescript-react-unsanitized-property */}
      <div dangerouslySetInnerHTML={{ __html: commentThreadHtml }} />
    </section>
  );
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1() {
  const [userData, setUserData] = useState({ name: '', bio: '' });

  useEffect(() => {
    axios.get('/api/user-profile')
      .then(response => {
        setUserData(response.data);
      })
      .catch(error => console.error('Error fetching user data:', error));
  }, []);

  // ok: typescript-react-unsanitized-property
  const sanitizedBio = DOMPurify.sanitize(userData.bio);

  return (
    <div>
      <h1>{userData.name}</h1>
      <div dangerouslySetInnerHTML={{ __html: sanitizedBio }} />
    </div>
  );
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2() {
  const [comment, setComment] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const userInput = (document.getElementById('commentInput') as HTMLInputElement).value;
    setComment(userInput);
  };

  // Render the comment as text, not HTML
  return (
    <div>
      <form onSubmit={handleSubmit}>
        <input id="commentInput" type="text" placeholder="Leave a comment" />
        <button type="submit">Post</button>
      </form>
      {/* ok: typescript-react-unsanitized-property */}
      <div>{comment}</div>
    </div>
  );
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3() {
  const [productDescription, setProductDescription] = useState('');

  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const productId = urlParams.get('id');
    
    axios.get(`/api/products/${productId}`)
      .then(response => {
        setProductDescription(response.data.description);
      })
      .catch(error => console.error('Error fetching product:', error));
  }, []);

  // ok: typescript-react-unsanitized-property
  const cleanDescription = DOMPurify.sanitize(productDescription);

  return (
    <div className="product-page">
      <div dangerouslySetInnerHTML={{ __html: cleanDescription }} />
    </div>
  );
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4() {
  const [articleContent, setArticleContent] = useState('');

  useEffect(() => {
    const fetchArticle = async () => {
      try {
        const response = await fetch('/api/articles/latest');
        const data = await response.json();
        setArticleContent(data.content);
      } catch (error) {
        console.error('Error fetching article:', error);
      }
    };
    
    fetchArticle();
  }, []);

  // ok: typescript-react-unsanitized-property
  const sanitizedContent = DOMPurify.sanitize(articleContent, { 
    ALLOWED_TAGS: ['p', 'b', 'i', 'em', 'strong', 'a', 'ul', 'ol', 'li'],
    ALLOWED_ATTR: ['href']
  });

  return (
    <article>
      <div dangerouslySetInnerHTML={{ __html: sanitizedContent }} />
    </article>
  );
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5() {
  const [notificationHtml, setNotificationHtml] = useState('');
  
  useEffect(() => {
    axios.get('/api/notifications')
      .then(response => {
        setNotificationHtml(response.data.message);
      })
      .catch(error => console.error('Error fetching notification:', error));
  }, []);

  // Using a library to sanitize the HTML
  // ok: typescript-react-unsanitized-property
  const sanitizedNotification = DOMPurify.sanitize(notificationHtml);

  return (
    <div className="notification-panel">
      <div dangerouslySetInnerHTML={{ __html: sanitizedNotification }} />
    </div>
  );
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6() {
  const [helpText, setHelpText] = useState('');

  const loadHelpText = () => {
    const helpId = (document.getElementById('helpTopic') as HTMLSelectElement).value;
    
    axios.get(`/api/help/${helpId}`)
      .then(response => {
        setHelpText(response.data.content);
      })
      .catch(error => console.error('Error loading help text:', error));
  };

  // ok: typescript-react-unsanitized-property
  const sanitizedHelpText = DOMPurify.sanitize(helpText);

  return (
    <div>
      <select id="helpTopic" onChange={loadHelpText}>
        <option value="account">Account</option>
        <option value="billing">Billing</option>
      </select>
      <div dangerouslySetInnerHTML={{ __html: sanitizedHelpText }} />
    </div>
  );
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7() {
  // Using hardcoded HTML is safe
  const staticHtml = '<p>Welcome to our <strong>secure</strong> application!</p>';

  return (
    <div>
      {/* ok: typescript-react-unsanitized-property */}
      <div dangerouslySetInnerHTML={{ __html: staticHtml }} />
    </div>
  );
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8() {
  const [reviewContent, setReviewContent] = useState('');

  useEffect(() => {
    fetch('/api/reviews/featured')
      .then(response => response.json())
      .then(data => {
        setReviewContent(data.content);
      })
      .catch(error => console.error('Error fetching review:', error));
  }, []);

  // ok: typescript-react-unsanitized-property
  // Using React's built-in escaping by not using dangerouslySetInnerHTML
  return (
    <section className="featured-review">
      <p>{reviewContent}</p>
    </section>
  );
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9() {
  const [faqAnswer, setFaqAnswer] = useState('');

  const handleFaqClick = (questionId: string) => {
    axios.get(`/api/faq/${questionId}`)
      .then(response => {
        setFaqAnswer(response.data.answer);
      })
      .catch(error => console.error('Error fetching FAQ answer:', error));
  };

  // ok: typescript-react-unsanitized-property
  const sanitizedAnswer = DOMPurify.sanitize(faqAnswer);

  return (
    <div className="faq-section">
      <button onClick={() => handleFaqClick('q1')}>What is your return policy?</button>
      <div className="answer" dangerouslySetInnerHTML={{ __html: sanitizedAnswer }} />
    </div>
  );
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10() {
  const [messageContent, setMessageContent] = useState('');

  useEffect(() => {
    const socket = new WebSocket('wss://example.com/chat');
    
    socket.onmessage = (event) => {
      const data = JSON.parse(event.data);
      setMessageContent(data.message);
    };
    
    return () => socket.close();
  }, []);

  // ok: typescript-react-unsanitized-property
  // Render as text, not HTML
  return (
    <div className="chat-message">
      <p>{messageContent}</p>
    </div>
  );
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11() {
  const [tutorialSteps, setTutorialSteps] = useState<Array<{title: string, content: string}>>([]);
  const [currentStep, setCurrentStep] = useState(0);

  useEffect(() => {
    axios.get('/api/tutorial')
      .then(response => {
        setTutorialSteps(response.data.steps);
      })
      .catch(error => console.error('Error fetching tutorial:', error));
  }, []);

  // ok: typescript-react-unsanitized-property
  const sanitizeContent = (html: string) => DOMPurify.sanitize(html);

  return (
    <div className="tutorial">
      {tutorialSteps.length > 0 && (
        <>
          <h2>{tutorialSteps[currentStep].title}</h2>
          <div dangerouslySetInnerHTML={{ __html: sanitizeContent(tutorialSteps[currentStep].content) }} />
        </>
      )}
    </div>
  );
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12() {
  const [emailTemplate, setEmailTemplate] = useState('');

  const loadTemplate = (templateId: string) => {
    axios.get(`/api/email-templates/${templateId}`)
      .then(response => {
        setEmailTemplate(response.data.html);
      })
      .catch(error => console.error('Error loading template:', error));
  };

  // ok: typescript-react-unsanitized-property
  const sanitizedTemplate = DOMPurify.sanitize(emailTemplate, {
    ALLOWED_TAGS: ['p', 'div', 'span', 'a', 'img', 'h1', 'h2', 'h3', 'ul', 'ol', 'li'],
    ALLOWED_ATTR: ['href', 'src', 'alt', 'style', 'class']
  });

  return (
    <div className="email-preview">
      <button onClick={() => loadTemplate('welcome')}>Preview Welcome Email</button>
      <div dangerouslySetInnerHTML={{ __html: sanitizedTemplate }} />
    </div>
  );
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13() {
  // Using a custom sanitizer function
  // ok: typescript-react-unsanitized-property
  const sanitizeHtml = (html: string): string => {
    const tempDiv = document.createElement('div');
    tempDiv.innerHTML = html;
    
    // Remove all script tags
    const scripts = tempDiv.getElementsByTagName('script');
    while (scripts[0]) {
      scripts[0].parentNode?.removeChild(scripts[0]);
    }
    
    // Remove on* attributes
    const elements = tempDiv.getElementsByTagName('*');
    for (let i = 0; i < elements.length; i++) {
      const attrs = elements[i].attributes;
      for (let j = attrs.length - 1; j >= 0; j--) {
        if (attrs[j].name.startsWith('on')) {
          elements[i].removeAttribute(attrs[j].name);
        }
      }
    }
    
    return tempDiv.innerHTML;
  };

  const [widgetContent, setWidgetContent] = useState('');

  useEffect(() => {
    const widgetId = new URLSearchParams(window.location.search).get('widgetId');
    
    if (widgetId) {
      fetch(`/api/widgets/${widgetId}`)
        .then(response => response.json())
        .then(data => {
          setWidgetContent(data.html);
        })
        .catch(error => console.error('Error loading widget:', error));
    }
  }, []);

  return (
    <div className="widget-container">
      <div dangerouslySetInnerHTML={{ __html: sanitizeHtml(widgetContent) }} />
    </div>
  );
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14() {
  const [adContent, setAdContent] = useState('');

  useEffect(() => {
    axios.get('/api/advertisements/current')
      .then(response => {
        setAdContent(response.data.html);
      })
      .catch(error => console.error('Error fetching advertisement:', error));
  }, []);

  // ok: typescript-react-unsanitized-property
  const sanitizedAd = DOMPurify.sanitize(adContent, {
    ADD_TAGS: ['iframe'],
    ADD_ATTR: ['allow', 'allowfullscreen', 'frameborder', 'scrolling']
  });

  return (
    <aside className="sidebar-ad">
      <div dangerouslySetInnerHTML={{ __html: sanitizedAd }} />
    </aside>
  );
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15() {
  // Using a trusted, hardcoded HTML template with dynamic data inserted safely
  const createSafeHtml = (username: string, joinDate: string): string => {
    // ok: typescript-react-unsanitized-property
    const template = `
      <div class="user-card">
        <h3>Welcome, ${DOMPurify.sanitize(username)}</h3>
        <p>Member since: ${DOMPurify.sanitize(joinDate)}</p>
      </div>
    `;
    return template;
  };

  const [user, setUser] = useState({ name: '', joinDate: '' });

  useEffect(() => {
    axios.get('/api/current-user')
      .then(response => {
        setUser({
          name: response.data.username,
          joinDate: response.data.joinDate
        });
      })
      .catch(error => console.error('Error fetching user data:', error));
  }, []);

  const userCardHtml = createSafeHtml(user.name, user.joinDate);

  return (
    <div dangerouslySetInnerHTML={{ __html: userCardHtml }} />
  );
}
// {/fact}

export {
  bad_case_1, bad_case_2, bad_case_3, bad_case_4, bad_case_5,
  bad_case_6, bad_case_7, bad_case_8, bad_case_9, bad_case_10,
  bad_case_11, bad_case_12, bad_case_13, bad_case_14, bad_case_15,
  good_case_1, good_case_2, good_case_3, good_case_4, good_case_5,
  good_case_6, good_case_7, good_case_8, good_case_9, good_case_10,
  good_case_11, good_case_12, good_case_13, good_case_14, good_case_15
};