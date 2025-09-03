import React, { useState, useEffect } from 'react';
import DOMPurify from 'dompurify';
import { sanitize } from 'sanitize-html';
import { useLocation, useParams, useSearchParams } from 'react-router-dom';
import axios from 'axios';

// True Positive Examples (Vulnerable Code)

// Example 1: Direct use of URL parameter in href
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_1() {
  const [searchParams] = useSearchParams();
  const redirectUrl = searchParams.get('redirectUrl');
  
  return (
    <div>
      <h1>Welcome to our site</h1>
      {/* ruleid: javascript-react-href-var */}
      <a href={redirectUrl}>Click here to continue</a>
    </div>
  );
}
// {/fact}

// Example 2: Using state from user input
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_2() {
  const [userInput, setUserInput] = useState('');
  const [link, setLink] = useState('');
  
  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setUserInput(e.target.value);
  };
  
  const handleSubmit = () => {
    setLink(userInput);
  };
  
  return (
    <div>
      <input type="text" onChange={handleChange} placeholder="Enter URL" />
      <button onClick={handleSubmit}>Set Link</button>
      {/* ruleid: javascript-react-href-var */}
      <a href={link}>Custom Link</a>
    </div>
  );
}
// {/fact}

// Example 3: Using URL parameter with template literals
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_3() {
  const { id } = useParams<{ id: string }>();
  const location = useLocation();
  const queryParams = new URLSearchParams(location.search);
  const section = queryParams.get('section');
  
  return (
    <div>
      {/* ruleid: javascript-react-href-var */}
      <a href={`/profile/${id}#${section}`}>Go to section</a>
    </div>
  );
}
// {/fact}

// Example 4: Using data from API response
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_4() {
  const [profileData, setProfileData] = useState<{ website: string }>({ website: '' });
  
  useEffect(() => {
    axios.get('/api/user-profile')
      .then(response => {
        setProfileData(response.data);
      });
  }, []);
  
  return (
    <div>
      <h2>User Profile</h2>
      {/* ruleid: javascript-react-href-var */}
      <a href={profileData.website}>Visit Website</a>
    </div>
  );
}
// {/fact}

// Example 5: Using URL hash
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_5() {
  const [hash, setHash] = useState('');
  
  useEffect(() => {
    // Get hash from window location
    setHash(window.location.hash.substring(1));
  }, []);
  
  return (
    <div>
      {/* ruleid: javascript-react-href-var */}
      <a href={`#${hash}`}>Jump to section</a>
    </div>
  );
}
// {/fact}

// Example 6: Using query parameters with concatenation
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_6() {
  const location = useLocation();
  const queryParams = new URLSearchParams(location.search);
  const campaign = queryParams.get('campaign');
  const source = queryParams.get('source');
  
  return (
    <div>
      {/* ruleid: javascript-react-href-var */}
      <a href={'/signup?ref=' + campaign + '&source=' + source}>Sign up now</a>
    </div>
  );
}
// {/fact}

// Example 7: Using localStorage data
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_7() {
  const [savedUrl, setSavedUrl] = useState('');
  
  useEffect(() => {
    const url = localStorage.getItem('lastVisitedUrl');
    if (url) {
      setSavedUrl(url);
    }
  }, []);
  
  return (
    <div>
      {/* ruleid: javascript-react-href-var */}
      <a href={savedUrl}>Return to last page</a>
    </div>
  );
}
// {/fact}

// Example 8: Using data from form submission
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_8() {
  const [formData, setFormData] = useState({ website: '' });
  
  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };
  
  return (
    <div>
      <form>
        <input 
          type="text" 
          name="website" 
          value={formData.website} 
          onChange={handleChange} 
          placeholder="Your website"
        />
      </form>
      {/* ruleid: javascript-react-href-var */}
      <a href={formData.website}>Preview your website</a>
    </div>
  );
}
// {/fact}

// Example 9: Using data from context
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_9() {
  // Simulating context data
  const [userData] = useState({ 
    profileUrl: new URLSearchParams(window.location.search).get('profile') || '' 
  });
  
  return (
    <div>
      <h2>User Profile</h2>
      {/* ruleid: javascript-react-href-var */}
      <a href={userData.profileUrl}>View Full Profile</a>
    </div>
  );
}
// {/fact}

// Example 10: Using data from a callback
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_10() {
  const [link, setLink] = useState('');
  
  useEffect(() => {
    const handleMessage = (event: MessageEvent) => {
      if (event.origin === 'https://trusted-source.com') {
        setLink(event.data.redirectUrl);
      }
    };
    
    window.addEventListener('message', handleMessage);
    return () => window.removeEventListener('message', handleMessage);
  }, []);
  
  return (
    <div>
      {/* ruleid: javascript-react-href-var */}
      <a href={link}>Partner Site</a>
    </div>
  );
}
// {/fact}

// Example 11: Using URL parameters with object destructuring
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_11() {
  const [searchParams] = useSearchParams();
  const { ref = '', campaign = '' } = Object.fromEntries(searchParams.entries());
  
  return (
    <div>
      {/* ruleid: javascript-react-href-var */}
      <a href={`/register?ref=${ref}&campaign=${campaign}`}>Register Now</a>
    </div>
  );
}
// {/fact}

// Example 12: Using data from sessionStorage
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_12() {
  const [referralLink, setReferralLink] = useState('');
  
  useEffect(() => {
    const storedLink = sessionStorage.getItem('referralLink');
    if (storedLink) {
      setReferralLink(storedLink);
    }
  }, []);
  
  return (
    <div>
      {/* ruleid: javascript-react-href-var */}
      <a href={referralLink}>Use your referral link</a>
    </div>
  );
}
// {/fact}

// Example 13: Using data from URL with minimal processing
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_13() {
  const location = useLocation();
  const returnUrl = new URLSearchParams(location.search).get('returnUrl') || '';
  const processedUrl = returnUrl.replace(/\s/g, ''); // Only removing spaces
  
  return (
    <div>
      {/* ruleid: javascript-react-href-var */}
      <a href={processedUrl}>Return to previous page</a>
    </div>
  );
}
// {/fact}

// Example 14: Using data from cookies
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_14() {
  const [affiliateLink, setAffiliateLink] = useState('');
  
  useEffect(() => {
    // Simple function to get cookie value
    const getCookie = (name: string) => {
      const value = `; ${document.cookie}`;
      const parts = value.split(`; ${name}=`);
      if (parts.length === 2) return parts.pop()?.split(';').shift() || '';
      return '';
    };
    
    setAffiliateLink(getCookie('affiliateLink'));
  }, []);
  
  return (
    <div>
      {/* ruleid: javascript-react-href-var */}
      <a href={affiliateLink}>Affiliate Link</a>
    </div>
  );
}
// {/fact}

// Example 15: Using data from a third-party API
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_15() {
  const [partnerUrl, setPartnerUrl] = useState('');
  
  useEffect(() => {
    axios.get('https://api.partner.com/get-redirect-url')
      .then(response => {
        setPartnerUrl(response.data.url);
      });
  }, []);
  
  return (
    <div>
      {/* ruleid: javascript-react-href-var */}
      <a href={partnerUrl}>Visit our partner</a>
    </div>
  );
}
// {/fact}

// True Negative Examples (Safe Code)

// Example 1: Using DOMPurify to sanitize URL
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_1() {
  const [searchParams] = useSearchParams();
  const redirectUrl = searchParams.get('redirectUrl');
  
  return (
    <div>
      <h1>Welcome to our site</h1>
      {/* ok: javascript-react-href-var */}
      <a href={DOMPurify.sanitize(redirectUrl || '')}>Click here to continue</a>
    </div>
  );
}
// {/fact}

// Example 2: Using sanitize-html library
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_2() {
  const [userInput, setUserInput] = useState('');
  const [link, setLink] = useState('');
  
  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setUserInput(e.target.value);
  };
  
  const handleSubmit = () => {
    setLink(sanitize(userInput));
  };
  
  return (
    <div>
      <input type="text" onChange={handleChange} placeholder="Enter URL" />
      <button onClick={handleSubmit}>Set Link</button>
      {/* ok: javascript-react-href-var */}
      <a href={link}>Custom Link</a>
    </div>
  );
}
// {/fact}

// Example 3: Using URL validation function
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_3() {
  const location = useLocation();
  const queryParams = new URLSearchParams(location.search);
  const redirectUrl = queryParams.get('redirectUrl') || '';
  
  const isValidUrl = (url: string): boolean => {
    try {
      const parsedUrl = new URL(url);
      return parsedUrl.protocol === 'http:' || parsedUrl.protocol === 'https:';
    } catch {
      return false;
    }
  };
  
  return (
    <div>
      {/* ok: javascript-react-href-var */}
      <a href={isValidUrl(redirectUrl) ? redirectUrl : '#'}>Continue</a>
    </div>
  );
}
// {/fact}

// Example 4: Using a whitelist of allowed domains
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_4() {
  const { id } = useParams<{ id: string }>();
  const [searchParams] = useSearchParams();
  const externalUrl = searchParams.get('externalUrl') || '';
  
  const allowedDomains = ['example.com', 'trusted-site.org', 'partner.net'];
  
  const isSafeDomain = (url: string): boolean => {
    try {
      const domain = new URL(url).hostname;
      return allowedDomains.some(allowed => domain === allowed || domain.endsWith(`.${allowed}`));
    } catch {
      return false;
    }
  };
  
  return (
    <div>
      {/* ok: javascript-react-href-var */}
      <a href={isSafeDomain(externalUrl) ? externalUrl : `/profile/${id}`}>
        External Link
      </a>
    </div>
  );
}
// {/fact}

// Example 5: Using hardcoded values
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_5() {
  const { productId } = useParams<{ productId: string }>();
  
  return (
    <div>
      {/* ok: javascript-react-href-var */}
      <a href={`/products/${productId}/details`}>View Product Details</a>
    </div>
  );
}
// {/fact}

// Example 6: Using URL constructor for validation
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_6() {
  const [searchParams] = useSearchParams();
  const redirectUrl = searchParams.get('redirectUrl');
  
  const getSafeUrl = (url: string | null): string => {
    if (!url) return '#';
    try {
      const safeUrl = new URL(url);
      // Only allow http and https protocols
      if (safeUrl.protocol !== 'http:' && safeUrl.protocol !== 'https:') {
        return '#';
      }
      return safeUrl.toString();
    } catch {
      return '#';
    }
  };
  
  return (
    <div>
      {/* ok: javascript-react-href-var */}
      <a href={getSafeUrl(redirectUrl)}>Continue to site</a>
    </div>
  );
}
// {/fact}

// Example 7: Using a custom sanitizer function
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_7() {
  const [profileData, setProfileData] = useState<{ website: string }>({ website: '' });
  
  useEffect(() => {
    axios.get('/api/user-profile')
      .then(response => {
        setProfileData(response.data);
      });
  }, []);
  
  const sanitizeUrl = (url: string): string => {
    // Remove any javascript: protocol
    const sanitized = url.replace(/^javascript:/i, '');
    
    // Ensure it starts with http:// or https://
    if (!/^https?:\/\//i.test(sanitized)) {
      return `https://${sanitized}`;
    }
    
    return sanitized;
  };
  
  return (
    <div>
      <h2>User Profile</h2>
      {/* ok: javascript-react-href-var */}
      <a href={sanitizeUrl(profileData.website)}>Visit Website</a>
    </div>
  );
}
// {/fact}

// Example 8: Using React Router's Link component instead of anchor
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_8() {
  const { id } = useParams<{ id: string }>();
  const location = useLocation();
  const queryParams = new URLSearchParams(location.search);
  const section = queryParams.get('section');
  
  return (
    <div>
      {/* ok: javascript-react-href-var */}
      <a href={`/safe-redirect?destination=${encodeURIComponent(`/profile/${id}`)}&section=${encodeURIComponent(section || '')}`}>
        Go to section
      </a>
    </div>
  );
}
// {/fact}

// Example 9: Using a server-side redirect pattern
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_9() {
  const [searchParams] = useSearchParams();
  const redirectId = searchParams.get('redirectId');
  
  return (
    <div>
      {/* ok: javascript-react-href-var */}
      <a href={`/api/redirect/${redirectId}`}>Continue</a>
    </div>
  );
}
// {/fact}

// Example 10: Using URL encoding
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_10() {
  const location = useLocation();
  const queryParams = new URLSearchParams(location.search);
  const campaign = queryParams.get('campaign');
  const source = queryParams.get('source');
  
  return (
    <div>
      {/* ok: javascript-react-href-var */}
      <a href={`/signup?ref=${encodeURIComponent(campaign || '')}&source=${encodeURIComponent(source || '')}`}>
        Sign up now
      </a>
    </div>
  );
}
// {/fact}

// Example 11: Using relative URLs only
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_11() {
  const { categoryId } = useParams<{ categoryId: string }>();
  const [searchParams] = useSearchParams();
  const filter = searchParams.get('filter');
  
  return (
    <div>
      {/* ok: javascript-react-href-var */}
      <a href={`/categories/${categoryId}/products?filter=${encodeURIComponent(filter || '')}`}>
        View Products
      </a>
    </div>
  );
}
// {/fact}

// Example 12: Using protocol check
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_12() {
  const [formData, setFormData] = useState({ website: '' });
  
  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };
  
  const getSafeHref = (url: string): string => {
    // Check if URL starts with http:// or https://
    if (/^https?:\/\//i.test(url)) {
      return url;
    }
    // If no protocol is specified, default to https://
    if (url && !url.includes(':')) {
      return `https://${url}`;
    }
    // Otherwise, it might be a malicious protocol
    return '#';
  };
  
  return (
    <div>
      <form>
        <input 
          type="text" 
          name="website" 
          value={formData.website} 
          onChange={handleChange} 
          placeholder="Your website"
        />
      </form>
      {/* ok: javascript-react-href-var */}
      <a href={getSafeHref(formData.website)}>Preview your website</a>
    </div>
  );
}
// {/fact}

// Example 13: Using a custom hook for URL safety
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_13() {
  const [searchParams] = useSearchParams();
  const externalUrl = searchParams.get('externalUrl');
  
  // Custom hook for URL safety
  const useSafeUrl = (url: string | null): string => {
    if (!url) return '#';
    
    // Sanitize with DOMPurify first
    const sanitized = DOMPurify.sanitize(url);
    
    try {
      const urlObj = new URL(sanitized);
      // Only allow http and https protocols
      if (urlObj.protocol === 'http:' || urlObj.protocol === 'https:') {
        return sanitized;
      }
    } catch {
      // Invalid URL
    }
    
    return '#';
  };
  
  const safeUrl = useSafeUrl(externalUrl);
  
  return (
    <div>
      {/* ok: javascript-react-href-var */}
      <a href={safeUrl}>External Link</a>
    </div>
  );
}
// {/fact}

// Example 14: Using a combination of techniques
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_14() {
  const location = useLocation();
  const returnUrl = new URLSearchParams(location.search).get('returnUrl') || '';
  
  const validateAndSanitizeUrl = (url: string): string => {
    // First sanitize with DOMPurify
    const sanitized = DOMPurify.sanitize(url);
    
    // Then validate URL structure
    try {
      const urlObj = new URL(sanitized);
      
      // Check protocol
      if (urlObj.protocol !== 'http:' && urlObj.protocol !== 'https:') {
        return '#';
      }
      
      // Check domain against whitelist
      const allowedDomains = ['example.com', 'trusted.org'];
      if (!allowedDomains.some(domain => urlObj.hostname === domain || urlObj.hostname.endsWith(`.${domain}`))) {
        return '#';
      }
      
      return sanitized;
    } catch {
      // If it's not a valid URL, check if it's a relative path
      if (url.startsWith('/') && !url.includes(':')) {
        return url; // Allow relative URLs
      }
      return '#';
    }
  };
  
  return (
    <div>
      {/* ok: javascript-react-href-var */}
      <a href={validateAndSanitizeUrl(returnUrl)}>Return to previous page</a>
    </div>
  );
}
// {/fact}

// Example 15: Using a centralized security service
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_15() {
  const [partnerUrl, setPartnerUrl] = useState('');
  
  useEffect(() => {
    axios.get('https://api.partner.com/get-redirect-url')
      .then(response => {
        setPartnerUrl(response.data.url);
      });
  }, []);
  
  // Simulating a security service
  const securityService = {
    sanitizeUrl: (url: string): string => {
      // Comprehensive URL sanitization
      const sanitized = DOMPurify.sanitize(url);
      
      try {
        const urlObj = new URL(sanitized);
        
        // Protocol check
        if (urlObj.protocol !== 'http:' && urlObj.protocol !== 'https:') {
          return '#';
        }
        
        // Domain whitelist check
        const trustedDomains = ['partner.com', 'affiliate.org', 'trusted-source.net'];
        if (!trustedDomains.some(domain => urlObj.hostname === domain || urlObj.hostname.endsWith(`.${domain}`))) {
          return '#';
        }
        
        return sanitized;
      } catch {
        return '#';
      }
    }
  };
  
  return (
    <div>
      {/* ok: javascript-react-href-var */}
      <a href={securityService.sanitizeUrl(partnerUrl)}>Visit our partner</a>
    </div>
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