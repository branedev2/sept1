// Import common libraries
const express = require('express');
const app = express();
const http = require('http');
const https = require('https');
const axios = require('axios');
const fetch = require('node-fetch');
const DOMPurify = require('dompurify');
const { URL } = require('url');

// Configure middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// TRUE POSITIVES (Vulnerable Code)

// Case 1: Direct use of query parameter in location.href
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_1(req, res) {
    const redirectUrl = req.query.url;
    res.send(`
        <script>
            // ruleid: javascript-location-url-xss
            window.location.href = "${redirectUrl}";
        </script>
    `);
}
// {/fact}

// Case 2: Using location.replace with user input
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_2(req, res) {
    const redirectUrl = req.query.redirect;
    res.send(`
        <script>
            // ruleid: javascript-location-url-xss
            location.replace("${redirectUrl}");
        </script>
    `);
}
// {/fact}

// Case 3: Using location.assign with user input
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_3(req, res) {
    const destination = req.query.dest;
    res.send(`
        <script>
            // ruleid: javascript-location-url-xss
            window.location.assign("${destination}");
        </script>
    `);
}
// {/fact}

// Case 4: Setting location directly with user input
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_4(req, res) {
    const target = req.query.target;
    res.send(`
        <script>
            // ruleid: javascript-location-url-xss
            location = "${target}";
        </script>
    `);
}
// {/fact}

// Case 5: Using document.location with user input
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_5(req, res) {
    const url = req.query.url;
    res.send(`
        <script>
            // ruleid: javascript-location-url-xss
            document.location = "${url}";
        </script>
    `);
}
// {/fact}

// Case 6: Using location.href with concatenation
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_6(req, res) {
    const id = req.query.id;
    res.send(`
        <script>
            // ruleid: javascript-location-url-xss
            window.location.href = "https://example.com/profile?id=" + "${id}";
        </script>
    `);
}
// {/fact}

// Case 7: Using template literals with location
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_7(req, res) {
    const section = req.query.section;
    res.send(`
        <script>
            // ruleid: javascript-location-url-xss
            window.location.href = \`/dashboard?section=${section}\`;
        </script>
    `);
}
// {/fact}

// Case 8: Using location with processed but unsanitized input
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_8(req, res) {
    let category = req.query.category;
    category = category.toLowerCase();
    res.send(`
        <script>
            // ruleid: javascript-location-url-xss
            window.location.href = "/products?cat=" + "${category}";
        </script>
    `);
}
// {/fact}

// Case 9: Using location with header data
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_9(req, res) {
    const referer = req.headers.referer;
    res.send(`
        <script>
            // ruleid: javascript-location-url-xss
            window.location.href = "${referer}";
        </script>
    `);
}
// {/fact}

// Case 10: Using location with cookie data
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_10(req, res) {
    const lastVisited = req.cookies.lastPage;
    res.send(`
        <script>
            // ruleid: javascript-location-url-xss
            window.location.href = "${lastVisited}";
        </script>
    `);
}
// {/fact}

// Case 11: Using location.pathname with user input
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_11(req, res) {
    const path = req.query.path;
    res.send(`
        <script>
            // ruleid: javascript-location-url-xss
            window.location.pathname = "${path}";
        </script>
    `);
}
// {/fact}

// Case 12: Using location.search with user input
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_12(req, res) {
    const queryString = req.query.search;
    res.send(`
        <script>
            // ruleid: javascript-location-url-xss
            window.location.search = "${queryString}";
        </script>
    `);
}
// {/fact}

// Case 13: Using location.hash with user input
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_13(req, res) {
    const fragment = req.query.fragment;
    res.send(`
        <script>
            // ruleid: javascript-location-url-xss
            window.location.hash = "${fragment}";
        </script>
    `);
}
// {/fact}

// Case 14: Using open() with user input URL
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_14(req, res) {
    const externalUrl = req.query.external;
    res.send(`
        <script>
            // ruleid: javascript-location-url-xss
            window.open("${externalUrl}", "_blank");
        </script>
    `);
}
// {/fact}

// Case 15: Using iframe src with user input
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_15(req, res) {
    const frameSource = req.query.frame;
    res.send(`
        <script>
            const iframe = document.createElement('iframe');
            // ruleid: javascript-location-url-xss
            iframe.src = "${frameSource}";
            document.body.appendChild(iframe);
        </script>
    `);
}
// {/fact}

// TRUE NEGATIVES (Safe Code)

// Case 1: Using a hardcoded URL
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_1(req, res) {
    res.send(`
        <script>
            // ok: javascript-location-url-xss
            window.location.href = "https://example.com/dashboard";
        </script>
    `);
}
// {/fact}

// Case 2: URL validation with regex pattern
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_2(req, res) {
    let redirectUrl = req.query.url;
    const urlPattern = /^(https?:\/\/)?example\.com\/[a-zA-Z0-9\/-]+$/;
    
    if (!urlPattern.test(redirectUrl)) {
        redirectUrl = "/default";
    }
    
    res.send(`
        <script>
            // ok: javascript-location-url-xss
            window.location.href = "${redirectUrl}";
        </script>
    `);
}
// {/fact}

// Case 3: Using a whitelist of allowed URLs
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_3(req, res) {
    const redirectUrl = req.query.url;
    const allowedUrls = [
        "/home",
        "/dashboard",
        "/profile",
        "/settings"
    ];
    
    if (!allowedUrls.includes(redirectUrl)) {
        res.status(400).send("Invalid URL");
        return;
    }
    
    res.send(`
        <script>
            // ok: javascript-location-url-xss
            window.location.href = "${redirectUrl}";
        </script>
    `);
}
// {/fact}

// Case 4: Using URL constructor for validation
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_4(req, res) {
    let redirectUrl;
    try {
        const urlObj = new URL(req.query.url, "https://example.com");
        if (urlObj.hostname === "example.com") {
            redirectUrl = urlObj.toString();
        } else {
            redirectUrl = "https://example.com";
        }
    } catch (e) {
        redirectUrl = "https://example.com";
    }
    
    res.send(`
        <script>
            // ok: javascript-location-url-xss
            window.location.href = "${redirectUrl}";
        </script>
    `);
}
// {/fact}

// Case 5: Using DOMPurify to sanitize URL
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_5(req, res) {
    const redirectUrl = DOMPurify.sanitize(req.query.url);
    
    res.send(`
        <script>
            // ok: javascript-location-url-xss
            window.location.href = "${redirectUrl}";
        </script>
    `);
}
// {/fact}

// Case 6: Using URL path validation
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_6(req, res) {
    let path = req.query.path || "";
    
    // Remove any characters that aren't alphanumeric, dash, or slash
    path = path.replace(/[^a-zA-Z0-9\/-]/g, "");
    
    res.send(`
        <script>
            // ok: javascript-location-url-xss
            window.location.pathname = "${path}";
        </script>
    `);
}
// {/fact}

// Case 7: Using a lookup table for redirects
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_7(req, res) {
    const redirectKey = req.query.page;
    const redirectMap = {
        "home": "/home",
        "profile": "/user/profile",
        "settings": "/user/settings",
        "help": "/support"
    };
    
    const redirectUrl = redirectMap[redirectKey] || "/home";
    
    res.send(`
        <script>
            // ok: javascript-location-url-xss
            window.location.href = "${redirectUrl}";
        </script>
    `);
}
// {/fact}

// Case 8: Using encodeURIComponent for query parameters
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_8(req, res) {
    const searchTerm = req.query.search;
    const encodedSearch = encodeURIComponent(searchTerm);
    
    res.send(`
        <script>
            // ok: javascript-location-url-xss
            window.location.href = "/search?q=" + "${encodedSearch}";
        </script>
    `);
}
// {/fact}

// Case 9: Using numeric validation for IDs
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_9(req, res) {
    let productId = req.query.id;
    
    // Ensure it's a valid number
    if (!/^\d+$/.test(productId)) {
        productId = "1";
    }
    
    res.send(`
        <script>
            // ok: javascript-location-url-xss
            window.location.href = "/product/" + "${productId}";
        </script>
    `);
}
// {/fact}

// Case 10: Using server-side redirect instead of client-side
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_10(req, res) {
    const redirectUrl = req.query.url;
    
    if (redirectUrl && redirectUrl.startsWith('/')) {
        // ok: javascript-location-url-xss
        res.redirect(redirectUrl);
    } else {
        res.redirect('/default');
    }
}
// {/fact}

// Case 11: Using URL constructor with origin validation
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_11(req, res) {
    let redirectUrl;
    try {
        const urlObj = new URL(req.query.url);
        const allowedOrigins = ['example.com', 'api.example.com', 'cdn.example.com'];
        
        if (allowedOrigins.includes(urlObj.hostname)) {
            redirectUrl = urlObj.toString();
        } else {
            redirectUrl = "https://example.com";
        }
    } catch (e) {
        redirectUrl = "https://example.com";
    }
    
    res.send(`
        <script>
            // ok: javascript-location-url-xss
            window.location.href = "${redirectUrl}";
        </script>
    `);
}
// {/fact}

// Case 12: Using a hash function to validate known URLs
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_12(req, res) {
    const urlId = req.query.id;
    
    // Simple hash map of pre-approved URLs
    const urlMap = {
        "a1b2c3": "/dashboard",
        "d4e5f6": "/profile",
        "g7h8i9": "/settings"
    };
    
    const redirectUrl = urlMap[urlId] || "/home";
    
    res.send(`
        <script>
            // ok: javascript-location-url-xss
            window.location.href = "${redirectUrl}";
        </script>
    `);
}
// {/fact}

// Case 13: Using path sanitization for fragments
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_13(req, res) {
    let fragment = req.query.section || "";
    
    // Only allow alphanumeric characters and hyphens in fragments
    fragment = fragment.replace(/[^a-zA-Z0-9-]/g, "");
    
    res.send(`
        <script>
            // ok: javascript-location-url-xss
            window.location.hash = "${fragment}";
        </script>
    `);
}
// {/fact}

// Case 14: Using boolean logic for simple redirects
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_14(req, res) {
    const shouldRedirect = req.query.redirect === "true";
    const redirectUrl = shouldRedirect ? "/success" : "/failure";
    
    res.send(`
        <script>
            // ok: javascript-location-url-xss
            window.location.href = "${redirectUrl}";
        </script>
    `);
}
// {/fact}

// Case 15: Using a function to validate URL
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_15(req, res) {
    const userUrl = req.query.url;
    
    function isValidUrl(url) {
        try {
            const parsedUrl = new URL(url);
            return parsedUrl.protocol === "https:" && 
                   (parsedUrl.hostname === "example.com" || 
                    parsedUrl.hostname.endsWith(".example.com"));
        } catch (e) {
            return false;
        }
    }
    
    const redirectUrl = isValidUrl(userUrl) ? userUrl : "https://example.com";
    
    res.send(`
        <script>
            // ok: javascript-location-url-xss
            window.location.href = "${redirectUrl}";
        </script>
    `);
}
// {/fact}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});