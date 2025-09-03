// Import necessary libraries
import express, { Request, Response } from 'express';
import { URL } from 'url';
import * as http from 'http';
import * as https from 'https';
import { parse as parseUrl } from 'url';
import { NextFunction } from 'express';
import * as validator from 'validator';
import { sanitizeUrl } from '@braintree/sanitize-url';

// True Positives (Vulnerable Code)

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_1(req: Request, res: Response) {
    const redirectUrl = req.query.url as string;
    // ruleid: typescript-unsafe-redirect
    res.redirect(redirectUrl);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_2(req: Request, res: Response) {
    const redirectUrl = req.params.target;
    // ruleid: typescript-unsafe-redirect
    res.redirect(302, redirectUrl);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_3(req: Request, res: Response) {
    const { returnTo } = req.body;
    // ruleid: typescript-unsafe-redirect
    res.location(returnTo).status(302).end();
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_4(req: Request, res: Response) {
    const redirectPath = req.query.path as string;
    const fullUrl = `https://example.com${redirectPath}`;
    // ruleid: typescript-unsafe-redirect
    res.redirect(fullUrl);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_5(req: Request, res: Response) {
    const destination = req.headers.referer as string;
    // ruleid: typescript-unsafe-redirect
    res.writeHead(302, { Location: destination });
    res.end();
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_6(req: Request, res: Response) {
    const target = req.query.target as string;
    if (target) {
        // ruleid: typescript-unsafe-redirect
        res.setHeader('Location', target);
        res.statusCode = 302;
        res.end();
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_7(req: Request, res: Response) {
    const redirectUrl = req.cookies.returnUrl;
    // ruleid: typescript-unsafe-redirect
    res.redirect(redirectUrl || '/default');
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_8(req: Request, res: Response) {
    const { next } = req.query;
    if (typeof next === 'string' && next.startsWith('/')) {
        // ruleid: typescript-unsafe-redirect
        res.redirect(next);
    } else {
        res.redirect('/home');
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_9(req: Request, res: Response) {
    let redirectUrl = '/dashboard';
    if (req.query.redirect) {
        redirectUrl = req.query.redirect as string;
    }
    // ruleid: typescript-unsafe-redirect
    res.redirect(redirectUrl);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_10(req: Request, res: Response) {
    const target = req.body.redirectTarget;
    const baseUrl = 'https://example.com';
    // ruleid: typescript-unsafe-redirect
    res.redirect(`${baseUrl}${target}`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_11(req: Request, res: Response) {
    const { returnTo } = req.query;
    const redirectUrl = Array.isArray(returnTo) ? returnTo[0] : returnTo as string;
    // ruleid: typescript-unsafe-redirect
    res.redirect(redirectUrl);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_12(req: Request, res: Response) {
    const redirects: Record<string, string> = {
        'profile': '/user/profile',
        'settings': '/user/settings',
        'default': '/home'
    };
    
    const page = req.query.page as string;
    const destination = redirects[page] || page;
    // ruleid: typescript-unsafe-redirect
    res.redirect(destination);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_13(req: Request, res: Response) {
    const url = new URL(req.originalUrl, 'https://example.com');
    const redirectParam = url.searchParams.get('redirect');
    if (redirectParam) {
        // ruleid: typescript-unsafe-redirect
        res.redirect(redirectParam);
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_14(req: Request, res: Response) {
    const userInput = req.query.url as string;
    const decodedUrl = decodeURIComponent(userInput);
    // ruleid: typescript-unsafe-redirect
    res.redirect(decodedUrl);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_15(req: Request, res: Response) {
    const { returnUrl } = req.body;
    if (returnUrl && typeof returnUrl === 'string') {
        // ruleid: typescript-unsafe-redirect
        window.location.href = returnUrl;
    }
}
// {/fact}

// True Negatives (Safe Code)

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_1(req: Request, res: Response) {
    const redirectUrl = req.query.url as string;
    const allowedDomains = ['example.com', 'trusted-site.com'];
    
    try {
        const urlObj = new URL(redirectUrl);
        // ok: typescript-unsafe-redirect
        if (allowedDomains.includes(urlObj.hostname)) {
            res.redirect(redirectUrl);
        } else {
            res.redirect('/default');
        }
    } catch (e) {
        res.redirect('/default');
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_2(req: Request, res: Response) {
    const redirectUrl = req.query.url as string;
    // ok: typescript-unsafe-redirect
    const safeUrls = ['/home', '/dashboard', '/profile'];
    if (safeUrls.includes(redirectUrl)) {
        res.redirect(redirectUrl);
    } else {
        res.redirect('/home');
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_3(req: Request, res: Response) {
    // ok: typescript-unsafe-redirect
    const hardcodedRedirectUrl = '/dashboard';
    res.redirect(hardcodedRedirectUrl);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_4(req: Request, res: Response) {
    const redirectPath = req.query.path as string;
    
    // ok: typescript-unsafe-redirect
    if (/^\/[a-zA-Z0-9\/-]*$/.test(redirectPath)) {
        res.redirect(redirectPath);
    } else {
        res.redirect('/');
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_5(req: Request, res: Response) {
    const { returnTo } = req.query;
    
    // ok: typescript-unsafe-redirect
    if (typeof returnTo === 'string' && returnTo.startsWith('/') && !returnTo.includes('//')) {
        res.redirect(returnTo);
    } else {
        res.redirect('/home');
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_6(req: Request, res: Response) {
    const target = req.query.target as string;
    
    try {
        const url = new URL(target, 'https://example.com');
        // ok: typescript-unsafe-redirect
        if (url.hostname === 'example.com') {
            res.redirect(url.toString());
        } else {
            res.redirect('/');
        }
    } catch (e) {
        res.redirect('/');
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_7(req: Request, res: Response) {
    const redirectUrl = req.query.url as string;
    
    // ok: typescript-unsafe-redirect
    const sanitizedUrl = sanitizeUrl(redirectUrl);
    if (sanitizedUrl !== 'about:blank') {
        res.redirect(sanitizedUrl);
    } else {
        res.redirect('/');
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_8(req: Request, res: Response) {
    const { next } = req.query;
    
    // ok: typescript-unsafe-redirect
    if (typeof next === 'string' && validator.isURL(next, { 
        protocols: ['http', 'https'],
        require_tld: true,
        require_protocol: true,
        require_host: true,
        require_valid_protocol: true,
        allow_underscores: false,
        host_whitelist: ['example.com', 'subdomain.example.com'],
        host_blacklist: ['evil.com']
    })) {
        res.redirect(next);
    } else {
        res.redirect('/default');
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_9(req: Request, res: Response) {
    const redirectMap: Record<string, string> = {
        'profile': '/user/profile',
        'settings': '/user/settings',
        'dashboard': '/user/dashboard'
    };
    
    const page = req.query.page as string;
    // ok: typescript-unsafe-redirect
    const destination = redirectMap[page] || '/default';
    res.redirect(destination);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_10(req: Request, res: Response) {
    const { returnTo } = req.query;
    
    // ok: typescript-unsafe-redirect
    const allowedUrls = new Set(['/home', '/dashboard', '/profile', '/settings']);
    const redirectUrl = allowedUrls.has(returnTo as string) ? returnTo as string : '/home';
    res.redirect(redirectUrl);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_11(req: Request, res: Response) {
    // ok: typescript-unsafe-redirect
    res.redirect(302, '/login');
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_12(req: Request, res: Response) {
    const redirectUrl = req.query.url as string;
    
    function isRelativeUrl(url: string): boolean {
        return url.startsWith('/') && !url.startsWith('//');
    }
    
    // ok: typescript-unsafe-redirect
    if (redirectUrl && isRelativeUrl(redirectUrl)) {
        res.redirect(redirectUrl);
    } else {
        res.redirect('/default');
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_13(req: Request, res: Response) {
    const { returnUrl } = req.query;
    
    // ok: typescript-unsafe-redirect
    const baseUrl = 'https://example.com';
    const paths = ['/home', '/dashboard', '/profile'];
    
    if (typeof returnUrl === 'string' && paths.includes(returnUrl)) {
        res.redirect(`${baseUrl}${returnUrl}`);
    } else {
        res.redirect(`${baseUrl}/home`);
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_14(req: Request, res: Response) {
    const redirectUrl = req.query.url as string;
    
    // ok: typescript-unsafe-redirect
    const validRedirectUrlPattern = /^(\/[a-zA-Z0-9\/-]*)?$/;
    if (redirectUrl && validRedirectUrlPattern.test(redirectUrl)) {
        res.redirect(redirectUrl);
    } else {
        res.redirect('/');
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_15(req: Request, res: Response) {
    const { next } = req.query;
    
    // ok: typescript-unsafe-redirect
    function validateRedirectUrl(url: string): boolean {
        if (!url || typeof url !== 'string') return false;
        if (url.startsWith('/') && !url.includes('//')) return true;
        try {
            const parsedUrl = new URL(url);
            return parsedUrl.hostname === 'example.com';
        } catch (e) {
            return false;
        }
    }
    
    if (validateRedirectUrl(next as string)) {
        res.redirect(next as string);
    } else {
        res.redirect('/default');
    }
}
// {/fact}