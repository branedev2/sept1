import express from 'express';
import { Request, Response } from 'express';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { User, Role, Permission } from './models';

const app = express();
app.use(express.json());

// TRUE POSITIVES (Vulnerable code)

// Example 1: Using user-provided role for access control
// {fact rule=untrusted-data-in-decision@v1.0 defects=1}
function bad_case_1(req: Request, res: Response) {
    const userRole = req.query.role as string;
    
    // ruleid: typescript-untrusted-data-in-decision-making
    if (userRole === 'admin') {
        // Grant admin access
        res.json({ adminData: 'sensitive information' });
    } else {
        res.status(403).json({ error: 'Access denied' });
    }
}
// {/fact}

// Example 2: Using user-provided permission level for authorization
// {fact rule=untrusted-data-in-decision@v1.0 defects=1}
function bad_case_2(req: Request, res: Response) {
    const permissionLevel = req.body.permissionLevel;
    
    // ruleid: typescript-untrusted-data-in-decision-making
    if (permissionLevel >= 5) {
        // Allow access to sensitive operation
        performSensitiveOperation();
        res.json({ success: true });
    } else {
        res.status(403).json({ error: 'Insufficient permissions' });
    }
}
// {/fact}

// Example 3: Using user-provided token for authentication bypass
// {fact rule=untrusted-data-in-decision@v1.0 defects=1}
function bad_case_3(req: Request, res: Response) {
    const isAdmin = req.query.isAdmin === 'true';
    
    // ruleid: typescript-untrusted-data-in-decision-making
    if (isAdmin) {
        // Grant admin access
        res.json({ adminDashboard: 'admin data' });
    } else {
        res.status(403).json({ error: 'Not an admin' });
    }
}
// {/fact}

// Example 4: Using user-provided flag to determine if user is authenticated
// {fact rule=untrusted-data-in-decision@v1.0 defects=1}
function bad_case_4(req: Request, res: Response) {
    const authenticated = req.headers['x-authenticated'] === 'true';
    
    // ruleid: typescript-untrusted-data-in-decision-making
    if (authenticated) {
        // Allow access to protected resource
        res.json({ protectedData: 'sensitive information' });
    } else {
        res.status(401).json({ error: 'Authentication required' });
    }
}
// {/fact}

// Example 5: Using user-provided user ID for direct object reference
// {fact rule=untrusted-data-in-decision@v1.0 defects=1}
function bad_case_5(req: Request, res: Response) {
    const userId = req.params.id;
    const resourceOwnerId = '12345'; // Actual owner ID
    
    // ruleid: typescript-untrusted-data-in-decision-making
    if (userId === resourceOwnerId) {
        // Allow access to the resource
        res.json({ resource: 'sensitive user data' });
    } else {
        res.status(403).json({ error: 'Access denied' });
    }
}
// {/fact}

// Example 6: Using user-provided path for file access
// {fact rule=untrusted-data-in-decision@v1.0 defects=1}
function bad_case_6(req: Request, res: Response) {
    const filePath = req.query.path as string;
    
    // ruleid: typescript-untrusted-data-in-decision-making
    if (filePath.startsWith('/public/')) {
        // Allow access to the file
        const fileContent = fs.readFileSync(filePath, 'utf8');
        res.send(fileContent);
    } else {
        res.status(403).json({ error: 'Access denied' });
    }
}
// {/fact}

// Example 7: Using user-provided email domain for privilege escalation
// {fact rule=untrusted-data-in-decision@v1.0 defects=1}
function bad_case_7(req: Request, res: Response) {
    const email = req.body.email as string;
    
    // ruleid: typescript-untrusted-data-in-decision-making
    if (email.endsWith('@admin.company.com')) {
        // Grant admin privileges
        grantAdminPrivileges(email);
        res.json({ success: true });
    } else {
        res.status(403).json({ error: 'Not an admin email' });
    }
}
// {/fact}

// Example 8: Using user-provided IP for rate limiting bypass
// {fact rule=untrusted-data-in-decision@v1.0 defects=1}
function bad_case_8(req: Request, res: Response) {
    const clientIP = req.headers['x-forwarded-for'] as string;
    
    // ruleid: typescript-untrusted-data-in-decision-making
    if (clientIP === '127.0.0.1' || clientIP.startsWith('192.168.')) {
        // Bypass rate limiting for internal IPs
        res.json({ data: 'Unlimited access granted' });
    } else {
        // Apply rate limiting
        applyRateLimiting(clientIP);
        res.json({ data: 'Rate limited access' });
    }
}
// {/fact}

// Example 9: Using user-provided security question answer
// {fact rule=untrusted-data-in-decision@v1.0 defects=1}
function bad_case_9(req: Request, res: Response) {
    const providedAnswer = req.body.securityAnswer as string;
    const expectedAnswer = 'Smith'; // Stored answer for security question
    
    // ruleid: typescript-untrusted-data-in-decision-making
    if (providedAnswer === expectedAnswer) {
        // Allow password reset
        resetPassword(req.body.userId);
        res.json({ success: true });
    } else {
        res.status(403).json({ error: 'Incorrect security answer' });
    }
}
// {/fact}

// Example 10: Using user-provided feature flag
// {fact rule=untrusted-data-in-decision@v1.0 defects=1}
function bad_case_10(req: Request, res: Response) {
    const featureEnabled = req.query.enableFeature === 'true';
    
    // ruleid: typescript-untrusted-data-in-decision-making
    if (featureEnabled) {
        // Enable premium feature
        res.json({ premiumFeature: 'enabled' });
    } else {
        res.status(403).json({ error: 'Feature not available' });
    }
}
// {/fact}

// Example 11: Using user-provided API key directly
// {fact rule=untrusted-data-in-decision@v1.0 defects=1}
function bad_case_11(req: Request, res: Response) {
    const apiKey = req.headers['x-api-key'] as string;
    const validApiKey = 'sk_live_abcdefg123456';
    
    // ruleid: typescript-untrusted-data-in-decision-making
    if (apiKey === validApiKey) {
        // Allow API access
        res.json({ data: 'Sensitive API data' });
    } else {
        res.status(401).json({ error: 'Invalid API key' });
    }
}
// {/fact}

// Example 12: Using user-provided account type
// {fact rule=untrusted-data-in-decision@v1.0 defects=1}
function bad_case_12(req: Request, res: Response) {
    const accountType = req.body.accountType as string;
    
    // ruleid: typescript-untrusted-data-in-decision-making
    if (accountType === 'premium') {
        // Allow premium features
        res.json({ premiumFeatures: ['feature1', 'feature2'] });
    } else {
        res.json({ basicFeatures: ['feature1'] });
    }
}
// {/fact}

// Example 13: Using user-provided authorization header directly
// {fact rule=untrusted-data-in-decision@v1.0 defects=1}
function bad_case_13(req: Request, res: Response) {
    const authHeader = req.headers.authorization as string;
    
    // ruleid: typescript-untrusted-data-in-decision-making
    if (authHeader && authHeader.startsWith('Bearer ')) {
        // Allow access to protected resource
        res.json({ protectedData: 'sensitive information' });
    } else {
        res.status(401).json({ error: 'Authentication required' });
    }
}
// {/fact}

// Example 14: Using user-provided verification status
// {fact rule=untrusted-data-in-decision@v1.0 defects=1}
function bad_case_14(req: Request, res: Response) {
    const isVerified = req.query.verified === 'true';
    
    // ruleid: typescript-untrusted-data-in-decision-making
    if (isVerified) {
        // Allow access to verified-only content
        res.json({ verifiedContent: 'exclusive content' });
    } else {
        res.status(403).json({ error: 'Verification required' });
    }
}
// {/fact}

// Example 15: Using user-provided subscription level
// {fact rule=untrusted-data-in-decision@v1.0 defects=1}
function bad_case_15(req: Request, res: Response) {
    const subscriptionTier = req.body.subscriptionTier as string;
    
    // ruleid: typescript-untrusted-data-in-decision-making
    if (subscriptionTier === 'enterprise') {
        // Allow enterprise features
        res.json({ enterpriseFeatures: 'advanced analytics' });
    } else {
        res.status(403).json({ error: 'Enterprise subscription required' });
    }
}
// {/fact}

// TRUE NEGATIVES (Secure code)

// Example 1: Verifying role from database
// {fact rule=untrusted-data-in-decision@v1.0 defects=0}
function good_case_1(req: Request, res: Response) {
    const userId = req.session.userId;
    
    // Fetch user from database
    const user = getUserFromDatabase(userId);
    
    // ok: typescript-untrusted-data-in-decision-making
    if (user && user.role === 'admin') {
        // Grant admin access
        res.json({ adminData: 'sensitive information' });
    } else {
        res.status(403).json({ error: 'Access denied' });
    }
}
// {/fact}

// Example 2: Verifying permission level from authenticated session
// {fact rule=untrusted-data-in-decision@v1.0 defects=0}
function good_case_2(req: Request, res: Response) {
    const userId = req.session.userId;
    
    // Fetch user permissions from database
    const userPermissions = getPermissionsFromDatabase(userId);
    
    // ok: typescript-untrusted-data-in-decision-making
    if (userPermissions && userPermissions.level >= 5) {
        // Allow access to sensitive operation
        performSensitiveOperation();
        res.json({ success: true });
    } else {
        res.status(403).json({ error: 'Insufficient permissions' });
    }
}
// {/fact}

// Example 3: Using JWT token verification for admin status
// {fact rule=untrusted-data-in-decision@v1.0 defects=0}
function good_case_3(req: Request, res: Response) {
    const token = req.headers.authorization?.split(' ')[1];
    
    try {
        // Verify token and extract claims
        const decodedToken = verifyJwtToken(token);
        
        // ok: typescript-untrusted-data-in-decision-making
        if (decodedToken && decodedToken.isAdmin) {
            // Grant admin access
            res.json({ adminDashboard: 'admin data' });
        } else {
            res.status(403).json({ error: 'Not an admin' });
        }
    } catch (error) {
        res.status(401).json({ error: 'Invalid token' });
    }
}
// {/fact}

// Example 4: Using session-based authentication
// {fact rule=untrusted-data-in-decision@v1.0 defects=0}
function good_case_4(req: Request, res: Response) {
    // ok: typescript-untrusted-data-in-decision-making
    if (req.session && req.session.authenticated) {
        // Allow access to protected resource
        res.json({ protectedData: 'sensitive information' });
    } else {
        res.status(401).json({ error: 'Authentication required' });
    }
}
// {/fact}

// Example 5: Proper authorization check for resource access
// {fact rule=untrusted-data-in-decision@v1.0 defects=0}
function good_case_5(req: Request, res: Response) {
    const userId = req.session.userId;
    const resourceId = req.params.resourceId;
    
    // Check if user owns the resource
    const isAuthorized = checkResourceOwnership(userId, resourceId);
    
    // ok: typescript-untrusted-data-in-decision-making
    if (isAuthorized) {
        // Allow access to the resource
        const resource = getResourceData(resourceId);
        res.json({ resource });
    } else {
        res.status(403).json({ error: 'Access denied' });
    }
}
// {/fact}

// Example 6: Secure file access with path validation
// {fact rule=untrusted-data-in-decision@v1.0 defects=0}
function good_case_6(req: Request, res: Response) {
    const requestedFile = req.query.file as string;
    
    // Sanitize and validate the file path
    const sanitizedPath = sanitizeFilePath(requestedFile);
    const fullPath = path.join('/public', sanitizedPath);
    
    // Verify the path is within allowed directory
    const isPathSafe = isPathWithinAllowedDirectory(fullPath, '/public');
    
    // ok: typescript-untrusted-data-in-decision-making
    if (isPathSafe && fs.existsSync(fullPath)) {
        const fileContent = fs.readFileSync(fullPath, 'utf8');
        res.send(fileContent);
    } else {
        res.status(403).json({ error: 'Access denied' });
    }
}
// {/fact}

// Example 7: Proper email domain verification
// {fact rule=untrusted-data-in-decision@v1.0 defects=0}
function good_case_7(req: Request, res: Response) {
    const userId = req.session.userId;
    
    // Get user email from database
    const user = getUserFromDatabase(userId);
    
    // ok: typescript-untrusted-data-in-decision-making
    if (user && user.email.endsWith('@admin.company.com')) {
        // Grant admin privileges
        grantAdminPrivileges(user.email);
        res.json({ success: true });
    } else {
        res.status(403).json({ error: 'Not an admin email' });
    }
}
// {/fact}

// Example 8: Proper IP-based access control
// {fact rule=untrusted-data-in-decision@v1.0 defects=0}
function good_case_8(req: Request, res: Response) {
    // Get IP from trusted source (e.g., reverse proxy configuration)
    const clientIP = req.ip;
    
    // Check against whitelist
    const internalIPs = ['127.0.0.1', '192.168.1.1', '10.0.0.1'];
    
    // ok: typescript-untrusted-data-in-decision-making
    if (internalIPs.includes(clientIP)) {
        // Bypass rate limiting for internal IPs
        res.json({ data: 'Unlimited access granted' });
    } else {
        // Apply rate limiting
        applyRateLimiting(clientIP);
        res.json({ data: 'Rate limited access' });
    }
}
// {/fact}

// Example 9: Secure security question verification
// {fact rule=untrusted-data-in-decision@v1.0 defects=0}
function good_case_9(req: Request, res: Response) {
    const userId = req.body.userId;
    const providedAnswer = req.body.securityAnswer as string;
    
    // Get stored security answer from database
    const user = getUserFromDatabase(userId);
    
    // ok: typescript-untrusted-data-in-decision-making
    if (user && crypto.timingSafeEqual(
        Buffer.from(providedAnswer),
        Buffer.from(user.securityAnswer)
    )) {
        // Allow password reset
        resetPassword(userId);
        res.json({ success: true });
    } else {
        res.status(403).json({ error: 'Incorrect security answer' });
    }
}
// {/fact}

// Example 10: Proper feature flag management
// {fact rule=untrusted-data-in-decision@v1.0 defects=0}
function good_case_10(req: Request, res: Response) {
    const userId = req.session.userId;
    
    // Get user subscription from database
    const userSubscription = getUserSubscription(userId);
    
    // ok: typescript-untrusted-data-in-decision-making
    if (userSubscription && userSubscription.features.includes('premium')) {
        // Enable premium feature
        res.json({ premiumFeature: 'enabled' });
    } else {
        res.status(403).json({ error: 'Feature not available' });
    }
}
// {/fact}

// Example 11: Proper API key verification
// {fact rule=untrusted-data-in-decision@v1.0 defects=0}
function good_case_11(req: Request, res: Response) {
    const apiKey = req.headers['x-api-key'] as string;
    
    // Verify API key against database or secure storage
    const isValidApiKey = verifyApiKey(apiKey);
    
    // ok: typescript-untrusted-data-in-decision-making
    if (isValidApiKey) {
        // Allow API access
        res.json({ data: 'Sensitive API data' });
    } else {
        res.status(401).json({ error: 'Invalid API key' });
    }
}
// {/fact}

// Example 12: Proper account type verification
// {fact rule=untrusted-data-in-decision@v1.0 defects=0}
function good_case_12(req: Request, res: Response) {
    const userId = req.session.userId;
    
    // Get account type from database
    const user = getUserFromDatabase(userId);
    
    // ok: typescript-untrusted-data-in-decision-making
    if (user && user.accountType === 'premium') {
        // Allow premium features
        res.json({ premiumFeatures: ['feature1', 'feature2'] });
    } else {
        res.json({ basicFeatures: ['feature1'] });
    }
}
// {/fact}

// Example 13: Proper token verification
// {fact rule=untrusted-data-in-decision@v1.0 defects=0}
function good_case_13(req: Request, res: Response) {
    const authHeader = req.headers.authorization as string;
    
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.substring(7);
        
        try {
            // Verify token
            const decodedToken = verifyJwtToken(token);
            
            // ok: typescript-untrusted-data-in-decision-making
            if (decodedToken) {
                // Allow access to protected resource
                res.json({ protectedData: 'sensitive information' });
            } else {
                res.status(401).json({ error: 'Invalid token' });
            }
        } catch (error) {
            res.status(401).json({ error: 'Invalid token' });
        }
    } else {
        res.status(401).json({ error: 'Authentication required' });
    }
}
// {/fact}

// Example 14: Proper verification status check
// {fact rule=untrusted-data-in-decision@v1.0 defects=0}
function good_case_14(req: Request, res: Response) {
    const userId = req.session.userId;
    
    // Get verification status from database
    const user = getUserFromDatabase(userId);
    
    // ok: typescript-untrusted-data-in-decision-making
    if (user && user.isVerified) {
        // Allow access to verified-only content
        res.json({ verifiedContent: 'exclusive content' });
    } else {
        res.status(403).json({ error: 'Verification required' });
    }
}
// {/fact}

// Example 15: Proper subscription level verification
// {fact rule=untrusted-data-in-decision@v1.0 defects=0}
function good_case_15(req: Request, res: Response) {
    const userId = req.session.userId;
    
    // Get subscription from database
    const subscription = getSubscriptionFromDatabase(userId);
    
    // ok: typescript-untrusted-data-in-decision-making
    if (subscription && subscription.tier === 'enterprise') {
        // Allow enterprise features
        res.json({ enterpriseFeatures: 'advanced analytics' });
    } else {
        res.status(403).json({ error: 'Enterprise subscription required' });
    }
}
// {/fact}

// Helper functions (implementation not shown for brevity)
function getUserFromDatabase(userId: string): any { return { role: 'admin', email: 'admin@admin.company.com', isVerified: true, accountType: 'premium', securityAnswer: 'Smith' }; }
function getPermissionsFromDatabase(userId: string): any { return { level: 10 }; }
function verifyJwtToken(token: string | undefined): any { return { isAdmin: true }; }
function checkResourceOwnership(userId: string, resourceId: string): boolean { return true; }
function getResourceData(resourceId: string): any { return { data: 'resource data' }; }
function sanitizeFilePath(path: string): string { return path.replace(/\.\./g, ''); }
function isPathWithinAllowedDirectory(path: string, allowedDir: string): boolean { return path.startsWith(allowedDir); }
function grantAdminPrivileges(email: string): void {}
function applyRateLimiting(ip: string): void {}
function resetPassword(userId: string): void {}
function getUserSubscription(userId: string): any { return { features: ['premium'] }; }
function verifyApiKey(apiKey: string): boolean { return true; }
function getSubscriptionFromDatabase(userId: string): any { return { tier: 'enterprise' }; }
function performSensitiveOperation(): void {}