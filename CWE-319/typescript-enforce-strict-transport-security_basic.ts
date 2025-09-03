import express from 'express';
import helmet from 'helmet';
import { Request, Response, NextFunction } from 'express';

// TRUE POSITIVES (Vulnerable/Insecure Code)

// Bad Case 1: No HSTS header set at all
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_1() {
    const app = express();
    
    app.use((req: Request, res: Response, next: NextFunction) => {
        // No security headers set
        // ruleid: typescript-enforce-strict-transport-security
        next();
    });
    
    app.listen(3000);
}
// {/fact}

// Bad Case 2: HSTS header with insufficient max-age (too short)
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_2() {
    const app = express();
    
    app.use((req: Request, res: Response, next: NextFunction) => {
        // ruleid: typescript-enforce-strict-transport-security
        res.setHeader('Strict-Transport-Security', 'max-age=86400'); // Only 1 day
        next();
    });
    
    app.listen(3000);
}
// {/fact}

// Bad Case 3: HSTS header missing includeSubDomains directive
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_3() {
    const app = express();
    
    app.use((req: Request, res: Response, next: NextFunction) => {
        // ruleid: typescript-enforce-strict-transport-security
        res.setHeader('Strict-Transport-Security', 'max-age=31536000'); // Missing includeSubDomains
        next();
    });
    
    app.listen(3000);
}
// {/fact}

// Bad Case 4: HSTS header with includeSubDomains set to false
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_4() {
    const app = express();
    
    app.use((req: Request, res: Response, next: NextFunction) => {
        // ruleid: typescript-enforce-strict-transport-security
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains=false');
        next();
    });
    
    app.listen(3000);
}
// {/fact}

// Bad Case 5: Using helmet but with insufficient max-age
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_5() {
    const app = express();
    
    // ruleid: typescript-enforce-strict-transport-security
    app.use(helmet.hsts({
        maxAge: 10000, // Too short
        includeSubDomains: true
    }));
    
    app.listen(3000);
}
// {/fact}

// Bad Case 6: Using helmet with includeSubDomains set to false
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_6() {
    const app = express();
    
    // ruleid: typescript-enforce-strict-transport-security
    app.use(helmet.hsts({
        maxAge: 15552000,
        includeSubDomains: false // Should be true
    }));
    
    app.listen(3000);
}
// {/fact}

// Bad Case 7: Setting HSTS header directly with both issues
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_7() {
    const app = express();
    
    app.use((req: Request, res: Response, next: NextFunction) => {
        // ruleid: typescript-enforce-strict-transport-security
        res.setHeader('Strict-Transport-Security', 'max-age=10000'); // Too short and no includeSubDomains
        next();
    });
    
    app.listen(3000);
}
// {/fact}

// Bad Case 8: Setting HSTS header with wrong format
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_8() {
    const app = express();
    
    app.use((req: Request, res: Response, next: NextFunction) => {
        // ruleid: typescript-enforce-strict-transport-security
        res.setHeader('Strict-Transport-Security', 'maxage=31536000; includeSubDomains=true'); // Wrong format
        next();
    });
    
    app.listen(3000);
}
// {/fact}

// Bad Case 9: Using custom middleware with insufficient HSTS settings
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_9() {
    const app = express();
    
    const securityMiddleware = (req: Request, res: Response, next: NextFunction) => {
        // ruleid: typescript-enforce-strict-transport-security
        res.setHeader('Strict-Transport-Security', 'max-age=15000000; includeSubDomains=false');
        next();
    };
    
    app.use(securityMiddleware);
    app.listen(3000);
}
// {/fact}

// Bad Case 10: Using helmet with disabled HSTS
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_10() {
    const app = express();
    
    // ruleid: typescript-enforce-strict-transport-security
    app.use(helmet({
        hsts: false // Disabled HSTS
    }));
    
    app.listen(3000);
}
// {/fact}

// Bad Case 11: Setting HSTS header conditionally but with insufficient settings
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_11() {
    const app = express();
    
    app.use((req: Request, res: Response, next: NextFunction) => {
        if (req.secure) {
            // ruleid: typescript-enforce-strict-transport-security
            res.setHeader('Strict-Transport-Security', 'max-age=8000000'); // Missing includeSubDomains
        }
        next();
    });
    
    app.listen(3000);
}
// {/fact}

// Bad Case 12: Setting HSTS header with typo in directive name
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_12() {
    const app = express();
    
    app.use((req: Request, res: Response, next: NextFunction) => {
        // ruleid: typescript-enforce-strict-transport-security
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomain=true'); // Typo in directive name
        next();
    });
    
    app.listen(3000);
}
// {/fact}

// Bad Case 13: Using helmet with custom options but insufficient max-age
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_13() {
    const app = express();
    
    // ruleid: typescript-enforce-strict-transport-security
    app.use(helmet({
        hsts: {
            maxAge: 100000, // Too short
            includeSubDomains: true
        }
    }));
    
    app.listen(3000);
}
// {/fact}

// Bad Case 14: Setting HSTS header with max-age as a string that's too low
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_14() {
    const app = express();
    
    app.use((req: Request, res: Response, next: NextFunction) => {
        // ruleid: typescript-enforce-strict-transport-security
        res.setHeader('Strict-Transport-Security', 'max-age="1000000"; includeSubDomains=true'); // Too short
        next();
    });
    
    app.listen(3000);
}
// {/fact}

// Bad Case 15: Setting HSTS header with incorrect order of directives
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_15() {
    const app = express();
    
    app.use((req: Request, res: Response, next: NextFunction) => {
        // ruleid: typescript-enforce-strict-transport-security
        res.setHeader('Strict-Transport-Security', 'includeSubDomains=true; max-age=10000'); // Too short max-age
        next();
    });
    
    app.listen(3000);
}
// {/fact}

// TRUE NEGATIVES (Safe/Secure Code)

// Good Case 1: Proper HSTS header with sufficient max-age and includeSubDomains
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_1() {
    const app = express();
    
    app.use((req: Request, res: Response, next: NextFunction) => {
        // ok: typescript-enforce-strict-transport-security
        res.setHeader('Strict-Transport-Security', 'max-age=15552000; includeSubDomains=true');
        next();
    });
    
    app.listen(3000);
}
// {/fact}

// Good Case 2: Using helmet with proper HSTS settings
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_2() {
    const app = express();
    
    // ok: typescript-enforce-strict-transport-security
    app.use(helmet.hsts({
        maxAge: 15552000,
        includeSubDomains: true
    }));
    
    app.listen(3000);
}
// {/fact}

// Good Case 3: Setting HSTS header with higher max-age than required
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_3() {
    const app = express();
    
    app.use((req: Request, res: Response, next: NextFunction) => {
        // ok: typescript-enforce-strict-transport-security
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains=true'); // 1 year
        next();
    });
    
    app.listen(3000);
}
// {/fact}

// Good Case 4: Using helmet with default settings (which are secure)
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_4() {
    const app = express();
    
    // ok: typescript-enforce-strict-transport-security
    app.use(helmet()); // Default HSTS settings are secure
    
    app.listen(3000);
}
// {/fact}

// Good Case 5: Setting HSTS header with preload directive
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_5() {
    const app = express();
    
    app.use((req: Request, res: Response, next: NextFunction) => {
        // ok: typescript-enforce-strict-transport-security
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains=true; preload');
        next();
    });
    
    app.listen(3000);
}
// {/fact}

// Good Case 6: Using helmet with preload option
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_6() {
    const app = express();
    
    // ok: typescript-enforce-strict-transport-security
    app.use(helmet.hsts({
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }));
    
    app.listen(3000);
}
// {/fact}

// Good Case 7: Setting HSTS header with alternative format (no =true)
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_7() {
    const app = express();
    
    app.use((req: Request, res: Response, next: NextFunction) => {
        // ok: typescript-enforce-strict-transport-security
        res.setHeader('Strict-Transport-Security', 'max-age=15552000; includeSubDomains');
        next();
    });
    
    app.listen(3000);
}
// {/fact}

// Good Case 8: Setting HSTS header conditionally with proper settings
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_8() {
    const app = express();
    
    app.use((req: Request, res: Response, next: NextFunction) => {
        if (req.secure) {
            // ok: typescript-enforce-strict-transport-security
            res.setHeader('Strict-Transport-Security', 'max-age=15552000; includeSubDomains');
        }
        next();
    });
    
    app.listen(3000);
}
// {/fact}

// Good Case 9: Using custom middleware with proper HSTS settings
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_9() {
    const app = express();
    
    const securityMiddleware = (req: Request, res: Response, next: NextFunction) => {
        // ok: typescript-enforce-strict-transport-security
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains=true');
        next();
    };
    
    app.use(securityMiddleware);
    app.listen(3000);
}
// {/fact}

// Good Case 10: Setting multiple security headers including proper HSTS
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_10() {
    const app = express();
    
    app.use((req: Request, res: Response, next: NextFunction) => {
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'DENY');
        // ok: typescript-enforce-strict-transport-security
        res.setHeader('Strict-Transport-Security', 'max-age=15552000; includeSubDomains=true');
        next();
    });
    
    app.listen(3000);
}
// {/fact}

// Good Case 11: Using helmet with custom options including proper HSTS
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_11() {
    const app = express();
    
    // ok: typescript-enforce-strict-transport-security
    app.use(helmet({
        hsts: {
            maxAge: 15552000,
            includeSubDomains: true
        },
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"]
            }
        }
    }));
    
    app.listen(3000);
}
// {/fact}

// Good Case 12: Setting HSTS header with exact minimum required max-age
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_12() {
    const app = express();
    
    app.use((req: Request, res: Response, next: NextFunction) => {
        // ok: typescript-enforce-strict-transport-security
        res.setHeader('Strict-Transport-Security', 'max-age=15552000; includeSubDomains=true');
        next();
    });
    
    app.listen(3000);
}
// {/fact}

// Good Case 13: Setting HSTS header with numeric max-age
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_13() {
    const app = express();
    
    const MAX_AGE = 15552000;
    
    app.use((req: Request, res: Response, next: NextFunction) => {
        // ok: typescript-enforce-strict-transport-security
        res.setHeader('Strict-Transport-Security', `max-age=${MAX_AGE}; includeSubDomains=true`);
        next();
    });
    
    app.listen(3000);
}
// {/fact}

// Good Case 14: Using environment variable for max-age with proper minimum value
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_14() {
    const app = express();
    
    // Simulating environment variable
    const HSTS_MAX_AGE = process.env.HSTS_MAX_AGE || '31536000'; // Default to 1 year
    
    app.use((req: Request, res: Response, next: NextFunction) => {
        // ok: typescript-enforce-strict-transport-security
        res.setHeader('Strict-Transport-Security', `max-age=${HSTS_MAX_AGE}; includeSubDomains=true`);
        next();
    });
    
    app.listen(3000);
}
// {/fact}

// Good Case 15: Setting HSTS header with all directives in different order
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_15() {
    const app = express();
    
    app.use((req: Request, res: Response, next: NextFunction) => {
        // ok: typescript-enforce-strict-transport-security
        res.setHeader('Strict-Transport-Security', 'includeSubDomains=true; max-age=31536000; preload');
        next();
    });
    
    app.listen(3000);
}
// {/fact}