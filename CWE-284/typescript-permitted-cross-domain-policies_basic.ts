// File: permitted-cross-domain-policies-tests.ts
import * as fs from 'fs';
import * as http from 'http';
import * as express from 'express';
import * as xml2js from 'xml2js';
import { Request, Response } from 'express';

// True Positive Examples (Vulnerable Code)

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_1() {
    // Creating a cross-domain policy file with wildcard domain access
    const crossDomainPolicy = `<?xml version="1.0"?>
    <!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
    <cross-domain-policy>
        <!-- ruleid: typescript-permitted-cross-domain-policies -->
        <site-control permitted-cross-domain-policies="all"/>
        <allow-access-from domain="*" />
    </cross-domain-policy>`;
    
    fs.writeFileSync('crossdomain.xml', crossDomainPolicy);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_2() {
    // Setting up an Express server that serves a permissive cross-domain policy
    const app = express();
    
    app.get('/crossdomain.xml', (req: Request, res: Response) => {
        const policy = `<?xml version="1.0"?>
        <!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
        <cross-domain-policy>
            <!-- ruleid: typescript-permitted-cross-domain-policies -->
            <site-control permitted-cross-domain-policies="all"/>
            <allow-access-from domain="*" secure="false"/>
        </cross-domain-policy>`;
        
        res.type('application/xml');
        res.send(policy);
    });
    
    app.listen(3000);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_3() {
    // Creating a client access policy file with wildcard domain access
    const clientAccessPolicy = `<?xml version="1.0" encoding="utf-8"?>
    <access-policy>
        <cross-domain-access>
            <policy>
                <!-- ruleid: typescript-permitted-cross-domain-policies -->
                <allow-from http-request-headers="*">
                    <domain uri="*"/>
                </allow-from>
                <grant-to>
                    <resource path="/" include-subpaths="true"/>
                </grant-to>
            </policy>
        </cross-domain-access>
    </access-policy>`;
    
    fs.writeFileSync('clientaccesspolicy.xml', clientAccessPolicy);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_4() {
    // Programmatically generating a permissive cross-domain policy
    const domains = ["*"];
    let policyContent = '<?xml version="1.0"?>\n';
    policyContent += '<!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">\n';
    policyContent += '<cross-domain-policy>\n';
    // ruleid: typescript-permitted-cross-domain-policies
    policyContent += '    <site-control permitted-cross-domain-policies="all"/>\n';
    
    for (const domain of domains) {
        policyContent += `    <allow-access-from domain="${domain}" />\n`;
    }
    
    policyContent += '</cross-domain-policy>';
    fs.writeFileSync('crossdomain.xml', policyContent);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_5() {
    // Express server with permissive client access policy
    const app = express();
    
    app.get('/clientaccesspolicy.xml', (req: Request, res: Response) => {
        const policy = `<?xml version="1.0" encoding="utf-8"?>
        <access-policy>
            <cross-domain-access>
                <policy>
                    <!-- ruleid: typescript-permitted-cross-domain-policies -->
                    <allow-from http-request-headers="*">
                        <domain uri="*"/>
                    </allow-from>
                    <grant-to>
                        <resource path="/" include-subpaths="true"/>
                    </grant-to>
                </policy>
            </cross-domain-access>
        </access-policy>`;
        
        res.type('application/xml');
        res.send(policy);
    });
    
    app.listen(3001);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_6() {
    // Creating a cross-domain policy with insecure headers
    const crossDomainPolicy = `<?xml version="1.0"?>
    <!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
    <cross-domain-policy>
        <!-- ruleid: typescript-permitted-cross-domain-policies -->
        <site-control permitted-cross-domain-policies="master-only"/>
        <allow-access-from domain="*" headers="*"/>
    </cross-domain-policy>`;
    
    fs.writeFileSync('crossdomain.xml', crossDomainPolicy);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_7() {
    // Using XML builder to create permissive policy
    const builder = new xml2js.Builder();
    const policy = {
        'cross-domain-policy': {
            // ruleid: typescript-permitted-cross-domain-policies
            'site-control': [{ $: { 'permitted-cross-domain-policies': 'all' } }],
            'allow-access-from': [{ $: { domain: '*', secure: 'false' } }]
        }
    };
    
    const xml = builder.buildObject(policy);
    fs.writeFileSync('crossdomain.xml', xml);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_8() {
    // HTTP server serving permissive cross-domain policy
    const server = http.createServer((req, res) => {
        if (req.url === '/crossdomain.xml') {
            const policy = `<?xml version="1.0"?>
            <!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
            <cross-domain-policy>
                <!-- ruleid: typescript-permitted-cross-domain-policies -->
                <site-control permitted-cross-domain-policies="by-content-type"/>
                <allow-access-from domain="*" />
                <allow-http-request-headers-from domain="*" headers="*"/>
            </cross-domain-policy>`;
            
            res.writeHead(200, { 'Content-Type': 'application/xml' });
            res.end(policy);
        }
    });
    
    server.listen(8080);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_9() {
    // Creating a permissive policy with multiple domains including wildcard
    const domains = ["example.com", "test.com", "*"];
    let policyContent = '<?xml version="1.0"?>\n';
    policyContent += '<!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">\n';
    policyContent += '<cross-domain-policy>\n';
    // ruleid: typescript-permitted-cross-domain-policies
    policyContent += '    <site-control permitted-cross-domain-policies="all"/>\n';
    
    for (const domain of domains) {
        policyContent += `    <allow-access-from domain="${domain}" />\n`;
    }
    
    policyContent += '</cross-domain-policy>';
    fs.writeFileSync('crossdomain.xml', policyContent);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_10() {
    // Express middleware for serving permissive policy
    const app = express();
    
    const serveCrossDomainPolicy = (req: Request, res: Response, next: Function) => {
        if (req.path === '/crossdomain.xml') {
            const policy = `<?xml version="1.0"?>
            <!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
            <cross-domain-policy>
                <!-- ruleid: typescript-permitted-cross-domain-policies -->
                <site-control permitted-cross-domain-policies="all"/>
                <allow-access-from domain="*" />
            </cross-domain-policy>`;
            
            res.type('application/xml');
            return res.send(policy);
        }
        next();
    };
    
    app.use(serveCrossDomainPolicy);
    app.listen(3002);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_11() {
    // Creating a cross-domain policy with permissive socket access
    const crossDomainPolicy = `<?xml version="1.0"?>
    <!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
    <cross-domain-policy>
        <!-- ruleid: typescript-permitted-cross-domain-policies -->
        <site-control permitted-cross-domain-policies="all"/>
        <allow-access-from domain="*" />
        <allow-http-request-headers-from domain="*" headers="*"/>
        <allow-socket-access host="*" port="*" />
    </cross-domain-policy>`;
    
    fs.writeFileSync('crossdomain.xml', crossDomainPolicy);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_12() {
    // Dynamic policy generation with insecure settings
    function generateCrossDomainPolicy(allowAllDomains: boolean): string {
        let policy = '<?xml version="1.0"?>\n';
        policy += '<!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">\n';
        policy += '<cross-domain-policy>\n';
        
        if (allowAllDomains) {
            // ruleid: typescript-permitted-cross-domain-policies
            policy += '    <site-control permitted-cross-domain-policies="all"/>\n';
            policy += '    <allow-access-from domain="*" />\n';
        }
        
        policy += '</cross-domain-policy>';
        return policy;
    }
    
    const xmlPolicy = generateCrossDomainPolicy(true);
    fs.writeFileSync('crossdomain.xml', xmlPolicy);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_13() {
    // Creating a permissive policy with insecure settings for both Flash and Silverlight
    const flashPolicy = `<?xml version="1.0"?>
    <!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
    <cross-domain-policy>
        <!-- ruleid: typescript-permitted-cross-domain-policies -->
        <site-control permitted-cross-domain-policies="all"/>
        <allow-access-from domain="*" secure="false"/>
    </cross-domain-policy>`;
    
    const silverlightPolicy = `<?xml version="1.0" encoding="utf-8"?>
    <access-policy>
        <cross-domain-access>
            <policy>
                <!-- ruleid: typescript-permitted-cross-domain-policies -->
                <allow-from http-request-headers="*">
                    <domain uri="*"/>
                </allow-from>
                <grant-to>
                    <resource path="/" include-subpaths="true"/>
                </grant-to>
            </policy>
        </cross-domain-access>
    </access-policy>`;
    
    fs.writeFileSync('crossdomain.xml', flashPolicy);
    fs.writeFileSync('clientaccesspolicy.xml', silverlightPolicy);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_14() {
    // Express route with permissive policy and dynamic domain
    const app = express();
    
    app.get('/crossdomain.xml', (req: Request, res: Response) => {
        const domain = req.query.domain || "*";
        
        const policy = `<?xml version="1.0"?>
        <!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
        <cross-domain-policy>
            <!-- ruleid: typescript-permitted-cross-domain-policies -->
            <site-control permitted-cross-domain-policies="all"/>
            <allow-access-from domain="${domain}" />
        </cross-domain-policy>`;
        
        res.type('application/xml');
        res.send(policy);
    });
    
    app.listen(3003);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_15() {
    // Creating a cross-domain policy with multiple insecure settings
    const crossDomainPolicy = `<?xml version="1.0"?>
    <!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
    <cross-domain-policy>
        <!-- ruleid: typescript-permitted-cross-domain-policies -->
        <site-control permitted-cross-domain-policies="all"/>
        <allow-access-from domain="*" secure="false"/>
        <allow-http-request-headers-from domain="*" headers="*"/>
        <allow-socket-access host="*" port="*" secure="false"/>
    </cross-domain-policy>`;
    
    fs.writeFileSync('crossdomain.xml', crossDomainPolicy);
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_1() {
    // Creating a cross-domain policy file with restricted domain access
    const crossDomainPolicy = `<?xml version="1.0"?>
    <!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
    <cross-domain-policy>
        <!-- ok: typescript-permitted-cross-domain-policies -->
        <site-control permitted-cross-domain-policies="none"/>
    </cross-domain-policy>`;
    
    fs.writeFileSync('crossdomain.xml', crossDomainPolicy);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_2() {
    // Setting up an Express server that serves a restrictive cross-domain policy
    const app = express();
    
    app.get('/crossdomain.xml', (req: Request, res: Response) => {
        const policy = `<?xml version="1.0"?>
        <!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
        <cross-domain-policy>
            <!-- ok: typescript-permitted-cross-domain-policies -->
            <site-control permitted-cross-domain-policies="master-only"/>
            <allow-access-from domain="trusted-domain.com" secure="true"/>
        </cross-domain-policy>`;
        
        res.type('application/xml');
        res.send(policy);
    });
    
    app.listen(3004);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_3() {
    // Creating a client access policy file with specific domain access
    const clientAccessPolicy = `<?xml version="1.0" encoding="utf-8"?>
    <access-policy>
        <cross-domain-access>
            <policy>
                <!-- ok: typescript-permitted-cross-domain-policies -->
                <allow-from>
                    <domain uri="https://trusted-domain.com"/>
                </allow-from>
                <grant-to>
                    <resource path="/api" include-subpaths="true"/>
                </grant-to>
            </policy>
        </cross-domain-access>
    </access-policy>`;
    
    fs.writeFileSync('clientaccesspolicy.xml', clientAccessPolicy);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_4() {
    // Programmatically generating a restrictive cross-domain policy
    const trustedDomains = ["trusted-domain.com", "api.example.com"];
    let policyContent = '<?xml version="1.0"?>\n';
    policyContent += '<!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">\n';
    policyContent += '<cross-domain-policy>\n';
    // ok: typescript-permitted-cross-domain-policies
    policyContent += '    <site-control permitted-cross-domain-policies="master-only"/>\n';
    
    for (const domain of trustedDomains) {
        policyContent += `    <allow-access-from domain="${domain}" secure="true" />\n`;
    }
    
    policyContent += '</cross-domain-policy>';
    fs.writeFileSync('crossdomain.xml', policyContent);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_5() {
    // Express server with restrictive client access policy
    const app = express();
    
    app.get('/clientaccesspolicy.xml', (req: Request, res: Response) => {
        const policy = `<?xml version="1.0" encoding="utf-8"?>
        <access-policy>
            <cross-domain-access>
                <policy>
                    <!-- ok: typescript-permitted-cross-domain-policies -->
                    <allow-from>
                        <domain uri="https://trusted-domain.com"/>
                        <domain uri="https://api.example.com"/>
                    </allow-from>
                    <grant-to>
                        <resource path="/api" include-subpaths="false"/>
                    </grant-to>
                </policy>
            </cross-domain-access>
        </access-policy>`;
        
        res.type('application/xml');
        res.send(policy);
    });
    
    app.listen(3005);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_6() {
    // Creating a cross-domain policy with secure headers
    const crossDomainPolicy = `<?xml version="1.0"?>
    <!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
    <cross-domain-policy>
        <!-- ok: typescript-permitted-cross-domain-policies -->
        <site-control permitted-cross-domain-policies="by-content-type"/>
        <allow-access-from domain="trusted-domain.com" secure="true"/>
        <allow-http-request-headers-from domain="trusted-domain.com" headers="Authorization, Content-Type"/>
    </cross-domain-policy>`;
    
    fs.writeFileSync('crossdomain.xml', crossDomainPolicy);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_7() {
    // Using XML builder to create restrictive policy
    const builder = new xml2js.Builder();
    const policy = {
        'cross-domain-policy': {
            // ok: typescript-permitted-cross-domain-policies
            'site-control': [{ $: { 'permitted-cross-domain-policies': 'none' } }]
        }
    };
    
    const xml = builder.buildObject(policy);
    fs.writeFileSync('crossdomain.xml', xml);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_8() {
    // HTTP server serving restrictive cross-domain policy
    const server = http.createServer((req, res) => {
        if (req.url === '/crossdomain.xml') {
            const policy = `<?xml version="1.0"?>
            <!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
            <cross-domain-policy>
                <!-- ok: typescript-permitted-cross-domain-policies -->
                <site-control permitted-cross-domain-policies="none"/>
            </cross-domain-policy>`;
            
            res.writeHead(200, { 'Content-Type': 'application/xml' });
            res.end(policy);
        }
    });
    
    server.listen(8081);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_9() {
    // Creating a restrictive policy with specific domains
    const trustedDomains = ["api.example.com", "trusted-domain.com"];
    let policyContent = '<?xml version="1.0"?>\n';
    policyContent += '<!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">\n';
    policyContent += '<cross-domain-policy>\n';
    // ok: typescript-permitted-cross-domain-policies
    policyContent += '    <site-control permitted-cross-domain-policies="master-only"/>\n';
    
    for (const domain of trustedDomains) {
        policyContent += `    <allow-access-from domain="${domain}" secure="true" />\n`;
    }
    
    policyContent += '</cross-domain-policy>';
    fs.writeFileSync('crossdomain.xml', policyContent);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_10() {
    // Express middleware for serving restrictive policy
    const app = express();
    
    const serveCrossDomainPolicy = (req: Request, res: Response, next: Function) => {
        if (req.path === '/crossdomain.xml') {
            const policy = `<?xml version="1.0"?>
            <!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
            <cross-domain-policy>
                <!-- ok: typescript-permitted-cross-domain-policies -->
                <site-control permitted-cross-domain-policies="none"/>
            </cross-domain-policy>`;
            
            res.type('application/xml');
            return res.send(policy);
        }
        next();
    };
    
    app.use(serveCrossDomainPolicy);
    app.listen(3006);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_11() {
    // Creating a cross-domain policy with restricted socket access
    const crossDomainPolicy = `<?xml version="1.0"?>
    <!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
    <cross-domain-policy>
        <!-- ok: typescript-permitted-cross-domain-policies -->
        <site-control permitted-cross-domain-policies="master-only"/>
        <allow-access-from domain="trusted-domain.com" secure="true" />
        <allow-http-request-headers-from domain="trusted-domain.com" headers="Authorization, Content-Type"/>
        <allow-socket-access host="trusted-domain.com" port="443" secure="true" />
    </cross-domain-policy>`;
    
    fs.writeFileSync('crossdomain.xml', crossDomainPolicy);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_12() {
    // Dynamic policy generation with secure settings
    function generateCrossDomainPolicy(allowAllDomains: boolean): string {
        let policy = '<?xml version="1.0"?>\n';
        policy += '<!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">\n';
        policy += '<cross-domain-policy>\n';
        
        if (allowAllDomains) {
            policy += '    <site-control permitted-cross-domain-policies="master-only"/>\n';
            policy += '    <allow-access-from domain="trusted-domain.com" secure="true" />\n';
        } else {
            // ok: typescript-permitted-cross-domain-policies
            policy += '    <site-control permitted-cross-domain-policies="none"/>\n';
        }
        
        policy += '</cross-domain-policy>';
        return policy;
    }
    
    const xmlPolicy = generateCrossDomainPolicy(false);
    fs.writeFileSync('crossdomain.xml', xmlPolicy);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_13() {
    // Creating a restrictive policy for both Flash and Silverlight
    const flashPolicy = `<?xml version="1.0"?>
    <!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
    <cross-domain-policy>
        <!-- ok: typescript-permitted-cross-domain-policies -->
        <site-control permitted-cross-domain-policies="none"/>
    </cross-domain-policy>`;
    
    const silverlightPolicy = `<?xml version="1.0" encoding="utf-8"?>
    <access-policy>
        <cross-domain-access>
            <policy>
                <!-- ok: typescript-permitted-cross-domain-policies -->
                <allow-from>
                    <domain uri="https://trusted-domain.com"/>
                </allow-from>
                <grant-to>
                    <resource path="/api" include-subpaths="false"/>
                </grant-to>
            </policy>
        </cross-domain-access>
    </access-policy>`;
    
    fs.writeFileSync('crossdomain.xml', flashPolicy);
    fs.writeFileSync('clientaccesspolicy.xml', silverlightPolicy);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_14() {
    // Express route with restrictive policy and environment-based domain
    const app = express();
    
    app.get('/crossdomain.xml', (req: Request, res: Response) => {
        const trustedDomain = process.env.TRUSTED_DOMAIN || "trusted-domain.com";
        
        const policy = `<?xml version="1.0"?>
        <!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
        <cross-domain-policy>
            <!-- ok: typescript-permitted-cross-domain-policies -->
            <site-control permitted-cross-domain-policies="master-only"/>
            <allow-access-from domain="${trustedDomain}" secure="true" />
        </cross-domain-policy>`;
        
        res.type('application/xml');
        res.send(policy);
    });
    
    app.listen(3007);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_15() {
    // Creating a cross-domain policy with multiple secure settings
    const crossDomainPolicy = `<?xml version="1.0"?>
    <!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
    <cross-domain-policy>
        <!-- ok: typescript-permitted-cross-domain-policies -->
        <site-control permitted-cross-domain-policies="master-only"/>
        <allow-access-from domain="trusted-domain.com" secure="true"/>
        <allow-http-request-headers-from domain="trusted-domain.com" headers="Authorization, Content-Type"/>
        <allow-socket-access host="trusted-domain.com" port="443" secure="true"/>
    </cross-domain-policy>`;
    
    fs.writeFileSync('crossdomain.xml', crossDomainPolicy);
}
// {/fact}