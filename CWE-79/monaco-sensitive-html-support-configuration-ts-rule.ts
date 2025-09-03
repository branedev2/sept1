// File: monaco_hover_provider_test_cases.ts
import * as monaco from 'monaco-editor';

// TRUE POSITIVES (Vulnerable Code)

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1() {
    // Basic case: directly setting both supportHtml and isTrusted to true
    monaco.languages.registerHoverProvider('javascript', {
        provideHover: (model, position) => {
            const word = model.getWordAtPosition(position);
            const content = `<div>Documentation for ${word?.word}</div>`;
            // ruleid: monaco-sensitive-html-support-configuration-ts-rule
            return {
                contents: [
                    { value: content, supportHtml: true, isTrusted: true }
                ]
            };
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2() {
    // Using variables but still setting both flags to true
    const htmlSupport = true;
    const trustContent = true;
    
    monaco.languages.registerHoverProvider('typescript', {
        provideHover: (model, position) => {
            const content = `<b>Type information</b>: ${model.getValueInRange(model.getWordAtPosition(position)!.range)}`;
            // ruleid: monaco-sensitive-html-support-configuration-ts-rule
            return {
                contents: [
                    { value: content, supportHtml: htmlSupport, isTrusted: trustContent }
                ]
            };
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3() {
    // Setting properties in an object first, then using that object
    const hoverOptions = {
        supportHtml: true,
        isTrusted: true
    };
    
    monaco.languages.registerHoverProvider('html', {
        provideHover: (model, position) => {
            const content = `<div class="doc-tooltip">${model.getLineContent(position.lineNumber)}</div>`;
            // ruleid: monaco-sensitive-html-support-configuration-ts-rule
            return {
                contents: [
                    { value: content, ...hoverOptions }
                ]
            };
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4() {
    // Using a function to create hover content with both flags set to true
    function createHoverContent(text: string) {
        return {
            value: `<div>${text}</div>`,
            supportHtml: true,
            isTrusted: true
        };
    }
    
    monaco.languages.registerHoverProvider('css', {
        provideHover: (model, position) => {
            const text = model.getValueInRange(model.getWordAtPosition(position)!.range);
            // ruleid: monaco-sensitive-html-support-configuration-ts-rule
            return {
                contents: [createHoverContent(text)]
            };
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5() {
    // Multiple hover providers with both flags set to true
    ['javascript', 'typescript', 'html'].forEach(language => {
        monaco.languages.registerHoverProvider(language, {
            provideHover: (model, position) => {
                const content = `<span>${model.getLineContent(position.lineNumber)}</span>`;
                // ruleid: monaco-sensitive-html-support-configuration-ts-rule
                return {
                    contents: [
                        { value: content, supportHtml: true, isTrusted: true }
                    ]
                };
            }
        });
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6() {
    // Using conditional logic but still setting both flags to true
    const isDevEnvironment = process.env.NODE_ENV === 'development';
    
    monaco.languages.registerHoverProvider('markdown', {
        provideHover: (model, position) => {
            const content = isDevEnvironment 
                ? `<div class="dev-info">Debug: ${model.uri.toString()}</div>`
                : `<div>Line: ${position.lineNumber}</div>`;
            
            // ruleid: monaco-sensitive-html-support-configuration-ts-rule
            return {
                contents: [
                    { value: content, supportHtml: true, isTrusted: true }
                ]
            };
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7() {
    // Using a class to manage hover providers but still setting both flags
    class HoverManager {
        registerProviders() {
            monaco.languages.registerHoverProvider('json', {
                provideHover: (model, position) => {
                    const content = `<pre>${JSON.stringify(model.getWordAtPosition(position), null, 2)}</pre>`;
                    // ruleid: monaco-sensitive-html-support-configuration-ts-rule
                    return {
                        contents: [
                            { value: content, supportHtml: true, isTrusted: true }
                        ]
                    };
                }
            });
        }
    }
    
    new HoverManager().registerProviders();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8() {
    // Setting properties dynamically but both end up as true
    const config = {
        html: true,
        trust: true
    };
    
    monaco.languages.registerHoverProvider('python', {
        provideHover: (model, position) => {
            const content = `<div>Python help: ${model.getWordAtPosition(position)?.word}</div>`;
            // ruleid: monaco-sensitive-html-support-configuration-ts-rule
            return {
                contents: [
                    { 
                        value: content, 
                        supportHtml: config.html, 
                        isTrusted: config.trust 
                    }
                ]
            };
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9() {
    // Using a factory function but still setting both flags to true
    function createHoverProvider(language: string) {
        return monaco.languages.registerHoverProvider(language, {
            provideHover: (model, position) => {
                const content = `<div>${language} documentation for: ${model.getWordAtPosition(position)?.word}</div>`;
                // ruleid: monaco-sensitive-html-support-configuration-ts-rule
                return {
                    contents: [
                        { value: content, supportHtml: true, isTrusted: true }
                    ]
                };
            }
        });
    }
    
    createHoverProvider('java');
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10() {
    // Using object destructuring but still setting both flags to true
    const options = { supportHtml: true, isTrusted: true };
    const { supportHtml, isTrusted } = options;
    
    monaco.languages.registerHoverProvider('go', {
        provideHover: (model, position) => {
            const content = `<code>${model.getValueInRange(model.getWordAtPosition(position)!.range)}</code>`;
            // ruleid: monaco-sensitive-html-support-configuration-ts-rule
            return {
                contents: [
                    { value: content, supportHtml, isTrusted }
                ]
            };
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11() {
    // Using a more complex object structure but still setting both flags to true
    const editorConfig = {
        hover: {
            options: {
                supportHtml: true,
                isTrusted: true
            }
        }
    };
    
    monaco.languages.registerHoverProvider('rust', {
        provideHover: (model, position) => {
            const content = `<div class="rust-doc">${model.getWordAtPosition(position)?.word}</div>`;
            // ruleid: monaco-sensitive-html-support-configuration-ts-rule
            return {
                contents: [
                    { 
                        value: content, 
                        supportHtml: editorConfig.hover.options.supportHtml, 
                        isTrusted: editorConfig.hover.options.isTrusted 
                    }
                ]
            };
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12() {
    // Using a ternary operator but both branches set both flags to true
    const isDarkMode = window.matchMedia('(prefers-color-scheme: dark)').matches;
    
    monaco.languages.registerHoverProvider('csharp', {
        provideHover: (model, position) => {
            const content = isDarkMode
                ? `<div class="dark-theme">${model.getWordAtPosition(position)?.word}</div>`
                : `<div class="light-theme">${model.getWordAtPosition(position)?.word}</div>`;
            
            // ruleid: monaco-sensitive-html-support-configuration-ts-rule
            return {
                contents: [
                    { 
                        value: content, 
                        supportHtml: true, 
                        isTrusted: true 
                    }
                ]
            };
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13() {
    // Setting both flags to true with different syntax (object spread)
    const baseOptions = { supportHtml: true };
    const additionalOptions = { isTrusted: true };
    
    monaco.languages.registerHoverProvider('php', {
        provideHover: (model, position) => {
            const content = `<div class="php-doc">${model.getWordAtPosition(position)?.word}</div>`;
            // ruleid: monaco-sensitive-html-support-configuration-ts-rule
            return {
                contents: [
                    { 
                        value: content, 
                        ...baseOptions,
                        ...additionalOptions
                    }
                ]
            };
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14() {
    // Using a function to determine values but still setting both flags to true
    function getHoverOptions(language: string) {
        if (language === 'xml') {
            return { supportHtml: true, isTrusted: true };
        }
        return { supportHtml: false, isTrusted: false };
    }
    
    monaco.languages.registerHoverProvider('xml', {
        provideHover: (model, position) => {
            const content = `<div>${model.getWordAtPosition(position)?.word}</div>`;
            const options = getHoverOptions('xml');
            // ruleid: monaco-sensitive-html-support-configuration-ts-rule
            return {
                contents: [
                    { 
                        value: content, 
                        supportHtml: options.supportHtml, 
                        isTrusted: options.isTrusted 
                    }
                ]
            };
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15() {
    // Using logical operators but still resulting in both flags being true
    const enableHtml = true;
    const trustContent = true;
    
    monaco.languages.registerHoverProvider('yaml', {
        provideHover: (model, position) => {
            const content = `<pre>${model.getLineContent(position.lineNumber)}</pre>`;
            // ruleid: monaco-sensitive-html-support-configuration-ts-rule
            return {
                contents: [
                    { 
                        value: content, 
                        supportHtml: enableHtml && true, 
                        isTrusted: trustContent || false 
                    }
                ]
            };
        }
    });
}
// {/fact}

// TRUE NEGATIVES (Safe Code)

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1() {
    // Setting supportHtml to true but isTrusted to false
    monaco.languages.registerHoverProvider('javascript', {
        provideHover: (model, position) => {
            const word = model.getWordAtPosition(position);
            const content = `<div>Documentation for ${word?.word}</div>`;
            // ok: monaco-sensitive-html-support-configuration-ts-rule
            return {
                contents: [
                    { value: content, supportHtml: true, isTrusted: false }
                ]
            };
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2() {
    // Setting supportHtml to false and isTrusted to true
    monaco.languages.registerHoverProvider('typescript', {
        provideHover: (model, position) => {
            const content = `<b>Type information</b>: ${model.getValueInRange(model.getWordAtPosition(position)!.range)}`;
            // ok: monaco-sensitive-html-support-configuration-ts-rule
            return {
                contents: [
                    { value: content, supportHtml: false, isTrusted: true }
                ]
            };
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3() {
    // Not setting either flag (defaults to false)
    monaco.languages.registerHoverProvider('html', {
        provideHover: (model, position) => {
            const content = `Documentation for line ${position.lineNumber}`;
            // ok: monaco-sensitive-html-support-configuration-ts-rule
            return {
                contents: [
                    { value: content }
                ]
            };
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4() {
    // Setting both flags to false explicitly
    monaco.languages.registerHoverProvider('css', {
        provideHover: (model, position) => {
            const content = `CSS property: ${model.getWordAtPosition(position)?.word}`;
            // ok: monaco-sensitive-html-support-configuration-ts-rule
            return {
                contents: [
                    { value: content, supportHtml: false, isTrusted: false }
                ]
            };
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5() {
    // Using a sanitization library before displaying HTML content
    import { sanitize } from 'some-html-sanitizer';
    
    monaco.languages.registerHoverProvider('markdown', {
        provideHover: (model, position) => {
            const rawContent = `<div>${model.getWordAtPosition(position)?.word}</div>`;
            const sanitizedContent = sanitize(rawContent);
            // ok: monaco-sensitive-html-support-configuration-ts-rule
            return {
                contents: [
                    { value: sanitizedContent, supportHtml: true, isTrusted: false }
                ]
            };
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6() {
    // Using a different API that doesn't have these security implications
    monaco.languages.registerHoverProvider('json', {
        provideHover: (model, position) => {
            const word = model.getWordAtPosition(position)?.word;
            // ok: monaco-sensitive-html-support-configuration-ts-rule
            return {
                contents: [word || '']
            };
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7() {
    // Using markdown instead of HTML for rich content
    monaco.languages.registerHoverProvider('python', {
        provideHover: (model, position) => {
            const word = model.getWordAtPosition(position)?.word;
            const content = `**${word}**: Python built-in function`;
            // ok: monaco-sensitive-html-support-configuration-ts-rule
            return {
                contents: [
                    { value: content, supportThemeIcons: true }
                ]
            };
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8() {
    // Using conditional logic to ensure both flags are never true simultaneously
    const enableHtml = true;
    
    monaco.languages.registerHoverProvider('java', {
        provideHover: (model, position) => {
            const content = `<div>Java class: ${model.getWordAtPosition(position)?.word}</div>`;
            // ok: monaco-sensitive-html-support-configuration-ts-rule
            return {
                contents: [
                    { 
                        value: content, 
                        supportHtml: enableHtml, 
                        isTrusted: enableHtml ? false : true 
                    }
                ]
            };
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9() {
    // Using a factory function that ensures safe configuration
    function createSafeHoverProvider(language: string) {
        return monaco.languages.registerHoverProvider(language, {
            provideHover: (model, position) => {
                const content = `${language} documentation for: ${model.getWordAtPosition(position)?.word}`;
                // ok: monaco-sensitive-html-support-configuration-ts-rule
                return {
                    contents: [
                        { value: content, supportHtml: false }
                    ]
                };
            }
        });
    }
    
    createSafeHoverProvider('go');
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10() {
    // Using a class with safe hover configuration
    class SafeHoverManager {
        registerProviders() {
            monaco.languages.registerHoverProvider('rust', {
                provideHover: (model, position) => {
                    const word = model.getWordAtPosition(position)?.word || '';
                    // ok: monaco-sensitive-html-support-configuration-ts-rule
                    return {
                        contents: [
                            { value: `Rust symbol: ${word}`, isTrusted: false }
                        ]
                    };
                }
            });
        }
    }
    
    new SafeHoverManager().registerProviders();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11() {
    // Using object spread but ensuring safe configuration
    const baseOptions = { supportHtml: true };
    const safeOptions = { isTrusted: false };
    
    monaco.languages.registerHoverProvider('csharp', {
        provideHover: (model, position) => {
            const content = `<div class="cs-doc">${model.getWordAtPosition(position)?.word}</div>`;
            // ok: monaco-sensitive-html-support-configuration-ts-rule
            return {
                contents: [
                    { 
                        value: content, 
                        ...baseOptions,
                        ...safeOptions
                    }
                ]
            };
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12() {
    // Using a more complex object structure with safe configuration
    const editorConfig = {
        hover: {
            options: {
                supportHtml: false,
                isTrusted: true
            }
        }
    };
    
    monaco.languages.registerHoverProvider('php', {
        provideHover: (model, position) => {
            const content = `PHP function: ${model.getWordAtPosition(position)?.word}`;
            // ok: monaco-sensitive-html-support-configuration-ts-rule
            return {
                contents: [
                    { 
                        value: content, 
                        supportHtml: editorConfig.hover.options.supportHtml, 
                        isTrusted: editorConfig.hover.options.isTrusted 
                    }
                ]
            };
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13() {
    // Using environment variables to control configuration safely
    const isDev = process.env.NODE_ENV === 'development';
    
    monaco.languages.registerHoverProvider('xml', {
        provideHover: (model, position) => {
            const content = `XML tag: ${model.getWordAtPosition(position)?.word}`;
            // ok: monaco-sensitive-html-support-configuration-ts-rule
            return {
                contents: [
                    { 
                        value: content, 
                        supportHtml: isDev, 
                        isTrusted: false 
                    }
                ]
            };
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14() {
    // Using a function to determine values with safe configuration
    function getHoverOptions(language: string) {
        if (language === 'yaml') {
            return { supportHtml: true, isTrusted: false };
        }
        return { supportHtml: false, isTrusted: false };
    }
    
    monaco.languages.registerHoverProvider('yaml', {
        provideHover: (model, position) => {
            const content = `YAML key: ${model.getWordAtPosition(position)?.word}`;
            const options = getHoverOptions('yaml');
            // ok: monaco-sensitive-html-support-configuration-ts-rule
            return {
                contents: [
                    { 
                        value: content, 
                        supportHtml: options.supportHtml, 
                        isTrusted: options.isTrusted 
                    }
                ]
            };
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15() {
    // Using a different approach to provide hover content
    monaco.languages.registerHoverProvider('sql', {
        provideHover: (model, position) => {
            const word = model.getWordAtPosition(position)?.word;
            // ok: monaco-sensitive-html-support-configuration-ts-rule
            return {
                contents: [
                    { value: '**SQL Keyword**' },
                    { value: `\`${word}\` is a SQL reserved keyword` }
                ]
            };
        }
    });
}
// {/fact}