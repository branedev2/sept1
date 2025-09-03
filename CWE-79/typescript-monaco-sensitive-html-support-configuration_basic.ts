import * as monaco from 'monaco-editor';

// True Positives (Vulnerable Code)

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1() {
    // Basic case: Setting both supportHtml and isTrusted to true
    monaco.languages.registerHoverProvider('javascript', {
        provideHover: (model, position) => {
            return {
                contents: [
                    { value: '<h1>Hello World</h1>' }
                ],
                // ruleid: monaco-sensitive-html-support-configuration-ts-rule
                supportHtml: true,
                isTrusted: true
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
            const content = model.getValueInRange(model.getWordAtPosition(position)?.range || new monaco.Range(1, 1, 1, 1));
            return {
                contents: [
                    { value: `<div>${content}</div>` }
                ],
                // ruleid: monaco-sensitive-html-support-configuration-ts-rule
                supportHtml: htmlSupport,
                isTrusted: trustContent
            };
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3() {
    // Using object destructuring but still vulnerable
    const hoverOptions = {
        supportHtml: true,
        isTrusted: true
    };
    
    monaco.languages.registerHoverProvider('html', {
        provideHover: (model, position) => {
            return {
                contents: [
                    { value: '<b>Bold text</b>' }
                ],
                // ruleid: monaco-sensitive-html-support-configuration-ts-rule
                ...hoverOptions
            };
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4() {
    // Using a function to create hover options but still vulnerable
    function createHoverOptions(content: string) {
        return {
            contents: [{ value: content }],
            supportHtml: true,
            isTrusted: true
        };
    }
    
    monaco.languages.registerHoverProvider('css', {
        provideHover: (model, position) => {
            // ruleid: monaco-sensitive-html-support-configuration-ts-rule
            return createHoverOptions('<i>Italic text</i>');
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5() {
    // Using conditional logic but still vulnerable
    const isDevEnvironment = process.env.NODE_ENV === 'development';
    
    monaco.languages.registerHoverProvider('json', {
        provideHover: (model, position) => {
            return {
                contents: [
                    { value: '<code>JSON content</code>' }
                ],
                // ruleid: monaco-sensitive-html-support-configuration-ts-rule
                supportHtml: true,
                isTrusted: isDevEnvironment ? true : true // Still both true regardless of condition
            };
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6() {
    // Using a class to encapsulate the hover provider but still vulnerable
    class CustomHoverProvider implements monaco.languages.HoverProvider {
        provideHover(model: monaco.editor.ITextModel, position: monaco.Position) {
            return {
                contents: [
                    { value: '<span style="color:red">Warning!</span>' }
                ],
                // ruleid: monaco-sensitive-html-support-configuration-ts-rule
                supportHtml: true,
                isTrusted: true
            };
        }
    }
    
    monaco.languages.registerHoverProvider('markdown', new CustomHoverProvider());
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7() {
    // Using a factory pattern but still vulnerable
    const hoverProviderFactory = {
        createProvider: (language: string) => {
            return {
                provideHover: (model: monaco.editor.ITextModel, position: monaco.Position) => {
                    return {
                        contents: [
                            { value: '<h2>Section Title</h2>' }
                        ],
                        // ruleid: monaco-sensitive-html-support-configuration-ts-rule
                        supportHtml: true,
                        isTrusted: true
                    };
                }
            };
        }
    };
    
    monaco.languages.registerHoverProvider('yaml', hoverProviderFactory.createProvider('yaml'));
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8() {
    // Using an array of hover providers but still vulnerable
    const providers = [
        {
            language: 'python',
            provider: {
                provideHover: (model: monaco.editor.ITextModel, position: monaco.Position) => {
                    return {
                        contents: [
                            { value: '<pre>Python code</pre>' }
                        ],
                        // ruleid: monaco-sensitive-html-support-configuration-ts-rule
                        supportHtml: true,
                        isTrusted: true
                    };
                }
            }
        }
    ];
    
    providers.forEach(({ language, provider }) => {
        monaco.languages.registerHoverProvider(language, provider);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9() {
    // Using a higher-order function but still vulnerable
    const withHtmlSupport = (provider: monaco.languages.HoverProvider): monaco.languages.HoverProvider => {
        const originalProvideHover = provider.provideHover;
        provider.provideHover = (model, position) => {
            const result = originalProvideHover.call(provider, model, position);
            if (result) {
                // ruleid: monaco-sensitive-html-support-configuration-ts-rule
                result.supportHtml = true;
                result.isTrusted = true;
            }
            return result;
        };
        return provider;
    };
    
    monaco.languages.registerHoverProvider('java', withHtmlSupport({
        provideHover: (model, position) => {
            return {
                contents: [
                    { value: '<em>Java code</em>' }
                ]
            };
        }
    }));
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10() {
    // Using async/await but still vulnerable
    monaco.languages.registerHoverProvider('csharp', {
        provideHover: async (model, position) => {
            const wordAtPosition = model.getWordAtPosition(position);
            const word = wordAtPosition ? model.getValueInRange(wordAtPosition.range) : '';
            
            // Simulate fetching documentation
            const docs = await Promise.resolve(`<p>Documentation for ${word}</p>`);
            
            return {
                contents: [
                    { value: docs }
                ],
                // ruleid: monaco-sensitive-html-support-configuration-ts-rule
                supportHtml: true,
                isTrusted: true
            };
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11() {
    // Using a switch statement but still vulnerable
    const mode = 'html';
    
    monaco.languages.registerHoverProvider('xml', {
        provideHover: (model, position) => {
            let content;
            switch (mode) {
                case 'text':
                    content = 'Plain text';
                    break;
                case 'html':
                    content = '<div>HTML content</div>';
                    break;
                default:
                    content = 'Default content';
            }
            
            return {
                contents: [
                    { value: content }
                ],
                // ruleid: monaco-sensitive-html-support-configuration-ts-rule
                supportHtml: true,
                isTrusted: true
            };
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12() {
    // Using a map to configure multiple languages but still vulnerable
    const languages = ['go', 'rust', 'swift'];
    
    languages.map(language => {
        monaco.languages.registerHoverProvider(language, {
            provideHover: (model, position) => {
                return {
                    contents: [
                        { value: `<strong>${language} code</strong>` }
                    ],
                    // ruleid: monaco-sensitive-html-support-configuration-ts-rule
                    supportHtml: true,
                    isTrusted: true
                };
            }
        });
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13() {
    // Using object property shorthand but still vulnerable
    const supportHtml = true;
    const isTrusted = true;
    
    monaco.languages.registerHoverProvider('php', {
        provideHover: (model, position) => {
            return {
                contents: [
                    { value: '<p>PHP documentation</p>' }
                ],
                // ruleid: monaco-sensitive-html-support-configuration-ts-rule
                supportHtml,
                isTrusted
            };
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14() {
    // Using a ternary operator but still vulnerable
    const isProduction = false;
    
    monaco.languages.registerHoverProvider('sql', {
        provideHover: (model, position) => {
            return {
                contents: [
                    { value: '<table><tr><td>SQL help</td></tr></table>' }
                ],
                // ruleid: monaco-sensitive-html-support-configuration-ts-rule
                supportHtml: isProduction ? true : true,
                isTrusted: isProduction ? true : true
            };
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15() {
    // Using a more complex setup with options object but still vulnerable
    const editorOptions = {
        hoverOptions: {
            html: true,
            trust: true
        }
    };
    
    monaco.languages.registerHoverProvider('ruby', {
        provideHover: (model, position) => {
            return {
                contents: [
                    { value: '<ruby>Ruby code</ruby>' }
                ],
                // ruleid: monaco-sensitive-html-support-configuration-ts-rule
                supportHtml: editorOptions.hoverOptions.html,
                isTrusted: editorOptions.hoverOptions.trust
            };
        }
    });
}
// {/fact}

// True Negatives (Safe Code)

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1() {
    // Basic case: Not setting both flags to true
    monaco.languages.registerHoverProvider('javascript', {
        provideHover: (model, position) => {
            return {
                contents: [
                    { value: 'Hello World' }
                ],
                // ok: monaco-sensitive-html-support-configuration-ts-rule
                supportHtml: false,
                isTrusted: true
            };
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2() {
    // Only setting supportHtml to true, but not isTrusted
    monaco.languages.registerHoverProvider('typescript', {
        provideHover: (model, position) => {
            return {
                contents: [
                    { value: 'TypeScript code' }
                ],
                // ok: monaco-sensitive-html-support-configuration-ts-rule
                supportHtml: true,
                isTrusted: false
            };
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3() {
    // Only setting isTrusted to true, but not supportHtml
    monaco.languages.registerHoverProvider('html', {
        provideHover: (model, position) => {
            return {
                contents: [
                    { value: 'HTML code' }
                ],
                // ok: monaco-sensitive-html-support-configuration-ts-rule
                supportHtml: false,
                isTrusted: true
            };
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4() {
    // Not setting either flag
    monaco.languages.registerHoverProvider('css', {
        provideHover: (model, position) => {
            // ok: monaco-sensitive-html-support-configuration-ts-rule
            return {
                contents: [
                    { value: 'CSS code' }
                ]
            };
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5() {
    // Using variables but not setting both to true
    const htmlSupport = true;
    const trustContent = false;
    
    monaco.languages.registerHoverProvider('json', {
        provideHover: (model, position) => {
            return {
                contents: [
                    { value: 'JSON content' }
                ],
                // ok: monaco-sensitive-html-support-configuration-ts-rule
                supportHtml: htmlSupport,
                isTrusted: trustContent
            };
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6() {
    // Using object destructuring but not both true
    const hoverOptions = {
        supportHtml: false,
        isTrusted: true
    };
    
    monaco.languages.registerHoverProvider('markdown', {
        provideHover: (model, position) => {
            return {
                contents: [
                    { value: 'Markdown content' }
                ],
                // ok: monaco-sensitive-html-support-configuration-ts-rule
                ...hoverOptions
            };
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7() {
    // Using a function to create hover options but safe
    function createHoverOptions(content: string) {
        return {
            contents: [{ value: content }],
            // ok: monaco-sensitive-html-support-configuration-ts-rule
            supportHtml: true,
            isTrusted: false
        };
    }
    
    monaco.languages.registerHoverProvider('yaml', {
        provideHover: (model, position) => {
            return createHoverOptions('YAML content');
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8() {
    // Using conditional logic to ensure both aren't true
    const isDevEnvironment = process.env.NODE_ENV === 'development';
    
    monaco.languages.registerHoverProvider('python', {
        provideHover: (model, position) => {
            return {
                contents: [
                    { value: 'Python content' }
                ],
                // ok: monaco-sensitive-html-support-configuration-ts-rule
                supportHtml: isDevEnvironment,
                isTrusted: !isDevEnvironment // Ensures both can't be true at the same time
            };
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9() {
    // Using a class to encapsulate the hover provider but safe
    class CustomHoverProvider implements monaco.languages.HoverProvider {
        provideHover(model: monaco.editor.ITextModel, position: monaco.Position) {
            return {
                contents: [
                    { value: 'Java content' }
                ],
                // ok: monaco-sensitive-html-support-configuration-ts-rule
                supportHtml: false,
                isTrusted: false
            };
        }
    }
    
    monaco.languages.registerHoverProvider('java', new CustomHoverProvider());
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10() {
    // Using a factory pattern but safe
    const hoverProviderFactory = {
        createProvider: (language: string) => {
            return {
                provideHover: (model: monaco.editor.ITextModel, position: monaco.Position) => {
                    return {
                        contents: [
                            { value: `${language} content` }
                        ],
                        // ok: monaco-sensitive-html-support-configuration-ts-rule
                        supportHtml: false,
                        isTrusted: true
                    };
                }
            };
        }
    };
    
    monaco.languages.registerHoverProvider('csharp', hoverProviderFactory.createProvider('csharp'));
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11() {
    // Using an array of hover providers but safe
    const providers = [
        {
            language: 'go',
            provider: {
                provideHover: (model: monaco.editor.ITextModel, position: monaco.Position) => {
                    return {
                        contents: [
                            { value: 'Go code' }
                        ],
                        // ok: monaco-sensitive-html-support-configuration-ts-rule
                        supportHtml: true,
                        isTrusted: false
                    };
                }
            }
        }
    ];
    
    providers.forEach(({ language, provider }) => {
        monaco.languages.registerHoverProvider(language, provider);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12() {
    // Using a higher-order function but safe
    const withSafeHtmlSupport = (provider: monaco.languages.HoverProvider): monaco.languages.HoverProvider => {
        const originalProvideHover = provider.provideHover;
        provider.provideHover = (model, position) => {
            const result = originalProvideHover.call(provider, model, position);
            if (result) {
                // ok: monaco-sensitive-html-support-configuration-ts-rule
                result.supportHtml = false;
                result.isTrusted = true;
            }
            return result;
        };
        return provider;
    };
    
    monaco.languages.registerHoverProvider('rust', withSafeHtmlSupport({
        provideHover: (model, position) => {
            return {
                contents: [
                    { value: 'Rust code' }
                ]
            };
        }
    }));
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13() {
    // Using async/await but safe
    monaco.languages.registerHoverProvider('swift', {
        provideHover: async (model, position) => {
            const wordAtPosition = model.getWordAtPosition(position);
            const word = wordAtPosition ? model.getValueInRange(wordAtPosition.range) : '';
            
            // Simulate fetching documentation
            const docs = await Promise.resolve(`Documentation for ${word}`);
            
            return {
                contents: [
                    { value: docs }
                ],
                // ok: monaco-sensitive-html-support-configuration-ts-rule
                supportHtml: false,
                isTrusted: false
            };
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14() {
    // Using a switch statement but safe
    const mode = 'html';
    
    monaco.languages.registerHoverProvider('php', {
        provideHover: (model, position) => {
            let supportHtml = false;
            let isTrusted = false;
            
            switch (mode) {
                case 'text':
                    supportHtml = false;
                    isTrusted = true;
                    break;
                case 'html':
                    supportHtml = true;
                    isTrusted = false;
                    break;
                default:
                    supportHtml = false;
                    isTrusted = false;
            }
            
            return {
                contents: [
                    { value: 'PHP content' }
                ],
                // ok: monaco-sensitive-html-support-configuration-ts-rule
                supportHtml,
                isTrusted
            };
        }
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15() {
    // Using a more complex setup with options object but safe
    const editorOptions = {
        hoverOptions: {
            html: true,
            trust: false
        }
    };
    
    monaco.languages.registerHoverProvider('ruby', {
        provideHover: (model, position) => {
            return {
                contents: [
                    { value: 'Ruby code' }
                ],
                // ok: monaco-sensitive-html-support-configuration-ts-rule
                supportHtml: editorOptions.hoverOptions.html,
                isTrusted: editorOptions.hoverOptions.trust
            };
        }
    });
}
// {/fact}