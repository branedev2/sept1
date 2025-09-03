import Vue from 'vue';
import { createApp } from 'vue';

// True Positive Examples (Vulnerable Code)

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1() {
  const app = new Vue({
    el: '#app',
    data: {
      userInput: '<script>alert("XSS")</script>'
    },
    template: '<div v-html="userInput"></div>' // ruleid: typescript-avoid-disabling-vue-sanitization
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2() {
  const app = createApp({
    data() {
      return {
        message: '<img src=x onerror="alert(\'XSS\')">'
      };
    },
    template: `
      <div>
        <div v-html="message"></div> // ruleid: typescript-avoid-disabling-vue-sanitization
      </div>
    `
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3() {
  const userProvidedHtml = '<script>document.cookie</script>';
  
  new Vue({
    render(h) {
      return h('div', {
        domProps: {
          innerHTML: userProvidedHtml // ruleid: typescript-avoid-disabling-vue-sanitization
        }
      });
    }
  }).$mount('#app');
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4() {
  const fetchedData = '<iframe src="javascript:alert(\'XSS\')"></iframe>';
  
  const app = createApp({
    setup() {
      return {
        content: fetchedData
      };
    },
    template: `<div v-html="content"></div>` // ruleid: typescript-avoid-disabling-vue-sanitization
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5() {
  const userComment = '<img src="x" onerror="alert(document.domain)">';
  
  new Vue({
    methods: {
      displayComment() {
        this.$refs.commentBox.innerHTML = userComment; // ruleid: typescript-avoid-disabling-vue-sanitization
      }
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6() {
  import { h } from 'vue';
  
  const userHtml = '<script>alert("XSS")</script>';
  
  createApp({
    render() {
      return h('div', {
        innerHTML: userHtml // ruleid: typescript-avoid-disabling-vue-sanitization
      });
    }
  }).mount('#app');
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7() {
  const app = createApp({});
  
  app.component('unsafe-component', {
    props: ['content'],
    template: '<div v-html="content"></div>' // ruleid: typescript-avoid-disabling-vue-sanitization
  });
  
  app.mount('#app');
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8() {
  import { MessageBox } from 'element-ui';
  
  const userMessage = '<img src=x onerror="alert(\'XSS\')">';
  
  MessageBox({
    title: 'Message',
    message: userMessage,
    dangerouslyUseHTMLString: true // ruleid: typescript-avoid-disabling-vue-sanitization
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9() {
  import { ElNotification } from 'element-plus';
  
  const userNotification = '<script>alert("Notification XSS")</script>';
  
  ElNotification({
    title: 'Title',
    message: userNotification,
    dangerouslyUseHTMLString: true // ruleid: typescript-avoid-disabling-vue-sanitization
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10() {
  const app = new Vue({
    data: {
      rawHtml: '<div onclick="alert(\'XSS\')">Click me</div>'
    },
    methods: {
      setInnerHTML() {
        this.$el.querySelector('#content').innerHTML = this.rawHtml; // ruleid: typescript-avoid-disabling-vue-sanitization
      }
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11() {
  import { createVNode, render } from 'vue';
  
  const userHtml = '<script>alert("Dynamic XSS")</script>';
  
  const vnode = createVNode('div', {
    innerHTML: userHtml // ruleid: typescript-avoid-disabling-vue-sanitization
  });
  
  render(vnode, document.getElementById('app')!);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12() {
  const app = createApp({
    directives: {
      unsafe: {
        mounted(el, binding) {
          el.innerHTML = binding.value; // ruleid: typescript-avoid-disabling-vue-sanitization
        }
      }
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13() {
  import { Tooltip } from 'element-ui';
  
  const userTooltip = '<img src=x onerror="alert(\'Tooltip XSS\')">';
  
  new Vue({
    components: { Tooltip },
    template: `
      <Tooltip :content="userTooltip" :dangerouslyUseHTMLString="true"> // ruleid: typescript-avoid-disabling-vue-sanitization
        <button>Hover me</button>
      </Tooltip>
    `,
    data() {
      return {
        userTooltip
      };
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14() {
  const app = createApp({});
  
  app.config.compilerOptions.isCustomElement = tag => tag.includes('-');
  app.config.isCustomElement = tag => tag.includes('-');
  
  app.component('blog-post', {
    props: ['content'],
    template: `
      <article>
        <div v-html="content"></div> // ruleid: typescript-avoid-disabling-vue-sanitization
      </article>
    `
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15() {
  import { ElPopover } from 'element-plus';
  
  const userContent = '<img src=x onerror="alert(\'Popover XSS\')">';
  
  createApp({
    components: { ElPopover },
    template: `
      <ElPopover
        :content="userContent"
        :dangerouslyUseHTMLString="true" // ruleid: typescript-avoid-disabling-vue-sanitization
        trigger="click"
      >
        <template #reference>
          <button>Click me</button>
        </template>
      </ElPopover>
    `,
    data() {
      return {
        userContent
      };
    }
  }).mount('#app');
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1() {
  const app = new Vue({
    el: '#app',
    data: {
      userInput: '<script>alert("XSS")</script>'
    },
    template: '<div>{{ userInput }}</div>' // ok: typescript-avoid-disabling-vue-sanitization
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2() {
  const app = createApp({
    data() {
      return {
        message: '<img src=x onerror="alert(\'XSS\')">'
      };
    },
    template: `
      <div>
        <div>{{ message }}</div> // ok: typescript-avoid-disabling-vue-sanitization
      </div>
    `
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3() {
  const userProvidedText = '<script>document.cookie</script>';
  
  new Vue({
    render(h) {
      return h('div', {}, userProvidedText); // ok: typescript-avoid-disabling-vue-sanitization
    }
  }).$mount('#app');
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4() {
  import DOMPurify from 'dompurify';
  
  const fetchedData = '<iframe src="javascript:alert(\'XSS\')"></iframe>';
  const sanitizedData = DOMPurify.sanitize(fetchedData);
  
  const app = createApp({
    setup() {
      return {
        content: sanitizedData
      };
    },
    template: `<div v-html="content"></div>` // ok: typescript-avoid-disabling-vue-sanitization
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5() {
  const userComment = '<img src="x" onerror="alert(document.domain)">';
  
  new Vue({
    methods: {
      displayComment() {
        this.$refs.commentBox.textContent = userComment; // ok: typescript-avoid-disabling-vue-sanitization
      }
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6() {
  import { h } from 'vue';
  import DOMPurify from 'dompurify';
  
  const userHtml = '<script>alert("XSS")</script>';
  const sanitizedHtml = DOMPurify.sanitize(userHtml);
  
  createApp({
    render() {
      return h('div', {
        innerHTML: sanitizedHtml // ok: typescript-avoid-disabling-vue-sanitization
      });
    }
  }).mount('#app');
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7() {
  const app = createApp({});
  
  app.component('safe-component', {
    props: ['content'],
    template: '<div>{{ content }}</div>' // ok: typescript-avoid-disabling-vue-sanitization
  });
  
  app.mount('#app');
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8() {
  import { MessageBox } from 'element-ui';
  
  const userMessage = '<img src=x onerror="alert(\'XSS\')">';
  
  MessageBox({
    title: 'Message',
    message: userMessage,
    dangerouslyUseHTMLString: false // ok: typescript-avoid-disabling-vue-sanitization
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9() {
  import { ElNotification } from 'element-plus';
  
  const userNotification = '<script>alert("Notification XSS")</script>';
  
  ElNotification({
    title: 'Title',
    message: userNotification // ok: typescript-avoid-disabling-vue-sanitization
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10() {
  const app = new Vue({
    data: {
      rawHtml: '<div onclick="alert(\'XSS\')">Click me</div>'
    },
    methods: {
      setTextContent() {
        this.$el.querySelector('#content').textContent = this.rawHtml; // ok: typescript-avoid-disabling-vue-sanitization
      }
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11() {
  import { createVNode, render } from 'vue';
  import DOMPurify from 'dompurify';
  
  const userHtml = '<script>alert("Dynamic XSS")</script>';
  const sanitizedHtml = DOMPurify.sanitize(userHtml);
  
  const vnode = createVNode('div', {
    innerHTML: sanitizedHtml // ok: typescript-avoid-disabling-vue-sanitization
  });
  
  render(vnode, document.getElementById('app')!);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12() {
  const app = createApp({
    directives: {
      safe: {
        mounted(el, binding) {
          el.textContent = binding.value; // ok: typescript-avoid-disabling-vue-sanitization
        }
      }
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13() {
  import { Tooltip } from 'element-ui';
  
  const userTooltip = '<img src=x onerror="alert(\'Tooltip XSS\')">';
  
  new Vue({
    components: { Tooltip },
    template: `
      <Tooltip :content="userTooltip" :dangerouslyUseHTMLString="false"> // ok: typescript-avoid-disabling-vue-sanitization
        <button>Hover me</button>
      </Tooltip>
    `,
    data() {
      return {
        userTooltip
      };
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14() {
  import sanitizeHtml from 'sanitize-html';
  
  const app = createApp({});
  
  app.component('blog-post', {
    props: ['content'],
    computed: {
      sanitizedContent() {
        return sanitizeHtml(this.content); // ok: typescript-avoid-disabling-vue-sanitization
      }
    },
    template: `
      <article>
        <div v-html="sanitizedContent"></div>
      </article>
    `
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15() {
  import { ElPopover } from 'element-plus';
  
  const userContent = '<img src=x onerror="alert(\'Popover XSS\')">';
  
  createApp({
    components: { ElPopover },
    template: `
      <ElPopover
        :content="userContent"
        trigger="click" // ok: typescript-avoid-disabling-vue-sanitization
      >
        <template #reference>
          <button>Click me</button>
        </template>
      </ElPopover>
    `,
    data() {
      return {
        userContent
      };
    }
  }).mount('#app');
}
// {/fact}