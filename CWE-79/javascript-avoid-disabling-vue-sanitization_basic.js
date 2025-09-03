// Vue.js XSS Vulnerability Examples - Disabling Sanitization
// This file demonstrates secure and insecure ways of handling HTML content in Vue.js applications

// Import Vue
import Vue from 'vue';
import axios from 'axios';

// True Positive Examples (Vulnerable Code)

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1() {
  new Vue({
    el: '#app',
    data: {
      userInput: ''
    },
    mounted() {
      axios.get('/api/user-content')
        .then(response => {
          // ruleid: javascript-avoid-disabling-vue-sanitization
          this.userInput = response.data;
          this.$el.innerHTML = this.userInput; // Directly setting innerHTML with user input
        });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2() {
  new Vue({
    el: '#app',
    data: {
      message: ''
    },
    mounted() {
      fetch('/api/message')
        .then(response => response.json())
        .then(data => {
          this.message = data.content;
        });
    },
    template: `
      <div>
        <!-- ruleid: javascript-avoid-disabling-vue-sanitization -->
        <div v-html="message"></div>
      </div>
    `
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3() {
  const userComment = document.getElementById('user-comment').value;
  
  new Vue({
    el: '#app',
    data: {
      comment: userComment
    },
    render(h) {
      // ruleid: javascript-avoid-disabling-vue-sanitization
      return h('div', {
        domProps: {
          innerHTML: this.comment
        }
      });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4() {
  const app = new Vue({
    el: '#app',
    data: {
      notification: ''
    },
    methods: {
      showNotification() {
        axios.get('/api/notifications/latest')
          .then(response => {
            // ruleid: javascript-avoid-disabling-vue-sanitization
            this.$message({
              dangerouslyUseHTMLString: true,
              message: response.data.message
            });
          });
      }
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5() {
  const userProfile = new Vue({
    el: '#profile',
    data: {
      profileData: {}
    },
    mounted() {
      fetch('/api/user/profile')
        .then(response => response.json())
        .then(data => {
          this.profileData = data;
        });
    },
    methods: {
      renderBio() {
        const bioElement = document.getElementById('user-bio');
        // ruleid: javascript-avoid-disabling-vue-sanitization
        bioElement.innerHTML = this.profileData.bio;
      }
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6() {
  Vue.component('user-content', {
    props: ['content'],
    mounted() {
      // ruleid: javascript-avoid-disabling-vue-sanitization
      this.$el.innerHTML = this.content;
    }
  });
  
  new Vue({
    el: '#app',
    data: {
      userContent: ''
    },
    mounted() {
      axios.get('/api/user-generated-content')
        .then(response => {
          this.userContent = response.data.content;
        });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7() {
  const app = new Vue({
    el: '#app',
    data: {
      articles: []
    },
    mounted() {
      fetch('/api/articles')
        .then(response => response.json())
        .then(data => {
          this.articles = data;
        });
    },
    methods: {
      displayArticle(article) {
        // ruleid: javascript-avoid-disabling-vue-sanitization
        this.$notify({
          title: article.title,
          dangerouslyUseHTMLString: true,
          message: article.content
        });
      }
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8() {
  Vue.component('comment-section', {
    data() {
      return {
        comments: []
      };
    },
    mounted() {
      axios.get('/api/comments')
        .then(response => {
          this.comments = response.data;
        });
    },
    methods: {
      renderComment(comment) {
        const commentEl = document.createElement('div');
        // ruleid: javascript-avoid-disabling-vue-sanitization
        commentEl.innerHTML = comment.text;
        this.$el.appendChild(commentEl);
      }
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9() {
  new Vue({
    el: '#app',
    data: {
      htmlContent: ''
    },
    mounted() {
      fetch('/api/html-content')
        .then(response => response.text())
        .then(html => {
          this.htmlContent = html;
        });
    },
    methods: {
      updateContent() {
        const container = this.$refs.container;
        // ruleid: javascript-avoid-disabling-vue-sanitization
        container.innerHTML = this.htmlContent;
      }
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10() {
  const MessageComponent = {
    props: ['messageHtml'],
    template: `
      <!-- ruleid: javascript-avoid-disabling-vue-sanitization -->
      <div v-html="messageHtml"></div>
    `
  };
  
  new Vue({
    el: '#app',
    components: {
      MessageComponent
    },
    data: {
      message: ''
    },
    mounted() {
      axios.get('/api/message')
        .then(response => {
          this.message = response.data.html;
        });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11() {
  Vue.component('rich-text-editor', {
    props: ['initialContent'],
    data() {
      return {
        content: this.initialContent
      };
    },
    mounted() {
      fetch('/api/editor-content')
        .then(response => response.text())
        .then(html => {
          this.content = html;
          // ruleid: javascript-avoid-disabling-vue-sanitization
          this.$el.querySelector('.editor-output').innerHTML = this.content;
        });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12() {
  new Vue({
    el: '#app',
    data: {
      tooltips: {}
    },
    mounted() {
      axios.get('/api/tooltips')
        .then(response => {
          this.tooltips = response.data;
        });
    },
    methods: {
      showTooltip(id) {
        // ruleid: javascript-avoid-disabling-vue-sanitization
        this.$tooltip({
          content: this.tooltips[id],
          dangerouslyUseHTMLString: true
        });
      }
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13() {
  const app = new Vue({
    el: '#app',
    data: {
      userHtml: ''
    },
    mounted() {
      fetch('/api/user-html')
        .then(response => response.text())
        .then(html => {
          this.userHtml = html;
        });
    },
    render(h) {
      // ruleid: javascript-avoid-disabling-vue-sanitization
      return h('div', {
        domProps: {
          innerHTML: this.userHtml
        },
        class: 'user-content'
      });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14() {
  Vue.component('dynamic-template', {
    props: ['templateHtml'],
    render(h) {
      const template = document.createElement('div');
      // ruleid: javascript-avoid-disabling-vue-sanitization
      template.innerHTML = this.templateHtml;
      return h('div', {
        domProps: {
          innerHTML: template.innerHTML
        }
      });
    }
  });
  
  new Vue({
    el: '#app',
    data: {
      template: ''
    },
    mounted() {
      axios.get('/api/template')
        .then(response => {
          this.template = response.data.html;
        });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15() {
  new Vue({
    el: '#app',
    data: {
      announcement: ''
    },
    mounted() {
      fetch('/api/announcements/latest')
        .then(response => response.json())
        .then(data => {
          this.announcement = data.content;
          // ruleid: javascript-avoid-disabling-vue-sanitization
          this.$createElement('div', {
            domProps: {
              innerHTML: this.announcement
            }
          });
        });
    }
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1() {
  new Vue({
    el: '#app',
    data: {
      userInput: ''
    },
    mounted() {
      axios.get('/api/user-content')
        .then(response => {
          // ok: javascript-avoid-disabling-vue-sanitization
          this.userInput = response.data;
          // Using text content instead of innerHTML
          this.$el.textContent = this.userInput;
        });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2() {
  new Vue({
    el: '#app',
    data: {
      message: ''
    },
    mounted() {
      fetch('/api/message')
        .then(response => response.json())
        .then(data => {
          this.message = data.content;
        });
    },
    template: `
      <div>
        <!-- ok: javascript-avoid-disabling-vue-sanitization -->
        <div>{{ message }}</div>
      </div>
    `
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3() {
  const userComment = document.getElementById('user-comment').value;
  
  new Vue({
    el: '#app',
    data: {
      comment: userComment
    },
    render(h) {
      // ok: javascript-avoid-disabling-vue-sanitization
      return h('div', {}, this.comment);
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4() {
  const app = new Vue({
    el: '#app',
    data: {
      notification: ''
    },
    methods: {
      showNotification() {
        axios.get('/api/notifications/latest')
          .then(response => {
            // ok: javascript-avoid-disabling-vue-sanitization
            this.$message({
              message: response.data.message
            });
          });
      }
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5() {
  const userProfile = new Vue({
    el: '#profile',
    data: {
      profileData: {}
    },
    mounted() {
      fetch('/api/user/profile')
        .then(response => response.json())
        .then(data => {
          this.profileData = data;
        });
    },
    methods: {
      renderBio() {
        const bioElement = document.getElementById('user-bio');
        // ok: javascript-avoid-disabling-vue-sanitization
        bioElement.textContent = this.profileData.bio;
      }
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6() {
  Vue.component('user-content', {
    props: ['content'],
    template: `
      <!-- ok: javascript-avoid-disabling-vue-sanitization -->
      <div>{{ content }}</div>
    `
  });
  
  new Vue({
    el: '#app',
    data: {
      userContent: ''
    },
    mounted() {
      axios.get('/api/user-generated-content')
        .then(response => {
          this.userContent = response.data.content;
        });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7() {
  const app = new Vue({
    el: '#app',
    data: {
      articles: []
    },
    mounted() {
      fetch('/api/articles')
        .then(response => response.json())
        .then(data => {
          this.articles = data;
        });
    },
    methods: {
      displayArticle(article) {
        // ok: javascript-avoid-disabling-vue-sanitization
        this.$notify({
          title: article.title,
          message: article.content
        });
      }
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8() {
  Vue.component('comment-section', {
    data() {
      return {
        comments: []
      };
    },
    mounted() {
      axios.get('/api/comments')
        .then(response => {
          this.comments = response.data;
        });
    },
    methods: {
      renderComment(comment) {
        const commentEl = document.createElement('div');
        // ok: javascript-avoid-disabling-vue-sanitization
        commentEl.textContent = comment.text;
        this.$el.appendChild(commentEl);
      }
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9() {
  new Vue({
    el: '#app',
    data: {
      htmlContent: ''
    },
    mounted() {
      fetch('/api/html-content')
        .then(response => response.text())
        .then(html => {
          // ok: javascript-avoid-disabling-vue-sanitization
          // Using DOMPurify to sanitize HTML
          const DOMPurify = require('dompurify');
          this.htmlContent = DOMPurify.sanitize(html);
        });
    },
    template: `
      <div v-html="htmlContent"></div>
    `
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10() {
  const MessageComponent = {
    props: ['messageText'],
    template: `
      <!-- ok: javascript-avoid-disabling-vue-sanitization -->
      <div>{{ messageText }}</div>
    `
  };
  
  new Vue({
    el: '#app',
    components: {
      MessageComponent
    },
    data: {
      message: ''
    },
    mounted() {
      axios.get('/api/message')
        .then(response => {
          this.message = response.data.text;
        });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11() {
  Vue.component('rich-text-editor', {
    props: ['initialContent'],
    data() {
      return {
        content: this.initialContent
      };
    },
    mounted() {
      fetch('/api/editor-content')
        .then(response => response.text())
        .then(html => {
          // ok: javascript-avoid-disabling-vue-sanitization
          const DOMPurify = require('dompurify');
          this.content = DOMPurify.sanitize(html);
          this.$el.querySelector('.editor-output').innerHTML = this.content;
        });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12() {
  new Vue({
    el: '#app',
    data: {
      tooltips: {}
    },
    mounted() {
      axios.get('/api/tooltips')
        .then(response => {
          this.tooltips = response.data;
        });
    },
    methods: {
      showTooltip(id) {
        // ok: javascript-avoid-disabling-vue-sanitization
        this.$tooltip({
          content: this.tooltips[id]
          // No dangerouslyUseHTMLString option
        });
      }
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13() {
  const app = new Vue({
    el: '#app',
    data: {
      userHtml: ''
    },
    mounted() {
      fetch('/api/user-html')
        .then(response => response.text())
        .then(html => {
          this.userHtml = html;
        });
    },
    render(h) {
      // ok: javascript-avoid-disabling-vue-sanitization
      return h('div', {
        attrs: {
          'data-content': this.userHtml
        },
        class: 'user-content'
      }, this.userHtml);
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14() {
  Vue.component('dynamic-template', {
    props: ['templateText'],
    render(h) {
      // ok: javascript-avoid-disabling-vue-sanitization
      return h('div', {}, this.templateText);
    }
  });
  
  new Vue({
    el: '#app',
    data: {
      template: ''
    },
    mounted() {
      axios.get('/api/template')
        .then(response => {
          this.template = response.data.text;
        });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15() {
  new Vue({
    el: '#app',
    data: {
      announcement: ''
    },
    mounted() {
      fetch('/api/announcements/latest')
        .then(response => response.json())
        .then(data => {
          this.announcement = data.content;
          // ok: javascript-avoid-disabling-vue-sanitization
          this.$createElement('div', {}, this.announcement);
        });
    }
  });
}
// {/fact}