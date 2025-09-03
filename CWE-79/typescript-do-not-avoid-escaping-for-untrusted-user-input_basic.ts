import express from 'express';
import * as nunjucks from 'nunjucks';
import * as ejs from 'ejs';
import * as pug from 'pug';
import * as handlebars from 'handlebars';
import * as mustache from 'mustache';
import * as Liquid from 'liquidjs';
import * as eta from 'eta';
import * as doT from 'dot';
import * as marko from 'marko';
import * as twig from 'twig';
import * as dust from 'dustjs-linkedin';
import * as hbs from 'hbs';
import * as consolidate from 'consolidate';
import * as template from 'lodash.template';

// True positives (vulnerable code)

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  const env = nunjucks.configure('views', {
    // ruleid: typescript-do-not-avoid-escaping-for-untrusted-user-input
    autoescape: false,
    express: app
  });
  
  app.get('/profile', (req, res) => {
    const userInput = req.query.name as string;
    res.render('profile', { username: userInput });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  
  // ruleid: typescript-do-not-avoid-escaping-for-untrusted-user-input
  nunjucks.configure('views', { autoescape: false });
  
  app.get('/article', (req, res) => {
    const content = req.body.content;
    res.render('article', { content });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  
  // ruleid: typescript-do-not-avoid-escaping-for-untrusted-user-input
  const env = new nunjucks.Environment(new nunjucks.FileSystemLoader('views'), {
    autoescape: false
  });
  
  app.get('/comment', (req, res) => {
    const comment = req.query.comment as string;
    const rendered = env.render('comment.html', { comment });
    res.send(rendered);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  
  // ruleid: typescript-do-not-avoid-escaping-for-untrusted-user-input
  app.engine('html', ejs.renderFile({ escape: false }));
  
  app.get('/message', (req, res) => {
    const message = req.query.message as string;
    res.render('message.html', { message });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  
  // ruleid: typescript-do-not-avoid-escaping-for-untrusted-user-input
  const options = { autoescape: false };
  nunjucks.configure('views', options);
  
  app.get('/post', (req, res) => {
    const title = req.query.title as string;
    res.render('post', { title });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6() {
  const app = express();
  const options = {
    // ruleid: typescript-do-not-avoid-escaping-for-untrusted-user-input
    autoescape: false,
    watch: true
  };
  
  if (process.env.NODE_ENV === 'development') {
    nunjucks.configure('views', options);
  }
  
  app.get('/review', (req, res) => {
    const review = req.body.review;
    res.render('review', { review });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7() {
  const app = express();
  
  // ruleid: typescript-do-not-avoid-escaping-for-untrusted-user-input
  const engine = new Liquid.Liquid({ autoEscape: false });
  
  app.get('/bio', (req, res) => {
    const bio = req.query.bio as string;
    const result = engine.parseAndRenderSync('bio.liquid', { bio });
    res.send(result);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  
  // ruleid: typescript-do-not-avoid-escaping-for-untrusted-user-input
  app.engine('eta', eta.renderFile({ autoEscape: false }));
  
  app.get('/description', (req, res) => {
    const desc = req.query.desc as string;
    res.render('description.eta', { desc });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  
  // ruleid: typescript-do-not-avoid-escaping-for-untrusted-user-input
  const config = { autoescape: false, noCache: true };
  const environment = nunjucks.configure('views', config);
  
  app.get('/feedback', (req, res) => {
    const feedback = req.body.feedback;
    res.render('feedback', { feedback });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  
  // ruleid: typescript-do-not-avoid-escaping-for-untrusted-user-input
  const pugOptions = { escape: false };
  app.engine('pug', pug.renderFile(pugOptions));
  
  app.get('/user-info', (req, res) => {
    const info = req.query.info as string;
    res.render('user-info.pug', { info });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  
  // ruleid: typescript-do-not-avoid-escaping-for-untrusted-user-input
  const env = nunjucks.configure(['views', 'templates'], {
    autoescape: false,
    trimBlocks: true,
    lstripBlocks: true
  });
  
  app.get('/note', (req, res) => {
    const note = req.query.note as string;
    res.render('note', { note });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12() {
  // ruleid: typescript-do-not-avoid-escaping-for-untrusted-user-input
  const options = { autoescape: false };
  let env;
  
  if (process.env.NODE_ENV === 'production') {
    env = nunjucks.configure('prod-views', options);
  } else {
    env = nunjucks.configure('dev-views', options);
  }
  
  const app = express();
  app.get('/status', (req, res) => {
    const status = req.query.status as string;
    res.send(env.render('status.html', { status }));
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  
  // ruleid: typescript-do-not-avoid-escaping-for-untrusted-user-input
  const hbsOptions = { noEscape: true };
  app.engine('handlebars', handlebars.engine(hbsOptions));
  
  app.get('/profile-card', (req, res) => {
    const userData = req.body.userData;
    res.render('profile-card', { userData });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  
  // ruleid: typescript-do-not-avoid-escaping-for-untrusted-user-input
  const twigOptions = { autoescape: false };
  app.engine('twig', twig.renderFile(twigOptions));
  
  app.get('/blog', (req, res) => {
    const blogContent = req.query.content as string;
    res.render('blog.twig', { blogContent });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  
  // ruleid: typescript-do-not-avoid-escaping-for-untrusted-user-input
  const config = { autoescape: false };
  const env = nunjucks.configure();
  env.opts.autoescape = false;
  
  app.get('/announcement', (req, res) => {
    const announcement = req.query.text as string;
    res.render('announcement', { announcement });
  });
}
// {/fact}

// True negatives (secure code)

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1() {
  const app = express();
  
  // ok: typescript-do-not-avoid-escaping-for-untrusted-user-input
  const env = nunjucks.configure('views', {
    autoescape: true,
    express: app
  });
  
  app.get('/profile', (req, res) => {
    const userInput = req.query.name as string;
    res.render('profile', { username: userInput });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2() {
  const app = express();
  
  // ok: typescript-do-not-avoid-escaping-for-untrusted-user-input
  nunjucks.configure('views'); // Default is autoescape: true
  
  app.get('/article', (req, res) => {
    const content = req.body.content;
    res.render('article', { content });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3() {
  const app = express();
  
  // ok: typescript-do-not-avoid-escaping-for-untrusted-user-input
  const env = new nunjucks.Environment(new nunjucks.FileSystemLoader('views'), {
    autoescape: true
  });
  
  app.get('/comment', (req, res) => {
    const comment = req.query.comment as string;
    const rendered = env.render('comment.html', { comment });
    res.send(rendered);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4() {
  const app = express();
  
  // ok: typescript-do-not-avoid-escaping-for-untrusted-user-input
  app.engine('html', ejs.renderFile({ escape: true }));
  
  app.get('/message', (req, res) => {
    const message = req.query.message as string;
    res.render('message.html', { message });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5() {
  const app = express();
  
  // ok: typescript-do-not-avoid-escaping-for-untrusted-user-input
  const options = { autoescape: true };
  nunjucks.configure('views', options);
  
  app.get('/post', (req, res) => {
    const title = req.query.title as string;
    res.render('post', { title });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6() {
  const app = express();
  
  // ok: typescript-do-not-avoid-escaping-for-untrusted-user-input
  const options = {
    watch: true
    // autoescape defaults to true when not specified
  };
  
  nunjucks.configure('views', options);
  
  app.get('/review', (req, res) => {
    const review = req.body.review;
    res.render('review', { review });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7() {
  const app = express();
  
  // ok: typescript-do-not-avoid-escaping-for-untrusted-user-input
  const engine = new Liquid.Liquid({ autoEscape: true });
  
  app.get('/bio', (req, res) => {
    const bio = req.query.bio as string;
    const result = engine.parseAndRenderSync('bio.liquid', { bio });
    res.send(result);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8() {
  const app = express();
  
  // ok: typescript-do-not-avoid-escaping-for-untrusted-user-input
  app.engine('eta', eta.renderFile({ autoEscape: true }));
  
  app.get('/description', (req, res) => {
    const desc = req.query.desc as string;
    res.render('description.eta', { desc });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9() {
  const app = express();
  
  // ok: typescript-do-not-avoid-escaping-for-untrusted-user-input
  const config = { noCache: true }; // autoescape defaults to true
  const environment = nunjucks.configure('views', config);
  
  app.get('/feedback', (req, res) => {
    const feedback = req.body.feedback;
    res.render('feedback', { feedback });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10() {
  const app = express();
  
  // ok: typescript-do-not-avoid-escaping-for-untrusted-user-input
  const pugOptions = {}; // escape defaults to true
  app.engine('pug', pug.renderFile(pugOptions));
  
  app.get('/user-info', (req, res) => {
    const info = req.query.info as string;
    res.render('user-info.pug', { info });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11() {
  const app = express();
  
  // ok: typescript-do-not-avoid-escaping-for-untrusted-user-input
  const env = nunjucks.configure(['views', 'templates'], {
    autoescape: true,
    trimBlocks: true,
    lstripBlocks: true
  });
  
  app.get('/note', (req, res) => {
    const note = req.query.note as string;
    res.render('note', { note });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12() {
  // ok: typescript-do-not-avoid-escaping-for-untrusted-user-input
  const options = { autoescape: true };
  let env;
  
  if (process.env.NODE_ENV === 'production') {
    env = nunjucks.configure('prod-views', options);
  } else {
    env = nunjucks.configure('dev-views', options);
  }
  
  const app = express();
  app.get('/status', (req, res) => {
    const status = req.query.status as string;
    res.send(env.render('status.html', { status }));
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13() {
  const app = express();
  
  // ok: typescript-do-not-avoid-escaping-for-untrusted-user-input
  const hbsOptions = { noEscape: false }; // Explicitly set to escape
  app.engine('handlebars', handlebars.engine(hbsOptions));
  
  app.get('/profile-card', (req, res) => {
    const userData = req.body.userData;
    res.render('profile-card', { userData });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14() {
  const app = express();
  
  // ok: typescript-do-not-avoid-escaping-for-untrusted-user-input
  const twigOptions = { autoescape: true };
  app.engine('twig', twig.renderFile(twigOptions));
  
  app.get('/blog', (req, res) => {
    const blogContent = req.query.content as string;
    res.render('blog.twig', { blogContent });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15() {
  const app = express();
  
  // ok: typescript-do-not-avoid-escaping-for-untrusted-user-input
  const config = {};  // Default configuration with autoescape enabled
  const env = nunjucks.configure(config);
  
  app.get('/announcement', (req, res) => {
    const announcement = req.query.text as string;
    res.render('announcement', { announcement });
  });
}
// {/fact}