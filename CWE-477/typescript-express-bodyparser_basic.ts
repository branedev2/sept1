import express from 'express';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import multer from 'multer';
import { Request, Response, NextFunction } from 'express';

// TRUE POSITIVES (Vulnerable/Insecure Code)

// {fact rule=deprecated-method@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  // ruleid: typescript-express-bodyparser
  app.use(bodyParser.json());
  app.use(bodyParser.urlencoded({ extended: true }));
  
  app.post('/api/users', (req: Request, res: Response) => {
    const user = req.body;
    res.json({ message: 'User created', user });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  // ruleid: typescript-express-bodyparser
  app.use(bodyParser.json({ limit: '10mb' }));
  
  app.post('/api/upload', (req: Request, res: Response) => {
    res.send('Upload successful');
  });
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  const jsonParser = bodyParser.json();
  const urlencodedParser = bodyParser.urlencoded({ extended: false });
  
  // ruleid: typescript-express-bodyparser
  app.post('/api/profile', jsonParser, (req: Request, res: Response) => {
    res.json(req.body);
  });
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  // ruleid: typescript-express-bodyparser
  app.use('/api', bodyParser.json());
  app.use('/api', bodyParser.urlencoded({ extended: true }));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=1}
function bad_case_5() {
  class ApiServer {
    constructor() {
      this.app = express();
      // ruleid: typescript-express-bodyparser
      this.app.use(bodyParser.json());
    }
    
    start() {
      this.app.listen(3000);
    }
  }
  
  const server = new ApiServer();
  server.start();
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=1}
function bad_case_6() {
  const app = express();
  const router = express.Router();
  
  // ruleid: typescript-express-bodyparser
  router.use(bodyParser.json());
  
  app.use('/api/v1', router);
  app.listen(3000);
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=1}
function bad_case_7() {
  const setupMiddleware = (app: express.Application) => {
    // ruleid: typescript-express-bodyparser
    app.use(bodyParser.raw({ type: 'application/vnd.custom-type' }));
    app.use(cookieParser());
  };
  
  const app = express();
  setupMiddleware(app);
  app.listen(3000);
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  
  if (process.env.NODE_ENV === 'production') {
    // ruleid: typescript-express-bodyparser
    app.use(bodyParser.json({ limit: '1mb' }));
  } else {
    // ruleid: typescript-express-bodyparser
    app.use(bodyParser.json({ limit: '10mb' }));
  }
  
  app.listen(3000);
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  const jsonParserWithLimit = bodyParser.json({ limit: '5mb' });
  const urlencodedParserWithLimit = bodyParser.urlencoded({ extended: true, limit: '5mb' });
  
  // ruleid: typescript-express-bodyparser
  app.post('/api/data', jsonParserWithLimit, (req: Request, res: Response) => {
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  const apiRouter = express.Router();
  const authRouter = express.Router();
  
  // ruleid: typescript-express-bodyparser
  apiRouter.use(bodyParser.json());
  // ruleid: typescript-express-bodyparser
  authRouter.use(bodyParser.urlencoded({ extended: true }));
  
  app.use('/api', apiRouter);
  app.use('/auth', authRouter);
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  
  const parseJson = () => {
    // ruleid: typescript-express-bodyparser
    return bodyParser.json();
  };
  
  app.use(parseJson());
  app.listen(3000);
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=1}
function bad_case_12() {
  const app = express();
  
  const middleware = [
    cookieParser(),
    // ruleid: typescript-express-bodyparser
    bodyParser.json(),
    // ruleid: typescript-express-bodyparser
    bodyParser.urlencoded({ extended: true })
  ];
  
  app.use(middleware);
  app.listen(3000);
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  
  // ruleid: typescript-express-bodyparser
  app.use(bodyParser.text({ type: 'text/html' }));
  
  app.post('/api/html', (req: Request, res: Response) => {
    const htmlContent = req.body;
    res.send(`Received HTML: ${htmlContent.length} characters`);
  });
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=1}
function bad_case_14() {
  const configureExpress = () => {
    const app = express();
    
    // ruleid: typescript-express-bodyparser
    app.use(bodyParser.json({ verify: (req, res, buf) => {
      req.rawBody = buf;
    }}));
    
    return app;
  };
  
  const app = configureExpress();
  app.listen(3000);
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  
  class RequestHandler {
    static configureBodyParsers(app: express.Application) {
      // ruleid: typescript-express-bodyparser
      app.use(bodyParser.json());
      // ruleid: typescript-express-bodyparser
      app.use(bodyParser.urlencoded({ extended: false }));
    }
  }
  
  RequestHandler.configureBodyParsers(app);
  app.listen(3000);
}
// {/fact}

// TRUE NEGATIVES (Safe/Secure Code)

// {fact rule=deprecated-method@v1.0 defects=0}
function good_case_1() {
  const app = express();
  // ok: typescript-express-bodyparser
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  
  app.post('/api/users', (req: Request, res: Response) => {
    const user = req.body;
    res.json({ message: 'User created', user });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=0}
function good_case_2() {
  const app = express();
  // ok: typescript-express-bodyparser
  app.use(express.json({ limit: '10mb' }));
  
  app.post('/api/upload', (req: Request, res: Response) => {
    res.send('Upload successful');
  });
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=0}
function good_case_3() {
  const app = express();
  const jsonParser = express.json();
  const urlencodedParser = express.urlencoded({ extended: false });
  
  // ok: typescript-express-bodyparser
  app.post('/api/profile', jsonParser, (req: Request, res: Response) => {
    res.json(req.body);
  });
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=0}
function good_case_4() {
  const app = express();
  // ok: typescript-express-bodyparser
  app.use('/api', express.json());
  app.use('/api', express.urlencoded({ extended: true }));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=0}
function good_case_5() {
  class ApiServer {
    constructor() {
      this.app = express();
      // ok: typescript-express-bodyparser
      this.app.use(express.json());
    }
    
    start() {
      this.app.listen(3000);
    }
  }
  
  const server = new ApiServer();
  server.start();
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=0}
function good_case_6() {
  const app = express();
  const router = express.Router();
  
  // ok: typescript-express-bodyparser
  router.use(express.json());
  
  app.use('/api/v1', router);
  app.listen(3000);
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=0}
function good_case_7() {
  const setupMiddleware = (app: express.Application) => {
    // ok: typescript-express-bodyparser
    app.use(express.raw({ type: 'application/vnd.custom-type' }));
    app.use(cookieParser());
  };
  
  const app = express();
  setupMiddleware(app);
  app.listen(3000);
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=0}
function good_case_8() {
  const app = express();
  
  if (process.env.NODE_ENV === 'production') {
    // ok: typescript-express-bodyparser
    app.use(express.json({ limit: '1mb' }));
  } else {
    // ok: typescript-express-bodyparser
    app.use(express.json({ limit: '10mb' }));
  }
  
  app.listen(3000);
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=0}
function good_case_9() {
  const app = express();
  // Using multer for file uploads instead of bodyParser
  // ok: typescript-express-bodyparser
  const upload = multer({ dest: 'uploads/' });
  
  app.post('/api/upload', upload.single('file'), (req: Request, res: Response) => {
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=0}
function good_case_10() {
  const app = express();
  const apiRouter = express.Router();
  const authRouter = express.Router();
  
  // ok: typescript-express-bodyparser
  apiRouter.use(express.json());
  // ok: typescript-express-bodyparser
  authRouter.use(express.urlencoded({ extended: true }));
  
  app.use('/api', apiRouter);
  app.use('/auth', authRouter);
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=0}
function good_case_11() {
  const app = express();
  
  const parseJson = () => {
    // ok: typescript-express-bodyparser
    return express.json();
  };
  
  app.use(parseJson());
  app.listen(3000);
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=0}
function good_case_12() {
  const app = express();
  
  const middleware = [
    cookieParser(),
    // ok: typescript-express-bodyparser
    express.json(),
    // ok: typescript-express-bodyparser
    express.urlencoded({ extended: true })
  ];
  
  app.use(middleware);
  app.listen(3000);
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=0}
function good_case_13() {
  const app = express();
  
  // ok: typescript-express-bodyparser
  app.use(express.text({ type: 'text/html' }));
  
  app.post('/api/html', (req: Request, res: Response) => {
    const htmlContent = req.body;
    res.send(`Received HTML: ${htmlContent.length} characters`);
  });
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=0}
function good_case_14() {
  const configureExpress = () => {
    const app = express();
    
    // ok: typescript-express-bodyparser
    app.use(express.json({ verify: (req, res, buf) => {
      req.rawBody = buf;
    }}));
    
    return app;
  };
  
  const app = configureExpress();
  app.listen(3000);
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=0}
function good_case_15() {
  const app = express();
  
  class RequestHandler {
    static configureBodyParsers(app: express.Application) {
      // ok: typescript-express-bodyparser
      app.use(express.json());
      // ok: typescript-express-bodyparser
      app.use(express.urlencoded({ extended: false }));
    }
  }
  
  RequestHandler.configureBodyParsers(app);
  app.listen(3000);
}
// {/fact}