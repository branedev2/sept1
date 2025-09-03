import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as kinesis from 'aws-cdk-lib/aws-kinesis';
import * as kms from 'aws-cdk-lib/aws-kms';
import { App, Stack } from 'aws-cdk-lib';

// True Positives (Vulnerable Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_1() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  // ruleid: typescript_cdk_kinesis_disabled_sse
  new kinesis.Stream(stack, 'MyStream', {
    streamName: 'my-stream',
    shardCount: 1,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_2() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  // ruleid: typescript_cdk_kinesis_disabled_sse
  new kinesis.Stream(stack, 'MyStream', {
    streamName: 'my-stream',
    shardCount: 3,
    encryption: kinesis.StreamEncryption.UNENCRYPTED,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_3() {
  class MyStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      // ruleid: typescript_cdk_kinesis_disabled_sse
      const stream = new kinesis.Stream(this, 'MyStream', {
        streamName: 'data-analytics-stream',
        retentionPeriod: cdk.Duration.hours(24),
        shardCount: 1,
      });
    }
  }
  
  const app = new cdk.App();
  new MyStack(app, 'MyStack');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_4() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const streamProps = {
    streamName: 'analytics-stream',
    shardCount: 2,
  };
  
  // ruleid: typescript_cdk_kinesis_disabled_sse
  new kinesis.Stream(stack, 'AnalyticsStream', streamProps);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_5() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  function createStream(id: string, name: string) {
    // ruleid: typescript_cdk_kinesis_disabled_sse
    return new kinesis.Stream(stack, id, {
      streamName: name,
      shardCount: 1,
    });
  }
  
  const stream = createStream('UserActivityStream', 'user-activity');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_6() {
  class DataPipeline extends Construct {
    constructor(scope: Construct, id: string) {
      super(scope, id);
      
      // ruleid: typescript_cdk_kinesis_disabled_sse
      const stream = new kinesis.Stream(this, 'DataStream', {
        streamName: 'data-pipeline',
        shardCount: 2,
        retentionPeriod: cdk.Duration.days(7),
      });
    }
  }
  
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  new DataPipeline(stack, 'Pipeline');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_7() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const encryptionSetting = process.env.ENCRYPT === 'true' 
    ? kinesis.StreamEncryption.KMS 
    : kinesis.StreamEncryption.UNENCRYPTED;
  
  // ruleid: typescript_cdk_kinesis_disabled_sse
  new kinesis.Stream(stack, 'ConditionalStream', {
    streamName: 'conditional-stream',
    shardCount: 1,
    encryption: encryptionSetting, // This could be UNENCRYPTED
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_8() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  for (let i = 1; i <= 3; i++) {
    // ruleid: typescript_cdk_kinesis_disabled_sse
    new kinesis.Stream(stack, `Stream${i}`, {
      streamName: `stream-${i}`,
      shardCount: i,
    });
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_9() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const streamConfigs = [
    { id: 'Stream1', name: 'stream-1', shards: 1 },
    { id: 'Stream2', name: 'stream-2', shards: 2 },
  ];
  
  streamConfigs.forEach(config => {
    // ruleid: typescript_cdk_kinesis_disabled_sse
    new kinesis.Stream(stack, config.id, {
      streamName: config.name,
      shardCount: config.shards,
    });
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_10() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  let streamProps: kinesis.StreamProps = {
    streamName: 'dynamic-stream',
    shardCount: 1,
  };
  
  if (process.env.HIGH_THROUGHPUT === 'true') {
    streamProps = {
      ...streamProps,
      shardCount: 10,
    };
  }
  
  // ruleid: typescript_cdk_kinesis_disabled_sse
  new kinesis.Stream(stack, 'DynamicStream', streamProps);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_11() {
  class StreamStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      // Create multiple streams without encryption
      // ruleid: typescript_cdk_kinesis_disabled_sse
      const stream1 = new kinesis.Stream(this, 'Stream1', {
        streamName: 'stream-1',
        shardCount: 1,
      });
      
      // ruleid: typescript_cdk_kinesis_disabled_sse
      const stream2 = new kinesis.Stream(this, 'Stream2', {
        streamName: 'stream-2',
        shardCount: 2,
      });
    }
  }
  
  const app = new cdk.App();
  new StreamStack(app, 'StreamStack');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_12() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const createStreamWithRetention = (id: string, name: string, retention: cdk.Duration) => {
    // ruleid: typescript_cdk_kinesis_disabled_sse
    return new kinesis.Stream(stack, id, {
      streamName: name,
      shardCount: 1,
      retentionPeriod: retention,
    });
  };
  
  const stream = createStreamWithRetention('RetentionStream', 'retention-stream', cdk.Duration.days(7));
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_13() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  try {
    // ruleid: typescript_cdk_kinesis_disabled_sse
    const stream = new kinesis.Stream(stack, 'TryStream', {
      streamName: 'try-stream',
      shardCount: 1,
    });
  } catch (e) {
    console.error('Failed to create stream', e);
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_14() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const getStreamProps = () => {
    return {
      streamName: 'function-stream',
      shardCount: 1,
    };
  };
  
  // ruleid: typescript_cdk_kinesis_disabled_sse
  new kinesis.Stream(stack, 'FunctionPropsStream', getStreamProps());
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_15() {
  class AnalyticsStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      const isProduction = this.node.tryGetContext('environment') === 'production';
      
      // Even in production, encryption is not enabled
      // ruleid: typescript_cdk_kinesis_disabled_sse
      const stream = new kinesis.Stream(this, 'AnalyticsStream', {
        streamName: isProduction ? 'prod-analytics' : 'dev-analytics',
        shardCount: isProduction ? 5 : 1,
        retentionPeriod: isProduction ? cdk.Duration.days(7) : cdk.Duration.days(1),
      });
    }
  }
  
  const app = new cdk.App();
  new AnalyticsStack(app, 'AnalyticsStack');
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_1() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  // ok: typescript_cdk_kinesis_disabled_sse
  new kinesis.Stream(stack, 'MyStream', {
    streamName: 'my-stream',
    shardCount: 1,
    encryption: kinesis.StreamEncryption.KMS,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_2() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const key = new kms.Key(stack, 'MyKey');
  
  // ok: typescript_cdk_kinesis_disabled_sse
  new kinesis.Stream(stack, 'MyStream', {
    streamName: 'my-stream',
    shardCount: 3,
    encryption: kinesis.StreamEncryption.KMS,
    encryptionKey: key,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_3() {
  class MyStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      // ok: typescript_cdk_kinesis_disabled_sse
      const stream = new kinesis.Stream(this, 'MyStream', {
        streamName: 'data-analytics-stream',
        retentionPeriod: cdk.Duration.hours(24),
        shardCount: 1,
        encryption: kinesis.StreamEncryption.MANAGED,
      });
    }
  }
  
  const app = new cdk.App();
  new MyStack(app, 'MyStack');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_4() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const streamProps = {
    streamName: 'analytics-stream',
    shardCount: 2,
    encryption: kinesis.StreamEncryption.KMS,
  };
  
  // ok: typescript_cdk_kinesis_disabled_sse
  new kinesis.Stream(stack, 'AnalyticsStream', streamProps);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_5() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  function createSecureStream(id: string, name: string) {
    // ok: typescript_cdk_kinesis_disabled_sse
    return new kinesis.Stream(stack, id, {
      streamName: name,
      shardCount: 1,
      encryption: kinesis.StreamEncryption.MANAGED,
    });
  }
  
  const stream = createSecureStream('UserActivityStream', 'user-activity');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_6() {
  class DataPipeline extends Construct {
    constructor(scope: Construct, id: string) {
      super(scope, id);
      
      const key = new kms.Key(this, 'StreamKey');
      
      // ok: typescript_cdk_kinesis_disabled_sse
      const stream = new kinesis.Stream(this, 'DataStream', {
        streamName: 'data-pipeline',
        shardCount: 2,
        retentionPeriod: cdk.Duration.days(7),
        encryption: kinesis.StreamEncryption.KMS,
        encryptionKey: key,
      });
    }
  }
  
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  new DataPipeline(stack, 'Pipeline');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_7() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  // Always use encryption regardless of environment variable
  const encryptionSetting = process.env.ENCRYPT === 'custom' 
    ? kinesis.StreamEncryption.KMS 
    : kinesis.StreamEncryption.MANAGED;
  
  // ok: typescript_cdk_kinesis_disabled_sse
  new kinesis.Stream(stack, 'ConditionalStream', {
    streamName: 'conditional-stream',
    shardCount: 1,
    encryption: encryptionSetting, // This is always encrypted
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_8() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  for (let i = 1; i <= 3; i++) {
    // ok: typescript_cdk_kinesis_disabled_sse
    new kinesis.Stream(stack, `Stream${i}`, {
      streamName: `stream-${i}`,
      shardCount: i,
      encryption: kinesis.StreamEncryption.MANAGED,
    });
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_9() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const streamConfigs = [
    { id: 'Stream1', name: 'stream-1', shards: 1 },
    { id: 'Stream2', name: 'stream-2', shards: 2 },
  ];
  
  streamConfigs.forEach(config => {
    // ok: typescript_cdk_kinesis_disabled_sse
    new kinesis.Stream(stack, config.id, {
      streamName: config.name,
      shardCount: config.shards,
      encryption: kinesis.StreamEncryption.KMS,
    });
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_10() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  let streamProps: kinesis.StreamProps = {
    streamName: 'dynamic-stream',
    shardCount: 1,
    encryption: kinesis.StreamEncryption.MANAGED,
  };
  
  if (process.env.HIGH_THROUGHPUT === 'true') {
    streamProps = {
      ...streamProps,
      shardCount: 10,
    };
  }
  
  // ok: typescript_cdk_kinesis_disabled_sse
  new kinesis.Stream(stack, 'DynamicStream', streamProps);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_11() {
  class StreamStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      const key = new kms.Key(this, 'StreamKey');
      
      // Create multiple streams with encryption
      // ok: typescript_cdk_kinesis_disabled_sse
      const stream1 = new kinesis.Stream(this, 'Stream1', {
        streamName: 'stream-1',
        shardCount: 1,
        encryption: kinesis.StreamEncryption.KMS,
        encryptionKey: key,
      });
      
      // ok: typescript_cdk_kinesis_disabled_sse
      const stream2 = new kinesis.Stream(this, 'Stream2', {
        streamName: 'stream-2',
        shardCount: 2,
        encryption: kinesis.StreamEncryption.MANAGED,
      });
    }
  }
  
  const app = new cdk.App();
  new StreamStack(app, 'StreamStack');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_12() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const createSecureStreamWithRetention = (id: string, name: string, retention: cdk.Duration) => {
    // ok: typescript_cdk_kinesis_disabled_sse
    return new kinesis.Stream(stack, id, {
      streamName: name,
      shardCount: 1,
      retentionPeriod: retention,
      encryption: kinesis.StreamEncryption.KMS,
    });
  };
  
  const stream = createSecureStreamWithRetention('RetentionStream', 'retention-stream', cdk.Duration.days(7));
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_13() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  try {
    // ok: typescript_cdk_kinesis_disabled_sse
    const stream = new kinesis.Stream(stack, 'TryStream', {
      streamName: 'try-stream',
      shardCount: 1,
      encryption: kinesis.StreamEncryption.MANAGED,
    });
  } catch (e) {
    console.error('Failed to create stream', e);
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_14() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const getSecureStreamProps = () => {
    return {
      streamName: 'function-stream',
      shardCount: 1,
      encryption: kinesis.StreamEncryption.KMS,
    };
  };
  
  // ok: typescript_cdk_kinesis_disabled_sse
  new kinesis.Stream(stack, 'FunctionPropsStream', getSecureStreamProps());
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_15() {
  class AnalyticsStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      const isProduction = this.node.tryGetContext('environment') === 'production';
      
      // In all environments, encryption is enabled
      // ok: typescript_cdk_kinesis_disabled_sse
      const stream = new kinesis.Stream(this, 'AnalyticsStream', {
        streamName: isProduction ? 'prod-analytics' : 'dev-analytics',
        shardCount: isProduction ? 5 : 1,
        retentionPeriod: isProduction ? cdk.Duration.days(7) : cdk.Duration.days(1),
        encryption: isProduction ? kinesis.StreamEncryption.KMS : kinesis.StreamEncryption.MANAGED,
      });
    }
  }
  
  const app = new cdk.App();
  new AnalyticsStack(app, 'AnalyticsStack');
}
// {/fact}