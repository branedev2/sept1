import axios from 'axios';
import { DynamoDB, S3 } from 'aws-sdk';
import { MongoClient } from 'mongodb';
import { Client } from '@elastic/elasticsearch';
import { PrismaClient } from '@prisma/client';
import { GoogleSpreadsheet } from 'google-spreadsheet';
import { GraphQLClient } from 'graphql-request';
import { Octokit } from '@octokit/rest';
import * as AWS from 'aws-sdk';
import * as firebase from 'firebase/app';
import 'firebase/firestore';

// True Positive Examples (Vulnerable Code)

// Example 1: Missing pagination with AWS DynamoDB scan
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
async function bad_case_1() {
  const dynamodb = new DynamoDB.DocumentClient();
  
  try {
    // ruleid: typescript-missing-pagination
    const result = await dynamodb.scan({
      TableName: 'users'
    }).promise();
    
    return result.Items;
  } catch (error) {
    console.error('Error scanning DynamoDB table:', error);
    throw error;
  }
}
// {/fact}

// Example 2: Missing pagination with MongoDB find
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
async function bad_case_2() {
  const client = new MongoClient('mongodb://localhost:27017');
  
  try {
    await client.connect();
    const database = client.db('myDatabase');
    const collection = database.collection('users');
    
    // ruleid: typescript-missing-pagination
    const users = await collection.find({}).toArray();
    
    return users;
  } catch (error) {
    console.error('Error querying MongoDB:', error);
    throw error;
  } finally {
    await client.close();
  }
}
// {/fact}

// Example 3: Missing pagination with S3 listObjects
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
async function bad_case_3() {
  const s3 = new S3();
  
  try {
    // ruleid: typescript-missing-pagination
    const objects = await s3.listObjects({
      Bucket: 'my-bucket'
    }).promise();
    
    return objects.Contents;
  } catch (error) {
    console.error('Error listing S3 objects:', error);
    throw error;
  }
}
// {/fact}

// Example 4: Missing pagination with Elasticsearch search
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
async function bad_case_4() {
  const client = new Client({ node: 'http://localhost:9200' });
  
  try {
    // ruleid: typescript-missing-pagination
    const result = await client.search({
      index: 'users',
      body: {
        query: {
          match_all: {}
        }
      }
    });
    
    return result.body.hits.hits;
  } catch (error) {
    console.error('Error searching Elasticsearch:', error);
    throw error;
  }
}
// {/fact}

// Example 5: Missing pagination with Prisma findMany
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
async function bad_case_5() {
  const prisma = new PrismaClient();
  
  try {
    // ruleid: typescript-missing-pagination
    const users = await prisma.user.findMany();
    
    return users;
  } catch (error) {
    console.error('Error querying with Prisma:', error);
    throw error;
  } finally {
    await prisma.$disconnect();
  }
}
// {/fact}

// Example 6: Missing pagination with Google Sheets API
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
async function bad_case_6() {
  const doc = new GoogleSpreadsheet('1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms');
  
  try {
    await doc.useServiceAccountAuth({
      client_email: 'client-email@example.com',
      private_key: 'private-key',
    });
    await doc.loadInfo();
    const sheet = doc.sheetsByIndex[0];
    
    // ruleid: typescript-missing-pagination
    const rows = await sheet.getRows();
    
    return rows;
  } catch (error) {
    console.error('Error fetching Google Sheet rows:', error);
    throw error;
  }
}
// {/fact}

// Example 7: Missing pagination with GraphQL query
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
async function bad_case_7() {
  const client = new GraphQLClient('https://api.example.com/graphql');
  
  try {
    const query = `
      query {
        users {
          id
          name
          email
        }
      }
    `;
    
    // ruleid: typescript-missing-pagination
    const data = await client.request(query);
    
    return data.users;
  } catch (error) {
    console.error('Error querying GraphQL API:', error);
    throw error;
  }
}
// {/fact}

// Example 8: Missing pagination with GitHub API
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
async function bad_case_8() {
  const octokit = new Octokit({
    auth: 'github-token'
  });
  
  try {
    // ruleid: typescript-missing-pagination
    const { data } = await octokit.issues.listForRepo({
      owner: 'octokit',
      repo: 'rest.js'
    });
    
    return data;
  } catch (error) {
    console.error('Error fetching GitHub issues:', error);
    throw error;
  }
}
// {/fact}

// Example 9: Missing pagination with REST API call
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
async function bad_case_9() {
  try {
    // ruleid: typescript-missing-pagination
    const response = await axios.get('https://api.example.com/users');
    
    return response.data;
  } catch (error) {
    console.error('Error fetching users:', error);
    throw error;
  }
}
// {/fact}

// Example 10: Missing pagination with AWS CloudWatch logs
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
async function bad_case_10() {
  const cloudwatchlogs = new AWS.CloudWatchLogs();
  
  try {
    // ruleid: typescript-missing-pagination
    const logs = await cloudwatchlogs.describeLogGroups().promise();
    
    return logs.logGroups;
  } catch (error) {
    console.error('Error fetching CloudWatch logs:', error);
    throw error;
  }
}
// {/fact}

// Example 11: Missing pagination with Firebase Firestore
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
async function bad_case_11() {
  const db = firebase.firestore();
  
  try {
    // ruleid: typescript-missing-pagination
    const snapshot = await db.collection('users').get();
    const users: any[] = [];
    
    snapshot.forEach(doc => {
      users.push(doc.data());
    });
    
    return users;
  } catch (error) {
    console.error('Error querying Firestore:', error);
    throw error;
  }
}
// {/fact}

// Example 12: Missing pagination with custom API wrapper
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
async function bad_case_12() {
  class ApiClient {
    async getUsers() {
      // ruleid: typescript-missing-pagination
      const response = await axios.get('https://api.example.com/users');
      return response.data;
    }
  }
  
  const client = new ApiClient();
  return await client.getUsers();
}
// {/fact}

// Example 13: Missing pagination with AWS DynamoDB query
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
async function bad_case_13() {
  const dynamodb = new DynamoDB.DocumentClient();
  
  try {
    // ruleid: typescript-missing-pagination
    const result = await dynamodb.query({
      TableName: 'users',
      KeyConditionExpression: 'userId = :userId',
      ExpressionAttributeValues: {
        ':userId': '123'
      }
    }).promise();
    
    return result.Items;
  } catch (error) {
    console.error('Error querying DynamoDB table:', error);
    throw error;
  }
}
// {/fact}

// Example 14: Missing pagination with MongoDB aggregation
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
async function bad_case_14() {
  const client = new MongoClient('mongodb://localhost:27017');
  
  try {
    await client.connect();
    const database = client.db('myDatabase');
    const collection = database.collection('users');
    
    // ruleid: typescript-missing-pagination
    const users = await collection.aggregate([
      { $match: { active: true } },
      { $project: { name: 1, email: 1 } }
    ]).toArray();
    
    return users;
  } catch (error) {
    console.error('Error aggregating MongoDB data:', error);
    throw error;
  } finally {
    await client.close();
  }
}
// {/fact}

// Example 15: Missing pagination with AWS S3 listObjectsV2
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
async function bad_case_15() {
  const s3 = new S3();
  
  try {
    // ruleid: typescript-missing-pagination
    const objects = await s3.listObjectsV2({
      Bucket: 'my-bucket'
    }).promise();
    
    return objects.Contents;
  } catch (error) {
    console.error('Error listing S3 objects:', error);
    throw error;
  }
}
// {/fact}

// True Negative Examples (Secure Code)

// Example 1: Proper pagination with AWS DynamoDB scan
// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
async function good_case_1() {
  const dynamodb = new DynamoDB.DocumentClient();
  const results: any[] = [];
  let lastEvaluatedKey: any = undefined;
  
  try {
    do {
      // ok: typescript-missing-pagination
      const response = await dynamodb.scan({
        TableName: 'users',
        Limit: 100,
        ExclusiveStartKey: lastEvaluatedKey
      }).promise();
      
      if (response.Items) {
        results.push(...response.Items);
      }
      
      lastEvaluatedKey = response.LastEvaluatedKey;
    } while (lastEvaluatedKey);
    
    return results;
  } catch (error) {
    console.error('Error scanning DynamoDB table:', error);
    throw error;
  }
}
// {/fact}

// Example 2: Proper pagination with MongoDB find
// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
async function good_case_2() {
  const client = new MongoClient('mongodb://localhost:27017');
  
  try {
    await client.connect();
    const database = client.db('myDatabase');
    const collection = database.collection('users');
    
    const limit = 100;
    let skip = 0;
    let hasMore = true;
    const results: any[] = [];
    
    while (hasMore) {
      // ok: typescript-missing-pagination
      const batch = await collection.find({})
        .skip(skip)
        .limit(limit)
        .toArray();
      
      results.push(...batch);
      
      if (batch.length < limit) {
        hasMore = false;
      } else {
        skip += limit;
      }
    }
    
    return results;
  } catch (error) {
    console.error('Error querying MongoDB:', error);
    throw error;
  } finally {
    await client.close();
  }
}
// {/fact}

// Example 3: Proper pagination with S3 listObjects
// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
async function good_case_3() {
  const s3 = new S3();
  const allObjects: AWS.S3.Object[] = [];
  let isTruncated = true;
  let marker: string | undefined;
  
  try {
    while (isTruncated) {
      // ok: typescript-missing-pagination
      const response = await s3.listObjects({
        Bucket: 'my-bucket',
        Marker: marker
      }).promise();
      
      if (response.Contents) {
        allObjects.push(...response.Contents);
      }
      
      isTruncated = response.IsTruncated || false;
      marker = response.Contents && response.Contents.length > 0 ? 
        response.Contents[response.Contents.length - 1].Key : 
        undefined;
    }
    
    return allObjects;
  } catch (error) {
    console.error('Error listing S3 objects:', error);
    throw error;
  }
}
// {/fact}

// Example 4: Proper pagination with Elasticsearch search
// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
async function good_case_4() {
  const client = new Client({ node: 'http://localhost:9200' });
  const pageSize = 100;
  let allResults: any[] = [];
  
  try {
    let from = 0;
    let response;
    let total = 0;
    
    do {
      // ok: typescript-missing-pagination
      response = await client.search({
        index: 'users',
        body: {
          query: { match_all: {} },
          from: from,
          size: pageSize
        }
      });
      
      const hits = response.body.hits.hits;
      allResults = allResults.concat(hits);
      
      if (from === 0) {
        total = response.body.hits.total.value;
      }
      
      from += pageSize;
    } while (allResults.length < total);
    
    return allResults;
  } catch (error) {
    console.error('Error searching Elasticsearch:', error);
    throw error;
  }
}
// {/fact}

// Example 5: Proper pagination with Prisma findMany
// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
async function good_case_5() {
  const prisma = new PrismaClient();
  const pageSize = 100;
  let allUsers: any[] = [];
  
  try {
    let skip = 0;
    let batch;
    
    do {
      // ok: typescript-missing-pagination
      batch = await prisma.user.findMany({
        take: pageSize,
        skip: skip
      });
      
      allUsers = allUsers.concat(batch);
      skip += pageSize;
    } while (batch.length === pageSize);
    
    return allUsers;
  } catch (error) {
    console.error('Error querying with Prisma:', error);
    throw error;
  } finally {
    await prisma.$disconnect();
  }
}
// {/fact}

// Example 6: Proper pagination with Google Sheets API
// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
async function good_case_6() {
  const doc = new GoogleSpreadsheet('1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms');
  
  try {
    await doc.useServiceAccountAuth({
      client_email: 'client-email@example.com',
      private_key: 'private-key',
    });
    await doc.loadInfo();
    const sheet = doc.sheetsByIndex[0];
    
    const batchSize = 100;
    let offset = 0;
    let allRows: any[] = [];
    let batch;
    
    do {
      // ok: typescript-missing-pagination
      batch = await sheet.getRows({
        offset: offset,
        limit: batchSize
      });
      
      allRows = allRows.concat(batch);
      offset += batchSize;
    } while (batch.length === batchSize);
    
    return allRows;
  } catch (error) {
    console.error('Error fetching Google Sheet rows:', error);
    throw error;
  }
}
// {/fact}

// Example 7: Proper pagination with GraphQL query
// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
async function good_case_7() {
  const client = new GraphQLClient('https://api.example.com/graphql');
  
  try {
    const pageSize = 100;
    let allUsers: any[] = [];
    let hasNextPage = true;
    let endCursor: string | null = null;
    
    while (hasNextPage) {
      const query = `
        query ($pageSize: Int!, $cursor: String) {
          users(first: $pageSize, after: $cursor) {
            edges {
              node {
                id
                name
                email
              }
            }
            pageInfo {
              endCursor
              hasNextPage
            }
          }
        }
      `;
      
      // ok: typescript-missing-pagination
      const data = await client.request(query, {
        pageSize,
        cursor: endCursor
      });
      
      allUsers = allUsers.concat(data.users.edges.map((edge: any) => edge.node));
      hasNextPage = data.users.pageInfo.hasNextPage;
      endCursor = data.users.pageInfo.endCursor;
    }
    
    return allUsers;
  } catch (error) {
    console.error('Error querying GraphQL API:', error);
    throw error;
  }
}
// {/fact}

// Example 8: Proper pagination with GitHub API
// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
async function good_case_8() {
  const octokit = new Octokit({
    auth: 'github-token'
  });
  
  try {
    const allIssues: any[] = [];
    let page = 1;
    let hasNextPage = true;
    
    while (hasNextPage) {
      // ok: typescript-missing-pagination
      const response = await octokit.issues.listForRepo({
        owner: 'octokit',
        repo: 'rest.js',
        per_page: 100,
        page: page
      });
      
      allIssues.push(...response.data);
      
      if (response.data.length < 100) {
        hasNextPage = false;
      } else {
        page++;
      }
    }
    
    return allIssues;
  } catch (error) {
    console.error('Error fetching GitHub issues:', error);
    throw error;
  }
}
// {/fact}

// Example 9: Proper pagination with REST API call
// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
async function good_case_9() {
  try {
    const pageSize = 100;
    let page = 1;
    let allUsers: any[] = [];
    let response;
    
    do {
      // ok: typescript-missing-pagination
      response = await axios.get('https://api.example.com/users', {
        params: {
          page: page,
          limit: pageSize
        }
      });
      
      allUsers = allUsers.concat(response.data.users);
      page++;
    } while (response.data.users.length === pageSize);
    
    return allUsers;
  } catch (error) {
    console.error('Error fetching users:', error);
    throw error;
  }
}
// {/fact}

// Example 10: Proper pagination with AWS CloudWatch logs
// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
async function good_case_10() {
  const cloudwatchlogs = new AWS.CloudWatchLogs();
  const allLogGroups: AWS.CloudWatchLogs.LogGroup[] = [];
  let nextToken: string | undefined;
  
  try {
    do {
      // ok: typescript-missing-pagination
      const response = await cloudwatchlogs.describeLogGroups({
        nextToken: nextToken
      }).promise();
      
      if (response.logGroups) {
        allLogGroups.push(...response.logGroups);
      }
      
      nextToken = response.nextToken;
    } while (nextToken);
    
    return allLogGroups;
  } catch (error) {
    console.error('Error fetching CloudWatch logs:', error);
    throw error;
  }
}
// {/fact}

// Example 11: Proper pagination with Firebase Firestore
// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
async function good_case_11() {
  const db = firebase.firestore();
  const batchSize = 100;
  const allUsers: any[] = [];
  
  try {
    let lastDoc = null;
    let query;
    let snapshot;
    
    do {
      if (lastDoc) {
        // ok: typescript-missing-pagination
        query = db.collection('users')
          .orderBy('createdAt')
          .startAfter(lastDoc)
          .limit(batchSize);
      } else {
        query = db.collection('users')
          .orderBy('createdAt')
          .limit(batchSize);
      }
      
      snapshot = await query.get();
      
      if (!snapshot.empty) {
        snapshot.forEach(doc => {
          allUsers.push(doc.data());
        });
        
        lastDoc = snapshot.docs[snapshot.docs.length - 1];
      }
    } while (!snapshot.empty && snapshot.docs.length === batchSize);
    
    return allUsers;
  } catch (error) {
    console.error('Error querying Firestore:', error);
    throw error;
  }
}
// {/fact}

// Example 12: Proper pagination with custom API wrapper
// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
async function good_case_12() {
  class ApiClient {
    async getUsers() {
      const pageSize = 100;
      let page = 1;
      let allUsers: any[] = [];
      let response;
      
      do {
        // ok: typescript-missing-pagination
        response = await axios.get('https://api.example.com/users', {
          params: {
            page: page,
            limit: pageSize
          }
        });
        
        allUsers = allUsers.concat(response.data.users);
        page++;
      } while (response.data.users.length === pageSize);
      
      return allUsers;
    }
  }
  
  const client = new ApiClient();
  return await client.getUsers();
}
// {/fact}

// Example 13: Proper pagination with AWS DynamoDB query
// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
async function good_case_13() {
  const dynamodb = new DynamoDB.DocumentClient();
  const results: any[] = [];
  let lastEvaluatedKey: any = undefined;
  
  try {
    do {
      // ok: typescript-missing-pagination
      const response = await dynamodb.query({
        TableName: 'users',
        KeyConditionExpression: 'userId = :userId',
        ExpressionAttributeValues: {
          ':userId': '123'
        },
        Limit: 100,
        ExclusiveStartKey: lastEvaluatedKey
      }).promise();
      
      if (response.Items) {
        results.push(...response.Items);
      }
      
      lastEvaluatedKey = response.LastEvaluatedKey;
    } while (lastEvaluatedKey);
    
    return results;
  } catch (error) {
    console.error('Error querying DynamoDB table:', error);
    throw error;
  }
}
// {/fact}

// Example 14: Proper pagination with MongoDB aggregation
// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
async function good_case_14() {
  const client = new MongoClient('mongodb://localhost:27017');
  
  try {
    await client.connect();
    const database = client.db('myDatabase');
    const collection = database.collection('users');
    
    const batchSize = 100;
    let allUsers: any[] = [];
    
    const cursor = collection.aggregate([
      { $match: { active: true } },
      { $project: { name: 1, email: 1 } }
    ]);
    
    // ok: typescript-missing-pagination
    let batch = await cursor.limit(batchSize).toArray();
    let lastId = batch.length > 0 ? batch[batch.length - 1]._id : null;
    
    allUsers = allUsers.concat(batch);
    
    while (batch.length === batchSize) {
      batch = await collection.aggregate([
        { $match: { active: true, _id: { $gt: lastId } } },
        { $project: { name: 1, email: 1 } },
        { $limit: batchSize }
      ]).toArray();
      
      if (batch.length > 0) {
        allUsers = allUsers.concat(batch);
        lastId = batch[batch.length - 1]._id;
      }
    }
    
    return allUsers;
  } catch (error) {
    console.error('Error aggregating MongoDB data:', error);
    throw error;
  } finally {
    await client.close();
  }
}
// {/fact}

// Example 15: Proper pagination with AWS S3 listObjectsV2
// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
async function good_case_15() {
  const s3 = new S3();
  const allObjects: AWS.S3.Object[] = [];
  let continuationToken: string | undefined;
  
  try {
    do {
      // ok: typescript-missing-pagination
      const response = await s3.listObjectsV2({
        Bucket: 'my-bucket',
        MaxKeys: 1000,
        ContinuationToken: continuationToken
      }).promise();
      
      if (response.Contents) {
        allObjects.push(...response.Contents);
      }
      
      continuationToken = response.NextContinuationToken;
    } while (continuationToken);
    
    return allObjects;
  } catch (error) {
    console.error('Error listing S3 objects:', error);
    throw error;
  }
}
// {/fact}