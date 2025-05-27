const AWS = require('aws-sdk');
const { CognitoUserPool, CognitoUser, AuthenticationDetails } = require('amazon-cognito-identity-js');

// Configuration for Cognito User Pool
const poolData = {
  UserPoolId: 'ap-southeast-1_F4feest0w', // Your user pool id here
  ClientId: '21l1hhaf4lo8tskt87bjg8v40o'   // Your client id here
};

const userPool = new CognitoUserPool(poolData);

// Function to authenticate with Cognito and retrieve tokens
function authenticateUser(username, password) {
  const authenticationDetails = new AuthenticationDetails({
    Username: username,
    Password: password,
  });

  const userData = {
    Username: username,
    Pool: userPool,
  };

  const cognitoUser = new CognitoUser(userData);

  cognitoUser.authenticateUser(authenticationDetails, {
    onSuccess: (session) => {
      const idToken = session.getIdToken().getJwtToken();
      const accessToken = session.getAccessToken().getJwtToken();
      console.log('ID Token:', idToken);
      console.log('Access Token:', accessToken);
      
      // Use the ID token to get temporary AWS credentials
      getAWSCredentials(idToken, () => {
        // Once we have valid AWS credentials, list S3 buckets
        listS3Buckets();
      });
    },
    onFailure: (err) => {
      console.error('Authentication failed:', err.message || JSON.stringify(err));
    },
  });
}

// Function to obtain AWS credentials using the ID token
function getAWSCredentials(idToken, callback) {
  const logins = {};
  logins[`cognito-idp.ap-southeast-1.amazonaws.com/${poolData.UserPoolId}`] = idToken;

  AWS.config.region = 'ap-southeast-1';

  AWS.config.credentials = new AWS.CognitoIdentityCredentials({
    IdentityPoolId: 'ap-southeast-1:4b14f089-5b51-43dc-ae8e-d4774d9b7259',
    Logins: logins,
  });

  AWS.config.credentials.refresh((error) => {
    if (error) {
      console.error('Failed to refresh credentials:', error);
    } else {
      console.log('AWS credentials refreshed.');
      callback();
    }
  });
}

// Function to list objects in an S3 bucket
function listS3Buckets() {
  const s3 = new AWS.S3();
  const params = {
    Bucket: 'tycloud', // Your S3 bucket name
  };

  s3.listObjectsV2(params, (err, data) => {
    if (err) {
      console.error('Error listing S3 objects:', err);
    } else {
      console.log('S3 Objects:');
      data.Contents.forEach(obj => console.log(obj.Key));
    }
  });
}

// Call this function with the username and password of a Cognito user
// authenticateUser('typrone1@gmail.com', '');
