const AWS = require('aws-sdk');
const { CognitoUserPool, CognitoUser, AuthenticationDetails } = require('amazon-cognito-identity-js');

// Configuration for Cognito User Pool
const poolData = {
    UserPoolId: 'ap-southeast-1_F4feest0w',
    ClientId: '21l1hhaf4lo8tskt87bjg8v40o'
};

const userPool = new CognitoUserPool(poolData);

// Promisify authenticateUser
function authenticateUserAsync(username, password) {
    return new Promise((resolve, reject) => {
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
                resolve(session);
            },
            onFailure: (err) => {
                reject(err);
            },
        });
    });
}

// Promisify AWS credentials refresh
function getAWSCredentialsAsync(idToken) {
    return new Promise((resolve, reject) => {
        const logins = {};
        logins[`cognito-idp.ap-southeast-1.amazonaws.com/${poolData.UserPoolId}`] = idToken;

        AWS.config.region = 'ap-southeast-1';

        AWS.config.credentials = new AWS.CognitoIdentityCredentials({
            IdentityPoolId: 'ap-southeast-1:4b14f089-5b51-43dc-ae8e-d4774d9b7259',
            Logins: logins,
        });

        AWS.config.credentials.refresh((error) => {
            if (error) {
                reject(error);
            } else {
                resolve();
            }
        });
    });
}

// Promisify S3 listObjectsV2
function listS3BucketsAsync() {
    return new Promise((resolve, reject) => {
        const s3 = new AWS.S3();
        const params = {
            Bucket: 'tycloud',
        };

        s3.listObjectsV2(params, (err, data) => {
            if (err) {
                reject(err);
            } else {
                resolve(data.Contents);
            }
        });
    });
}

// Main async function
async function main(username, password) {
    try {
        const session = await authenticateUserAsync(username, password);
        const idToken = session.getIdToken().getJwtToken();
        const accessToken = session.getAccessToken().getJwtToken();
        console.log('ID Token:', idToken);
        console.log('Access Token:', accessToken);

        await getAWSCredentialsAsync(idToken);
        console.log('AWS credentials refreshed.');

        const objects = await listS3BucketsAsync();
        console.log('S3 Objects:');
        objects.forEach(obj => console.log(obj.Key));
    } catch (err) {
        console.error('Error:', err.message || JSON.stringify(err));
    }
}

// Call main with username and password
// main('typrone1@gmail.com', '');
