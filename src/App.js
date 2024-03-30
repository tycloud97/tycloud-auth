import React, { useState } from 'react';
import AWS from 'aws-sdk';
import { useEffect } from 'react';

import {
  AuthenticationDetails,
  CognitoUserPool,
  CognitoUser,
} from 'amazon-cognito-identity-js';

const poolData = {
  UserPoolId: 'ap-southeast-1_F4feest0w', // Your user pool id here
  ClientId: '21l1hhaf4lo8tskt87bjg8v40o', // Your client id here
};

const userPool = new CognitoUserPool(poolData);

function App() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');


  useEffect(() => {
    const exchangeCodeForTokens = async () => {
      try {
        const urlParams = new URLSearchParams(window.location.search);

        if (urlParams.has('code')) {
          const code = urlParams.get('code');
          console.log(code); // Remove this log statement before deploying your app to production

          const tokenEndpoint = 'https://ty.auth.ap-southeast-1.amazoncognito.com/oauth2/token';
          const clientId = '21l1hhaf4lo8tskt87bjg8v40o'; // Replace with your actual client ID
          const redirectUri = 'http://localhost:3000';

          const bodyParams = new URLSearchParams();
          bodyParams.append('grant_type', 'authorization_code');
          bodyParams.append('client_id', clientId);
          bodyParams.append('code', code);
          bodyParams.append('redirect_uri', redirectUri);

          const response = await fetch(tokenEndpoint, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: bodyParams.toString(),
          });
          
          const data = await response.json();

          // If the response contains accessToken, idToken, refreshToken, it was successful
          if (data.access_token) {
            const accessToken = data.access_token;
            const idToken = data.id_token;
            const refreshToken = data.refresh_token;

            // Outputs to verify correct functionality, remove logs before deploying
            console.log(data, accessToken, idToken, refreshToken); 
            console.log('Token exchange successful');
          } else {
            // Handle the error situation e.g., display a message to the user
            console.log('Token exchange failed:', data);
          }
        }
      } catch (error) {
        console.error('Error exchanging code for tokens:', error);
      }
    };

    exchangeCodeForTokens();
  }, []);

  const handleSubmit = (event) => {
    event.preventDefault();

    const authenticationData = {
      Username: email,
      Password: password,
    };
    const authenticationDetails = new AuthenticationDetails(authenticationData);
    
    const userData = {
      Username: email,
      Pool: userPool,
    };
    const cognitoUser = new CognitoUser(userData);

    cognitoUser.authenticateUser(authenticationDetails, {
      onSuccess: (session) => {
        console.log('Authentication successful!', session);
        getAWSCredentials(session.getIdToken().getJwtToken());
      },
      onFailure: (err) => {
        alert(err.message || JSON.stringify(err));
      },
      // Add the new callback for new password required scenario.
      newPasswordRequired: () => {
        // This user needs to set a new password, can be handled accordingly
        console.log('New password required for the user.');
        // Redirect user to set new password or handle it in a desired way
        
        // Example: Prompt user to enter a new password and then call this method:
        // cognitoUser.completeNewPasswordChallenge(newPassword, requiredAttributes, callbacks);
      }
    });
  };
  
  function getAWSCredentials(token) {
    const logins = {};
    logins[`cognito-idp.ap-southeast-1.amazonaws.com/${poolData.UserPoolId}`] = token;

    AWS.config.region = 'ap-southeast-1'; // Your desired AWS region, e.g. 'ap-southeast-1'

    AWS.config.credentials = new AWS.CognitoIdentityCredentials({
      IdentityPoolId: 'ap-southeast-1:4b14f089-5b51-43dc-ae8e-d4774d9b7259', // Your identity pool id here
      Logins: logins,
    });

    // Refreshes credentials using AWS.CognitoIdentity.getCredentialsForIdentity()
    AWS.config.credentials.refresh((error) => {
      if (error) {
        console.error(error);
      } else {
        // Use the refreshed credentials
        console.log('Successfully logged!');
        // Print the AWS credentials
        console.log('AWS Credentials:', {
          AccessKeyId: AWS.config.credentials.accessKeyId,
          SecretAccessKey: AWS.config.credentials.secretAccessKey,
          SessionToken: AWS.config.credentials.sessionToken,
        });
      }
    });
  }

  return (
    <div className="flex items-center justify-center h-screen bg-gray-100">
      <div className="bg-white p-8 rounded shadow-md w-full max-w-sm">
        <h1 className="text-3xl font-bold text-center mb-6">Login</h1>
        <form onSubmit={handleSubmit}>
          <div className="mb-4">
            <label htmlFor="email" className="block text-gray-700 text-sm font-bold mb-2">
              Email
            </label>
            <input
              type="email"
              id="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              className="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
            />
          </div>

          <div className="mb-6">
            <label htmlFor="password" className="block text-gray-700 text-sm font-bold mb-2">
              Password
            </label>
            <input
              type="password"
              id="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              className="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 mb-3 leading-tight focus:outline-none focus:shadow-outline"
            />
          </div>

          <div className="flex items-center justify-between">
            <button
              type="submit"
              className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline"
            >
              Sign In
            </button>
            {/* Implement Google login functionality */}
            <a href="https://ty.auth.ap-southeast-1.amazoncognito.com/oauth2/authorize?identity_provider=Google&redirect_uri=http://localhost:3000&response_type=code&client_id=21l1hhaf4lo8tskt87bjg8v40o&scope=aws.cognito.signin.user.admin+openid+profile">
                Login with Google
            </a>


            <a
              href="#!"
              className="inline-block align-baseline font-bold text-sm text-blue-500 hover:text-blue-800"
            >
              Forgot Password?
            </a>
          </div>
        </form>
      </div>
    </div>
  );

  function handleGoogleLogin() {
    // Here you should implement the Google login logic
    console.log('Google login not implemented.');
  }
}

export default App;
