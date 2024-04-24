import React, { useState } from "react";
import AWS from "aws-sdk";
import { useEffect } from "react";

import {
  AuthenticationDetails,
  CognitoUserPool,
  CognitoUser,
} from "amazon-cognito-identity-js";

const poolData = {
  UserPoolId: "ap-southeast-1_F4feest0w", // Your user pool id here
  ClientId: "21l1hhaf4lo8tskt87bjg8v40o", // Your client id here
};

const userPool = new CognitoUserPool(poolData);

function jwtDecode(token) {
  const [headerEncoded, payloadEncoded] = token.split(".");

  const base64UrlDecode = (encodedString) => {
    const base64 = encodedString.replace(/-/g, "+").replace(/_/g, "/");
    const padLength = (4 - (base64.length % 4)) % 4;
    const paddedBase64 = base64.padEnd(base64.length + padLength, "=");
    const decodedBytes = atob(paddedBase64);

    return decodeURIComponent(
      Array.from(decodedBytes)
        .map((byte) => `%${("00" + byte.charCodeAt(0).toString(16)).slice(-2)}`)
        .join("")
    );
  };

  try {
    const payloadJson = base64UrlDecode(payloadEncoded);
    return JSON.parse(payloadJson);
  } catch (e) {
    console.error("Invalid token: Cannot decode payload.");
    return undefined;
  }
}

function App() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [user, setUser] = useState(null); // State for user info

  useEffect(() => {
    const handleAuthResponse = () => {
      const currentUrl = new URL(window.location.href);
      const idToken = currentUrl.hash
        .split("&")
        .find((param) => param.startsWith("#id_token"))
        ?.split("=")[1];

      if (idToken) {
        const userDetails = jwtDecode(idToken);
        setUser(userDetails);
        console.log("User details:", userDetails);
      }
    };

    handleAuthResponse();

    // Check for a stored user session on load
    const storedSession = localStorage.getItem("cognitoSession");
    if (storedSession) {
      const session = JSON.parse(storedSession);
      setUser(session);
    }
  }, []);

  const getUserDetails = async (accessToken) => {
    try {
      const userInfoEndpoint = "https://ty.auth.ap-southeast-1.amazoncognito.com/oauth2/userInfo";
  
      const response = await fetch(userInfoEndpoint, {
        method: "GET",
        headers: { Authorization: `Bearer ${accessToken}` },
      });
  
      const userDetails = await response.json();
  
      if (!response.ok) {
        console.error("Failed to retrieve user details:", userDetails);
        return null; // Return null or a clear indication that the retrieval failed.
      }
  
      console.log("User details retrieved successfully:", userDetails);
      return userDetails; // Assuming you want the function to return userDetails
    } catch (error) {
      console.error("Error fetching user details:", error);
      return null; // Consider returning null or an error object.
    }
  };

  useEffect(() => {
    async function exchangeCodeForTokens() {
      const urlParams = new URLSearchParams(window.location.search);
      const code = urlParams.get("code");
      if (!code) return;

      try {
        const tokenEndpoint =
          "https://ty.auth.ap-southeast-1.amazoncognito.com/oauth2/token";
        const redirectUri = "http://localhost:3000";

        const bodyParams = new URLSearchParams({
          grant_type: "authorization_code",
          client_id: poolData.ClientId,
          code,
          redirect_uri: redirectUri,
        });

        const response = await fetch(tokenEndpoint, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: bodyParams.toString(),
        });

        const data = await response.json();

        if (response.ok && data.access_token) {
          setUser(await getUserDetails(data.access_token));
          console.log("Token exchange successful");
        } else {
          console.error("Token exchange failed:", data);
        }
      } catch (error) {
        console.error("Error exchanging code for tokens:", error);
      }
    }

    exchangeCodeForTokens();
  }, []);

  useEffect(() => {
    // Check for a stored user session on load
    const storedSession = localStorage.getItem("cognitoSession");
    if (storedSession) {
      const session = JSON.parse(storedSession);
      setUser(session); // Restore the session from localStorage

      // Optionally refresh tokens or validate the session here
    }
  }, []);

  function signOut() {
    // Sign out logic
    if (AWS.config.credentials) {
      AWS.config.credentials.clearCachedId();
    }
    localStorage.removeItem("cognitoSession"); // Clear stored session on logout
    setUser(null);

    // Redirect user to Cognito logout URL
    window.location.assign(
      "https://ty.auth.ap-southeast-1.amazoncognito.com/logout?client_id=21l1hhaf4lo8tskt87bjg8v40o&logout_uri=http%3A%2F%2Flocalhost%3A3000"
    );
  }

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
      onSuccess: async (session) => {
        console.log("Authentication successful!", session);
        cognitoUser.getUserAttributes((err, attributes) => {
          if (err) {
            // Handle error
            console.error(err);
          } else {
            console.log("User attributes:", attributes);
            setUser(attributes);
            localStorage.setItem("cognitoSession", JSON.stringify(attributes));
            // attributes is an array containing user attribute objects
            // For example:
            // [{Name: 'sub', Value: '12345678-90ab-cdef-1234-567890abcdef'}, ...]
          }
        });

        getAWSCredentials(session.getIdToken().getJwtToken());
      },
      onFailure: (err) => {
        alert(err.message || JSON.stringify(err));
      },
      // Add the new callback for new password required scenario.
      newPasswordRequired: () => {
        console.log("New password required for the user.");
      },
    });
  };

  function getAWSCredentials(token) {
    const logins = {};
    logins[`cognito-idp.ap-southeast-1.amazonaws.com/${poolData.UserPoolId}`] =
      token;

    AWS.config.region = "ap-southeast-1"; // Your desired AWS region, e.g. 'ap-southeast-1'

    AWS.config.credentials = new AWS.CognitoIdentityCredentials({
      IdentityPoolId: "ap-southeast-1:4b14f089-5b51-43dc-ae8e-d4774d9b7259", // Your identity pool id here
      Logins: logins,
    });

    // Refreshes credentials using AWS.CognitoIdentity.getCredentialsForIdentity()
    AWS.config.credentials.refresh((error) => {
      if (error) {
        console.error(error);
      } else {
        // Use the refreshed credentials
        console.log("Successfully logged!");
        // Print the AWS credentials
        console.log("AWS Credentials:", {
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
        {user ? (
          <div>
            <h1 className="text-3xl font-bold text-center mb-6">Welcome</h1>
            <p className="mb-4">{JSON.stringify(user, null, 2)}</p>

            {/* Logout button */}
            <button
              onClick={signOut}
              className="w-full bg-red-500 hover:bg-red-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline"
            >
              Logout
            </button>
          </div>
        ) : (
          <>
            <h1 className="text-3xl font-bold text-center mb-6">Login</h1>

            <form onSubmit={handleSubmit}>
              <div className="mb-4">
                <label
                  htmlFor="email"
                  className="block text-gray-700 text-sm font-bold mb-2"
                >
                  Email
                </label>
                <input
                  type="email"
                  id="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
                />
              </div>

              <div className="mb-6">
                <label
                  htmlFor="password"
                  className="block text-gray-700 text-sm font-bold mb-2"
                >
                  Password
                </label>
                <input
                  type="password"
                  id="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
                />
              </div>

              <div className="flex flex-col space-y-4 items-center justify-between">
                <button
                  type="submit"
                  className="w-full bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline"
                >
                  Sign In
                </button>

                {/* Third-party login links */}
                <div className="space-y-2">
                  <a
                    href="https://ty.auth.ap-southeast-1.amazoncognito.com/oauth2/authorize?client_id=21l1hhaf4lo8tskt87bjg8v40o&response_type=code&scope=aws.cognito.signin.user.admin+email+openid+phone+profile&redirect_uri=http%3A%2F%2Flocalhost%3A3000"
                    className="block py-2 text-center text-blue-500 hover:text-blue-800"
                  >
                    Sign In with Cognito OAuth
                  </a>

                  {/* Implement Google login functionality */}
                  <a
                    href="https://ty.auth.ap-southeast-1.amazoncognito.com/oauth2/authorize?identity_provider=Google&redirect_uri=http://localhost:3000&response_type=code&client_id=21l1hhaf4lo8tskt87bjg8v40o&scope=aws.cognito.signin.user.admin+openid+profile"
                    className="block py-2 text-center text-blue-500 hover:text-blue-800"
                  >
                    Login with Google
                  </a>

                  <a
                    href="https://ty.auth.ap-southeast-1.amazoncognito.com/oauth2/authorize?identity_provider=Facebook&redirect_uri=http://localhost:3000&response_type=code&client_id=21l1hhaf4lo8tskt87bjg8v40o&scope=aws.cognito.signin.user.admin+email+openid+profile"
                    className="block py-2 text-center text-blue-500 hover:text-blue-800"
                  >
                    Login with Facebook
                  </a>

                  <a
                    href="https://ty.auth.ap-southeast-1.amazoncognito.com/oauth2/authorize?identity_provider=AWS&redirect_uri=http://localhost:3000&response_type=CODE&client_id=21l1hhaf4lo8tskt87bjg8v40o&scope=aws.cognito.signin.user.admin+email+openid+phone+profile"
                    className="block py-2 text-center text-blue-500 hover:text-blue-800"
                  >
                    Login with AWS
                  </a>
                </div>
              </div>
            </form>
          </>
        )}
      </div>
    </div>
  );
}

export default App;
