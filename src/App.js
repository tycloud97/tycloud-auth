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

function attributesArrayToObject(attributes) {
  if (!Array.isArray(attributes)) return attributes;
  const obj = {};
  attributes.forEach((attr) => {
    obj[attr.Name] = attr.Value;
  });
  return obj;
}

function App() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [user, setUser] = useState(null);
  const [buckets, setBuckets] = useState([]);
  const [selectedFile, setSelectedFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState("");
  const [uploadSuccess, setUploadSuccess] = useState("");

  // File upload
  const handleFileChange = (e) => {
    setSelectedFile(e.target.files[0]);
    setUploadError("");
    setUploadSuccess("");
  };

  const handleUpload = async (e) => {
    e.preventDefault();
    if (!selectedFile) {
      setUploadError("No file selected.");
      return;
    }
    setUploading(true);
    setUploadError("");
    setUploadSuccess("");
    const s3 = new AWS.S3();
    const params = {
      Bucket: "tycloud",
      Key: selectedFile.name,
      Body: selectedFile,
      ContentType: selectedFile.type,
    };
    s3.upload(params, (err) => {
      setUploading(false);
      if (err) setUploadError("Upload failed: " + err.message);
      else {
        setUploadSuccess("File uploaded successfully!");
        listS3Buckets(); // Refresh the S3 file list after upload
      }
    });
  };

  // List S3 files
  function listS3Buckets() {
    const s3 = new AWS.S3();
    const bucketName = "tycloud";
    const params = { Bucket: bucketName };
    s3.listObjectsV2(params, (err, data) => {
      if (!err && data.Contents)
        setBuckets(data.Contents.map((file) => file.Key));
    });
  }

  // Download file
  const handleDownload = (fileKey) => {
    const s3 = new AWS.S3();
    const params = { Bucket: "tycloud", Key: fileKey };
    s3.getObject(params, (err, data) => {
      if (!err) {
        const url = window.URL.createObjectURL(new Blob([data.Body]));
        const link = document.createElement("a");
        link.href = url;
        link.setAttribute("download", fileKey);
        document.body.appendChild(link);
        link.click();
        link.parentNode.removeChild(link);
        window.URL.revokeObjectURL(url);
      }
    });
  };

  const getUserDetails = async (accessToken) => {
    try {
      const userInfoEndpoint =
        "https://ty.auth.ap-southeast-1.amazoncognito.com/oauth2/userInfo";

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
          // Cache tokens and user info in localStorage
          localStorage.setItem(
            "cognitoSession",
            JSON.stringify({
              access_token: data.access_token,
              id_token: data.id_token,
              refresh_token: data.refresh_token,
              user: await getUserDetails(data.access_token),
            })
          );
          console.log("Token exchange successful");
          getAWSCredentials(data.id_token);
          listS3Buckets();
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
      // If session contains user details and id_token, restore them
      if (session.user && session.id_token) {
        setUser(session.user);
        getAWSCredentials(session.id_token);
        listS3Buckets();
      } else if (Array.isArray(session)) {
        // fallback for old format (attributes array)
        setUser(session);
      }
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
            setUser(attributesArrayToObject(attributes));
            // Store user attributes and tokens in localStorage
            localStorage.setItem(
              "cognitoSession",
              JSON.stringify({
                id_token: session.getIdToken().getJwtToken(),
                access_token: session.getAccessToken().getJwtToken(),
                refresh_token: session.getRefreshToken().getToken(),
                user: attributes,
              })
            );
          }
        });

        getAWSCredentials(session.getIdToken().getJwtToken());
        listS3Buckets();
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
        console.log("Successfully logged!");
      }
    });
  }

  // UI
  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-100 to-purple-200 flex items-center justify-center">
      <div className="bg-white rounded-2xl shadow-2xl p-8 w-full max-w-md">
        {user ? (
          <div>
            <div className="flex flex-col items-center mb-6">
              <div className="w-16 h-16 rounded-full bg-blue-200 flex items-center justify-center text-3xl font-bold text-blue-700 mb-2">
                {user.email
                  ? user.email[0].toUpperCase()
                  : user[2]?.Value?.[0]?.toUpperCase() || "U"}
              </div>
              <h1 className="text-2xl font-bold text-gray-800 mb-1">Welcome</h1>
              <p className="text-gray-500 text-sm mb-2">{user.email}</p>
            </div>

            {/* S3 Files */}
            <div className="mb-6">
              <h2 className="text-lg font-semibold text-gray-700 mb-2 border-b pb-1">
                Your S3 Files
              </h2>
              {buckets.length === 0 ? (
                <div className="text-gray-400 text-sm">No files found.</div>
              ) : (
                <ul className="divide-y divide-gray-100">
                  {buckets.map((bucket) => (
                    <li
                      key={bucket}
                      className="flex items-center justify-between py-2"
                    >
                      <span className="truncate text-gray-700">{bucket}</span>
                      <button
                        onClick={() => handleDownload(bucket)}
                        className="ml-2 bg-blue-500 hover:bg-blue-600 text-white text-xs px-3 py-1 rounded transition"
                      >
                        Download
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            {/* Upload */}
            <form
              onSubmit={handleUpload}
              className="flex flex-col items-center mb-6"
            >
              <label className="w-full flex flex-col items-center px-4 py-3 bg-blue-50 rounded-lg shadow cursor-pointer hover:bg-blue-100 mb-2">
                <span className="text-blue-700 font-semibold text-sm">
                  Select file to upload
                </span>
                <input
                  type="file"
                  onChange={handleFileChange}
                  className="hidden"
                />
              </label>
              <button
                type="submit"
                disabled={uploading}
                className="w-full bg-green-500 hover:bg-green-600 text-white font-bold py-2 px-4 rounded transition"
              >
                {uploading ? "Uploading..." : "Upload to S3"}
              </button>
              {uploadError && (
                <div className="text-red-500 mt-2 text-sm">{uploadError}</div>
              )}
              {uploadSuccess && (
                <div className="text-green-500 mt-2 text-sm">
                  {uploadSuccess}
                </div>
              )}
            </form>

            <button
              onClick={signOut}
              className="w-full bg-red-500 hover:bg-red-600 text-white font-bold py-2 px-4 rounded transition"
            >
              Logout
            </button>
          </div>
        ) : (
          <div>
            <h1 className="text-3xl font-bold text-center mb-6 text-blue-700">
              Sign In
            </h1>
            <form onSubmit={handleSubmit} className="space-y-5">
              <div>
                <label
                  htmlFor="email"
                  className="block text-gray-700 text-sm font-semibold mb-1"
                >
                  Email
                </label>
                <input
                  type="email"
                  id="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full border border-gray-300 rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-200"
                  required
                />
              </div>
              <div>
                <label
                  htmlFor="password"
                  className="block text-gray-700 text-sm font-semibold mb-1"
                >
                  Password
                </label>
                <input
                  type="password"
                  id="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full border border-gray-300 rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-200"
                  required
                />
              </div>
              <button
                type="submit"
                className="w-full bg-blue-500 hover:bg-blue-600 text-white font-bold py-2 px-4 rounded transition"
              >
                Sign In
              </button>
            </form>
            <div className="mt-8">
              <div className="text-center text-gray-500 mb-2 text-sm">
                Or sign in with
              </div>
              <div className="flex flex-col gap-2">
                <a
                  href="https://ty.auth.ap-southeast-1.amazoncognito.com/oauth2/authorize?client_id=21l1hhaf4lo8tskt87bjg8v40o&response_type=code&scope=aws.cognito.signin.user.admin+email+openid+phone+profile&redirect_uri=http%3A%2F%2Flocalhost%3A3000"
                  className="w-full bg-indigo-500 hover:bg-indigo-600 text-white py-2 rounded text-center font-semibold transition"
                >
                  Cognito OAuth
                </a>
                <a
                  href="https://ty.auth.ap-southeast-1.amazoncognito.com/oauth2/authorize?identity_provider=Google&redirect_uri=http://localhost:3000&response_type=code&client_id=21l1hhaf4lo8tskt87bjg8v40o&scope=aws.cognito.signin.user.admin+openid+profile"
                  className="w-full bg-red-500 hover:bg-red-600 text-white py-2 rounded text-center font-semibold transition"
                >
                  Google
                </a>
                <a
                  href="https://ty.auth.ap-southeast-1.amazoncognito.com/oauth2/authorize?identity_provider=Facebook&redirect_uri=http://localhost:3000&response_type=code&client_id=21l1hhaf4lo8tskt87bjg8v40o&scope=aws.cognito.signin.user.admin+email+openid+profile"
                  className="w-full bg-blue-700 hover:bg-blue-800 text-white py-2 rounded text-center font-semibold transition"
                >
                  Facebook
                </a>
                <a
                  href="https://ty.auth.ap-southeast-1.amazoncognito.com/oauth2/authorize?identity_provider=AWS&redirect_uri=http://localhost:3000&response_type=CODE&client_id=21l1hhaf4lo8tskt87bjg8v40o&scope=aws.cognito.signin.user.admin+email+openid+phone+profile"
                  className="w-full bg-yellow-500 hover:bg-yellow-600 text-white py-2 rounded text-center font-semibold transition"
                >
                  AWS
                </a>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;
