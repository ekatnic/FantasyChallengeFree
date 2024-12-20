import React from "react";
import { useEffect } from "react";

const CognitoAuth = ({ accessToken, setAccessToken }) => {
  // Replace with your actual Cognito configuration
  const config = {
    userPoolId: process.env.REACT_APP_COGNITO_USER_POOL_ID,
    clientId: process.env.REACT_APP_COGNITO_CLIENT_ID,
    domain: process.env.REACT_APP_COGNITO_DOMAIN_SHORT,
    redirectUri: process.env.REACT_APP_COGNITO_REDIRECT_URI, // Update with your redirect URI
    scope: "aws.cognito.signin.user.admin email openid profile", // Adjust scopes as needed
  };

  const signInUrl = `https://${
    config.domain
  }/login?response_type=token&client_id=${
    config.clientId
  }&redirect_uri=${encodeURIComponent(
    config.redirectUri
  )}&scope=${encodeURIComponent(config.scope)}`;

  const handleLogin = () => {
    // Redirect to Cognito Hosted UI
    window.location.href = signInUrl;
  };

  const handleLogout = () => {
    // Clear the access token and remove from local storage
    setAccessToken(null);
    localStorage.removeItem("access_token");
    window.location.href = "/";
  };

  return (
    <div>
      <h1>React AWS Cognito Auth</h1>
      {!accessToken ? (
        <button onClick={handleLogin}>Login with Cognito</button>
      ) : (
        <div>
          <h2>Logged In</h2>
          <p>Access Token: {accessToken}</p>
          <button onClick={handleLogout}>Logout</button>
        </div>
      )}
    </div>
  );
};

// export default CognitoAuth;

// import React, { useEffect, useState } from "react";

// const CognitoAuth = () => {
//   const [accessToken, setAccessToken] = useState(null);

//   // Replace these with your actual Cognito configuration
//   const config = {
//     userPoolId: process.env.REACT_APP_COGNITO_USER_POOL_ID,
//     clientId: process.env.REACT_APP_COGNITO_CLIENT_ID,
//     domain: process.env.REACT_APP_COGNITO_DOMAIN_SHORT,
//     redirectUri: process.env.REACT_APP_COGNITO_REDIRECT_URI, // Update with your redirect URI
//     scope: "aws.cognito.signin.user.admin email openid profile", // Adjust scopes as needed
//   };

//   // Construct the Cognito Hosted UI URL
//   const signInUrl = `https://${
//     config.domain
//   }/login?response_type=code&client_id=${config.clientId}&redirect_uri=${
//     config.redirectUri
//   }&scope=${encodeURIComponent(config.scope)}`;

//   // Handle the OAuth callback
//   useEffect(() => {
//     const handleCallback = async () => {
//       const urlParams = new URLSearchParams(window.location.search);
//       const authCode = urlParams.get("code");

//       if (authCode) {
//         try {
//           // Exchange auth code for tokens
//           const tokenResponse = await fetch(
//             `https://${config.domain}/oauth2/token`,
//             {
//               method: "POST",
//               headers: {
//                 "Content-Type": "application/x-www-form-urlencoded",
//               },
//               body: new URLSearchParams({
//                 grant_type: "token",
//                 client_id: config.clientId,
//                 code: authCode,
//                 redirect_uri: config.redirectUri,
//               }),
//             }
//           );

//           const tokens = await tokenResponse.json();
//           setAccessToken(tokens.access_token);

//           // Clear the URL parameters
//           window.history.replaceState(
//             {},
//             document.title,
//             window.location.pathname
//           );
//         } catch (error) {
//           console.error("Error exchanging auth code:", error);
//         }
//       }
//     };

//     handleCallback();
//   }, []);

//   // Example function to make authenticated API calls
//   const makeAuthenticatedRequest = async () => {
//     if (!accessToken) return;

//     try {
//       const response = await fetch("YOUR_BACKEND_API_ENDPOINT", {
//         headers: {
//           Authorization: `Bearer ${accessToken}`,
//         },
//       });
//       const data = await response.json();
//       console.log("API response:", data);
//     } catch (error) {
//       console.error("API request failed:", error);
//     }
//   };

//   return (
//     <div className="p-4">
//       {!accessToken ? (
//         <button
//           onClick={() => (window.location.href = signInUrl)}
//           className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded"
//         >
//           Sign In with Cognito
//         </button>
//       ) : (
//         <div>
//           <p className="mb-4">Successfully authenticated!</p>
//           <button
//             onClick={makeAuthenticatedRequest}
//             className="bg-green-500 hover:bg-green-700 text-white font-bold py-2 px-4 rounded"
//           >
//             Make Authenticated Request
//           </button>
//         </div>
//       )}
//     </div>
//   );
// };

class CognitoAuthManager {
  constructor(AWS_COGNITO, grantType = "authorization_code") {
    const {
      CLIENT_ID,
      CLIENT_SECRET,
      SCOPES,
      REDIRECT_URI,
      COGNITO_USER_POOL_URL,
      STATE,
    } = AWS_COGNITO;
    this.grantType = grantType;
    this.clientId = CLIENT_ID;
    this.clientSecret = CLIENT_SECRET;
    this.scopes = SCOPES;
    this.cognitoUserPoolUrl = COGNITO_USER_POOL_URL;
    this.state = 123;
    this.redirectUri = REDIRECT_URI;
    this.tokenUrl = `${COGNITO_USER_POOL_URL}/oauth2/token`;
    this.userinfoUrl = `${COGNITO_USER_POOL_URL}/oauth2/userInfo`;
  }

  getLoginUrl(state) {
    return (
      `${this.cognitoUserPoolUrl}/login` +
      `?response_type=code` +
      `&client_id=${encodeURIComponent(this.clientId)}` +
      `&redirect_uri=${this.redirectUri}` +
      `&scope=${encodeURIComponent(this.scopes)}` +
      `&state=${encodeURIComponent(this.state)}`
    );
  }

  async exchangeCodeForTokens(code) {
    const body = new URLSearchParams({
      grant_type: this.grantType,
      code: code,
      redirect_uri: this.redirectUri,
      client_id: this.clientId,
      client_secret: this.clientSecret,
    });

    try {
      const response = await fetch(this.tokenUrl, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: body.toString(),
      });

      if (!response.ok) {
        throw new Error(
          `Failed to exchange code for tokens: ${response.statusText}`
        );
      }

      return await response.json();
    } catch (error) {
      console.error("Error exchanging code for tokens:", error.message);
      throw error;
    }
  }

  async getUserInfo(token) {
    try {
      const response = await fetch(this.userinfoUrl, {
        method: "GET",
        headers: { Authorization: `Bearer ${token}` },
      });

      if (!response.ok) {
        throw new Error(`Failed to fetch user info: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error("Error getting user info:", error.message);
      throw error;
    }
  }
}
export default CognitoAuth;
