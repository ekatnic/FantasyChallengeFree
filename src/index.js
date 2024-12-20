import React from "react";
import ReactDOM from "react-dom/client";
import "./index.css";
import App from "./App";
import reportWebVitals from "./reportWebVitals";
import { Amplify } from "aws-amplify";

const root = ReactDOM.createRoot(document.getElementById("root"));

const awsconfig = {
  Auth: {
    Cognito: {
      region: process.env.REACT_APP_COGNITO_REGION, // The AWS region where your Cognito user pool is
      userPoolId: process.env.REACT_APP_COGNITO_USER_POOL_ID, // Your existing Cognito User Pool ID
      userPoolWebClientId: process.env.REACT_APP_COGNITO_CLIENT_ID, // Your existing Cognito App Client ID
      loginWith: {
        email: true,
      },
      signUpVerificationMethod: "code",
      userAttributes: {
        email: {
          required: true,
        },
      },
      allowGuestAccess: true,
      passwordFormat: {
        minLength: 8,
        requireLowercase: true,
        requireUppercase: true,
        requireNumbers: true,
        requireSpecialCharacters: true,
      },
    },
  },
};

Amplify.configure(awsconfig);

root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);

// // If you want to start measuring performance in your app, pass a function
// // to log results (for example: reportWebVitals(console.log))
// // or send to an analytics endpoint. Learn more: https://bit.ly/CRA-vitals
reportWebVitals();

// // index.js
// import React from "react";
// import ReactDOM from "react-dom/client";
// import { AuthProvider } from "react-oidc-context";
// import App from "./App";
// import "./index.css";
// import reportWebVitals from "./reportWebVitals";

// const cognitoAuthConfig = {
//   authority: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_INESI256k",
//   client_id: "6me1ss5grcq9f1nta9lvjb5ijn",
//   redirect_uri: "http://localhost:3000/callback/",
//   response_type: "code",
//   scope: "aws.cognito.signin.user.admin email openid profile",
//   // Add these for debugging
//   loadUserInfo: true,
//   onSigninCallback: () => {
//     console.log("Callback received");
//   },
//   onSigninError: (error) => {
//     console.error("Signin error:", error);
//   },
// };

// // Log the config for debugging
// console.log("Auth config:", cognitoAuthConfig);

// const root = ReactDOM.createRoot(document.getElementById("root"));

// root.render(
//   <React.StrictMode>
//     <AuthProvider {...cognitoAuthConfig}>
//       <App />
//     </AuthProvider>
//   </React.StrictMode>
// );

// // If you want to start measuring performance in your app, pass a function
// // to log results (for example: reportWebVitals(console.log))
// // or send to an analytics endpoint. Learn more: https://bit.ly/CRA-vitals
// reportWebVitals();
