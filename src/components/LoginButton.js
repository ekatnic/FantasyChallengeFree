// src/components/LoginButton.js
import React from "react";
import CognitoHelper from "./utils/CognitoHelper";

const LoginButton = () => {
  const handleLoginClick = () => {
    // Redirect the user to Cognito's Hosted UI for authentication
    const loginUrl = CognitoHelper.getLoginUrl();
    window.location.href = loginUrl;
  };

  return <button onClick={handleLoginClick}>Sign In with Cognito</button>;
};

export default LoginButton;
