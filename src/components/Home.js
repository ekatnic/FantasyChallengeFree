// src/components/Home.js
import React from "react";
import { useNavigate } from "react-router-dom"; // to navigate to other pages

const Home = () => {
  const navigate = useNavigate();

  function getLoginUrl() {
    return (
      // &scope=aws.cognito.signin.user.admin+email+openid+profile&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback%2F
      // https://playoff-showdown.auth.us-east-1.amazoncognito.com/login?client_id=6me1ss5grcq9f1nta9lvjb5ijn&response_type=token&scope=aws.cognito.signin.user.admin+email+openid+profile&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback%2F
      // `https://playoff-showdown.auth.us-east-1.amazoncognito.com/login?client_id=6me1ss5grcq9f1nta9lvjb5ijn&response_type=token&scope=aws.cognito.signin.user.admin+email+openid+profile`
      `${process.env.REACT_APP_COGNITO_DOMAIN}/login` +
      `?response_type=code` +
      `&client_id=${encodeURIComponent(
        process.env.REACT_APP_COGNITO_CLIENT_ID
      )}` +
      `&redirect_uri=${process.env.REACT_APP_COGNITO_REDIRECT_URI}` +
      "&scope=aws.cognito.signin.user.admin+email+openid+profile"
      //  `&scope=${encodeURIComponent(this.scopes)}` +
      //   `&state=${encodeURIComponent(this.state)}`
    );
  }

  const handleSignIn = () => {
    // Redirect user to Cognito Hosted UI
    // window.location.href = "https://<your_cognito_domain>/login"; // Replace with your Cognito hosted UI URL
    window.location.href = getLoginUrl();
  };

  return (
    <div>
      <h1>Welcome to the App!</h1>
      <button onClick={handleSignIn}>Sign In with Cognito</button>
    </div>
  );
};

export default Home;
