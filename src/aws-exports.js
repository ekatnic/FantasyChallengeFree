const awsconfig = {
  Auth: {
    region: process.env.REACT_APP_COGNITO_REGION, // The AWS region where your Cognito user pool is
    userPoolId: process.env.REACT_APP_COGNITO_USER_POOL_ID, // Your existing Cognito User Pool ID
    userPoolWebClientId: process.env.REACT_APP_COGNITO_CLIENT_ID, // Your existing Cognito App Client ID
  },
};

export default awsconfig;
