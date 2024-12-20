// src/utils/CognitoHelper.js
class CognitoHelper {
  static getLoginUrl() {
    const clientId = process.env.REACT_APP_COGNITO_CLIENT_ID;
    const redirectUri = process.env.REACT_APP_COGNITO_REDIRECT_URI;
    const domain = process.env.REACT_APP_COGNITO_DOMAIN;
    const responseType = "token"; // Use 'token' for Implicit flow
    const scope = "openid profile email"; // Adjust as needed

    return `${domain}/login?client_id=${clientId}&response_type=${responseType}&scope=${scope}&redirect_uri=${redirectUri}`;
  }

  static parseTokenFromUrl() {
    const hash = window.location.hash;
    const params = new URLSearchParams(hash.substring(1));
    const accessToken = params.get("access_token");
    const idToken = params.get("id_token");
    const error = params.get("error");

    if (error) {
      throw new Error(`Cognito Auth Error: ${error}`);
    }

    return { accessToken, idToken };
  }
}

export default CognitoHelper;
