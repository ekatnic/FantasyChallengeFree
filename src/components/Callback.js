import React, { useEffect } from "react";

const Callback = ({ setAccessToken }) => {
  useEffect(() => {
    const fragment = window.location.hash.substring(1);
    const params = new URLSearchParams(fragment);

    const accessToken = params.get("access_token");
    if (accessToken) {
      // Save the access token in localStorage and set state
      localStorage.setItem("access_token", accessToken);
      setAccessToken(accessToken);
      // Redirect to home page after storing the token
      window.location.href = "/";
    } else {
      console.error("Access token not found.");
    }
  }, [setAccessToken]);

  return <div>Processing login...</div>;
};

export default Callback;

// // src/components/Callback.js
// import React, { useEffect } from "react";
// import { useHistory } from "react-router-dom";
// import CognitoHelper from "../utils/CognitoHelper";

// const Callback = () => {
//   const history = useHistory();

//   useEffect(() => {
//     try {
//       // Parse the access token from the URL hash
//       const { accessToken, idToken } = CognitoHelper.parseTokenFromUrl();

//       if (accessToken) {
//         // Store the access token and ID token in localStorage or state
//         localStorage.setItem("accessToken", accessToken);
//         localStorage.setItem("idToken", idToken);

//         // Redirect to home or another page
//         history.push("/");
//       }
//     } catch (error) {
//       console.error("Authentication Error:", error.message);
//       // Handle error appropriately
//     }
//   }, [history]);

//   return <div>Loading...</div>;
// };

// export default Callback;
