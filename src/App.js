// import React from "react";
// import { BrowserRouter as Router, Route, Routes } from "react-router-dom";
// import EntryList from "./components/EntryList";
// import CreateEntry from "./components/CreateEntry";
// import CognitoAuth from "./components/CognitoAuth";
// import Callback from "./components/Callback";
// import PrivateRoute from "./components/PrivateRoute"; // Import the PrivateRoute component

// import { useState, useEffect } from "react";

// const App = () => {
//   const [accessToken, setAccessToken] = useState(null);

//   useEffect(() => {
//     // Check if access token is stored in local storage
//     const token = localStorage.getItem("access_token");
//     if (token) {
//       setAccessToken(token);
//     }
//   }, []);

//   return (
//     <Router>
//       <Routes>
//         <Route
//           path="/"
//           element={
//             <CognitoAuth
//               accessToken={accessToken}
//               setAccessToken={setAccessToken}
//             />
//           }
//         />
//         <Route
//           path="/callback"
//           element={<Callback setAccessToken={setAccessToken} />}
//         />
//         {/* Protected route */}
//         <Route
//           path="/protected"
//           element={
//             <PrivateRoute
//               element={<h2>Protected Content</h2>} // Replace with your protected component
//             />
//           }
//         />
//       </Routes>
//     </Router>
//   );
// };

// export default App;
// function App() {
//   return (
//     <Router>
//       <Routes>
//         <Route path="/" element={<CognitoAuth />} />
//         <Route path="/create-entry" element={<CreateEntry />} />
//         <Route path="/view-entry" element={<EntryList />} />
//       </Routes>
//     </Router>
//   );
// }

// export default App;

import React from "react";
import { BrowserRouter as Router, Route, Routes } from "react-router-dom";
import EntryList from "./components/EntryList";
import CreateEntry from "./components/CreateEntry";
import { withAuthenticator } from "@aws-amplify/ui-react";
// import Auth from "@aws-amplify/auth";
function App() {
  return (
    <div>
      <h1>Welcome to my app</h1>
    </div>
  );
}

export default withAuthenticator(App);

// function App() {
//   return (
//     <Router>
//       <Routes>
//         <Route path="/create-entry" element={<CreateEntry />} />
//         <Route path="/view-entry" element={<EntryList />} />
//       </Routes>
//     </Router>
//   );
// }

// export default App;

// import React from "react";
// import { BrowserRouter as Router, Route, Routes } from "react-router-dom";
// import EntryList from "./components/EntryList";
// import CreateEntry from "./components/CreateEntry";
// import useAuth from "./hooks/useAuth";
// import { useState, useEffect, useMemo } from "react";
// import Auth from "@aws-amplify/auth";

// const App = () => {
//   const { signIn, signOut, user, isSignedIn } = useAuth({
//     provider: "Cognito",
//     options: {
//       userPoolId: process.env.REACT_APP_COGNITO_USER_POOL_ID,
//       userPoolWebClientId: process.env.REACT_APP_COGNITO_CLIENT_ID,
//       oauth: {
//         domain: "playoff-showdown.auth.us-east-1.amazoncognito.com",
//         scope: ["email", "aws.cognito.signin.user.admin", "openid"],
//         redirectSignIn: "http://localhost:3000/callback/",
//         redirectSignOut: "http://localhost:3000/login/",
//         region: process.env.REACT_APP_COGNITO_REGION,
//         responseType: "code",
//       },
//     },
//   });

//   return (
//     <>
//       {isSignedIn ? (
//         <div style={{ whiteSpace: "pre" }}>
//           <button onClick={() => signOut()}>Logout</button>
//           <h1>Hi {user.username}</h1>
//           <code>{JSON.stringify(user, null, 2)}</code>
//         </div>
//       ) : (
//         <button onClick={() => signIn()}>Login</button>
//       )}
//     </>
//   );
// };

// export default App;

// App.js

// import { useAuth } from "react-oidc-context";

// function App() {
//   const auth = useAuth();

//   const signOutRedirect = () => {
//     const clientId = "6me1ss5grcq9f1nta9lvjb5ijn";
//     const logoutUri = "https://localhost:3000/login/";
//     const cognitoDomain =
//       "https://playoff-showdown.auth.us-east-1.amazoncognito.com";
//     window.location.href = `${cognitoDomain}/logout?client_id=${clientId}&logout_uri=${encodeURIComponent(
//       logoutUri
//     )}`;
//   };
//   console.log("auth", auth);
//   if (auth.isLoading) {
//     return <div>Loading...</div>;
//   }

//   if (auth.error) {
//     return <div>Encountering error... {auth.error.message}</div>;
//   }

//   if (auth.isAuthenticated) {
//     return (
//       <div>
//         <pre> Hello: {auth.user?.profile.email} </pre>
//         <pre> ID Token: {auth.user?.id_token} </pre>
//         <pre> Access Token: {auth.user?.access_token} </pre>
//         <pre> Refresh Token: {auth.user?.refresh_token} </pre>

//         <button onClick={() => auth.removeUser()}>Sign out</button>
//       </div>
//     );
//   }

//   return (
//     <div>
//       <button onClick={() => auth.signinRedirect()}>Sign in</button>
//       <button onClick={() => signOutRedirect()}>Sign out</button>
//     </div>
//   );
// }

// export default App;
// // App.js
// import React from "react";
// import {
//   BrowserRouter as Router,
//   Route,
//   Routes,
//   Navigate,
// } from "react-router-dom";
// import { useAuth } from "react-oidc-context";
// import EntryList from "./components/EntryList";
// import CreateEntry from "./components/CreateEntry";

// // Protected Route Component
// const ProtectedRoute = ({ children }) => {
//   const auth = useAuth();

//   if (auth.isLoading) {
//     return <div>Loading...</div>;
//   }

//   if (auth.error) {
//     return <div>Error: {auth.error.message}</div>;
//   }

//   if (!auth.isAuthenticated) {
//     return <Navigate to="/login" />;
//   }

//   return children;
// };

// // Login Component
// const Login = () => {
//   const auth = useAuth();

//   const signOutRedirect = () => {
//     const clientId = "6me1ss5grcq9f1nta9lvjb5ijn";
//     const logoutUri = "http://localhost:3000/login/";
//     const cognitoDomain =
//       "https://playoff-showdown.auth.us-east-1.amazoncognito.com";
//     window.location.href = `${cognitoDomain}/logout?client_id=${clientId}&logout_uri=${encodeURIComponent(
//       logoutUri
//     )}`;
//   };

//   if (auth.isAuthenticated) {
//     return <Navigate to="/view-entry" />;
//   }

//   return (
//     <div>
//       <h1>Welcome</h1>
//       <button onClick={() => auth.signinRedirect()}>Sign in</button>
//       <button onClick={signOutRedirect}>Sign out</button>
//     </div>
//   );
// };

// // Callback Component
// const CognitoCallback = () => {
//   const auth = useAuth();

//   if (auth.isLoading) {
//     return <div>Loading...</div>;
//   }

//   if (auth.error) {
//     return <div>Error: {auth.error.message}</div>;
//   }

//   if (auth.isAuthenticated) {
//     return <Navigate to="/view-entry" />;
//   }

//   return null;
// };

// // Main App Component
// function App() {
//   const auth = useAuth();
//   console.log("auth", auth);
//   console.log("auth.isAuthenticated", auth.isAuthenticated);
//   return (
//     <Router>
//       {auth.isAuthenticated && (
//         <div>
//           <button onClick={() => auth.removeUser()}>Sign out</button>
//           <div>Logged in as: {auth.user?.profile.email}</div>
//         </div>
//       )}
//       <Routes>
//         <Route path="/login" element={<Login />} />
//         <Route path="/callback" element={<CognitoCallback />} />
//         <Route
//           path="/create-entry"
//           element={
//             <ProtectedRoute>
//               <CreateEntry />
//             </ProtectedRoute>
//           }
//         />
//         <Route
//           path="/view-entry"
//           element={
//             <ProtectedRoute>
//               <EntryList />
//             </ProtectedRoute>
//           }
//         />
//         <Route path="/" element={<Navigate to="/login" />} />
//       </Routes>
//     </Router>
//   );
// }

// export default App;

// import React, { useEffect } from "react";
// import {
//   BrowserRouter as Router,
//   Route,
//   Routes,
//   Navigate,
// } from "react-router-dom";
// import axios from "axios";

// const COGNITO_DOMAIN =
//   "https://playoff-showdown.auth.us-east-1.amazoncognito.com";
// const CLIENT_ID = "6me1ss5grcq9f1nta9lvjb5ijn";
// const REDIRECT_URI = "http://localhost:3000/callback/";
// const LOGOUT_URI = "http://localhost:3000/login/";
// const RESPONSE_TYPE = "code";
// const SCOPE = "aws.cognito.signin.user.admin email openid profile";

// // Utility function to construct the Cognito Hosted UI login URL
// const getLoginUrl = () => {
//   return `${COGNITO_DOMAIN}/oauth2/authorize?client_id=${CLIENT_ID}&response_type=${RESPONSE_TYPE}&scope=${encodeURIComponent(
//     SCOPE
//   )}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}`;
// };

// // Login Component
// const Login = () => {
//   const handleLogin = () => {
//     window.location.href = getLoginUrl();
//   };

//   return (
//     <div>
//       <h1>Welcome</h1>
//       <button onClick={handleLogin}>Sign in with Cognito</button>
//     </div>
//   );
// };

// // Callback Component
// const Callback = () => {
//   useEffect(() => {
//     const authCode = new URLSearchParams(window.location.search).get("code");
//     if (authCode) {
//       axios
//         .post("http://localhost:8000/api/cognito/authenticate/", {
//           code: authCode,
//         })
//         .then((response) => {
//           const tokens = response.data.tokens;
//           localStorage.setItem("access_token", tokens.access_token);
//           localStorage.setItem("id_token", tokens.id_token);
//           localStorage.setItem("refresh_token", tokens.refresh_token);
//           window.location.href = "/protected/";
//         })
//         .catch((error) => {
//           console.error("Error during token exchange:", error);
//         });
//     }
//   }, []);

//   return <div>Loading...</div>;
// };

// // Protected Route Component
// const ProtectedRoute = ({ children }) => {
//   const token = localStorage.getItem("access_token");
//   if (!token) {
//     return <Navigate to="/login" />;
//   }
//   return children;
// };

// // Protected Content Component
// const ProtectedContent = () => {
//   const handleLogout = () => {
//     localStorage.clear();
//     window.location.href = `${COGNITO_DOMAIN}/logout?client_id=${CLIENT_ID}&logout_uri=${encodeURIComponent(
//       LOGOUT_URI
//     )}`;
//   };

//   return (
//     <div>
//       <h1>Protected Content</h1>
//       <button onClick={handleLogout}>Sign Out</button>
//     </div>
//   );
// };

// // Main App Component
// const App = () => {
//   return (
//     <Router>
//       <Routes>
//         <Route path="/login" element={<Login />} />
//         <Route path="/callback" element={<Callback />} />
//         <Route
//           path="/protected"
//           element={
//             <ProtectedRoute>
//               <ProtectedContent />
//             </ProtectedRoute>
//           }
//         />
//         <Route path="/" element={<Navigate to="/login" />} />
//       </Routes>
//     </Router>
//   );
// };

// export default App;
