// import React from 'react';
// import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
// import EntryList from "./components/EntryList";
// import CreateEntry from "./components/CreateEntry";

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
import React from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import { CssBaseline, Container } from "@mui/material";
import { AuthProvider } from "./contexts/AuthContext";

import { PrivateRoute } from "./components/PrivateRoute";
import EntryList from "./components/EntryList";
import CreateEntry from "./components/CreateEntry";

import { SignupForm } from "./components/auth/SignupForm";
import { LoginForm } from "./components/auth/LoginForm";
import { ForgotPasswordForm } from "./components/auth/ForgotPasswordForm";
import { ResetPasswordForm } from "./components/auth/ResetPasswordForm";
import HomePage from "./components/HomePage"; // Assuming HomePage is your main app page

const App = () => {
  return (
    <AuthProvider>
      <CssBaseline />
      <Router>
        <Container maxWidth="lg">
          <Routes>
            <Route
              path="/"
              element={
                <PrivateRoute>
                  <HomePage />
                </PrivateRoute>
              }
            />
            <Route path="/signup" element={<SignupForm />} />
            <Route path="/login" element={<LoginForm />} />
            <Route path="/forgot-password" element={<ForgotPasswordForm />} />
            <Route path="/reset-password" element={<ResetPasswordForm />} />
          </Routes>
        </Container>
      </Router>
    </AuthProvider>
  );
};

export default App;
// import React, { useState } from "react";
// import { BrowserRouter as Router, Route, Routes } from "react-router-dom";
// import EntryList from "./components/EntryList";
// import CreateEntry from "./components/CreateEntry";
// import Login from "./components/Login";
// import Signup from "./components/Signup";
// import PasswordReset from "./components/PasswordReset";

// const App = () => {
//   const [accessToken, setAccessToken] = useState(null);

//   return (
//     <div>
//       <h1>User Authentication</h1>
//       {accessToken ? (
//         <>
//           <Router>
//             <Routes>
//               <Route path="/create-entry" element={<CreateEntry />} />
//               <Route path="/view-entry" element={<EntryList />} />
//               <Route path="/password-reset" element={<PasswordReset />} />
//             </Routes>
//           </Router>
//         </>
//       ) : (
//         <>
//           <Login setAccessToken={setAccessToken} />
//           <Signup />
//         </>
//       )}
//     </div>
//   );
// };

// export default App;
