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
// import React from "react";
// import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
// import { CssBaseline, Container } from "@mui/material";
// import { AuthProvider } from "./contexts/AuthContext";

// import { PrivateRoute } from "./components/PrivateRoute";
// import { AppHeader } from "./components/AppHeader";
// import EntryList from "./components/EntryList";
// import CreateEntry from "./components/CreateEntry";

// import { SignupForm } from "./components/auth/SignupForm";
// import { LoginForm } from "./components/auth/LoginForm";
// import { ForgotPasswordForm } from "./components/auth/ForgotPasswordForm";
// import { ConfirmForgotPassowrd } from "./components/auth/ConfirmForgotPassowrd";
// import HomePage from "./components/HomePage"; // Assuming HomePage is your main app page

// const App = () => {
//   return (
//     <AuthProvider>
//       <CssBaseline />
//       <Router>
//         <Container maxWidth="lg">
//           <AppHeader />
//           <Routes>
//             <Route
//               path="/"
//               element={
//                 <PrivateRoute>
//                   <HomePage />
//                 </PrivateRoute>
//               }
//             />
//             <Route
//               path="/create-entry"
//               element={
//                 <PrivateRoute>
//                   <CreateEntry />
//                 </PrivateRoute>
//               }
//             />
//             <Route path="/signup" element={<SignupForm />} />
//             <Route path="/login" element={<LoginForm />} />
//             <Route path="/forgot-password" element={<ForgotPasswordForm />} />
//             <Route path="/reset-password" element={<ConfirmForgotPassowrd />} />
//           </Routes>
//         </Container>
//       </Router>
//     </AuthProvider>
//   );
// };

// export default App;

// App.js
import React from "react";
// import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
// import { CssBaseline, Container } from "@mui/material";
// import { AuthProvider } from "./contexts/AuthContext";

// import { PrivateRoute } from "./components/PrivateRoute";
// import { AppHeader } from "./components/AppHeader";
// import EntryList from "./components/EntryList";
// import CreateEntry from "./components/CreateEntry";

// import { SignupForm } from "./components/auth/SignupForm";
// import { LoginForm } from "./components/auth/LoginForm";
// import { ForgotPasswordForm } from "./components/auth/ForgotPasswordForm";
// import { ConfirmForgotPassowrd } from "./components/auth/ConfirmForgotPassowrd";
// import HomePage from "./components/HomePage"; // Assuming HomePage is your main app page

import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { Navbar } from "./components/Navbar";
import { LoginForm } from "./components/auth/LoginForm";
import { SignupForm } from "./components/auth/SignupForm";
import { ForgotPasswordForm } from "./components/auth/ForgotPasswordForm";
import { Dashboard } from "./components/Dashboard";
import { useAuth, AuthProvider } from "./contexts/AuthContext";
// import { AuthProvider } from "./hooks/useAuth";

// Protected Route Component
function ProtectedRoute({ children }) {
  const { isAuthenticated, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        Loading...
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return children;
}

// Public Route Component (redirects to dashboard if already authenticated)
function PublicRoute({ children }) {
  const { isAuthenticated, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        Loading...
      </div>
    );
  }

  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />;
  }

  return children;
}

function AppRoutes() {
  return (
    <>
      <Navbar />
      <Routes>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />

        {/* Public Routes */}
        <Route
          path="/login"
          element={
            <PublicRoute>
              <LoginForm />
            </PublicRoute>
          }
        />
        <Route
          path="/signup"
          element={
            <PublicRoute>
              <SignupForm />
            </PublicRoute>
          }
        />
        <Route
          path="/forgot-password"
          element={
            <PublicRoute>
              <ForgotPasswordForm />
            </PublicRoute>
          }
        />

        {/* Protected Routes */}
        <Route
          path="/dashboard"
          element={
            <ProtectedRoute>
              <Dashboard />
            </ProtectedRoute>
          }
        />

        {/* Catch all route */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </>
  );
}

function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <AppRoutes />
      </AuthProvider>
    </BrowserRouter>
  );
}

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
