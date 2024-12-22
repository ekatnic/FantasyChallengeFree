import React, { createContext, useState, useContext, useEffect } from "react";
// import { createContext, useContext, useState, useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import * as authAPI from "../services/auth"; // assuming your provided code is in this file
// import { checkAuthStatus } from "../services/auth";

// Create context
const AuthContext = createContext(null);

// Provider component
export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const navigate = useNavigate();
  const location = useLocation();
  // Check auth status when component mounts
  useEffect(() => {
    checkAuth();
  }, []);

  const checkAuth = async () => {
    try {
      const data = await authAPI.checkAuthStatus();
      setUser(data.user);
      setError(null);
    } catch (err) {
      setUser(null);
      setError("Authentication check failed");
    } finally {
      setLoading(false);
    }
  };

  const login = async (credentials) => {
    try {
      setLoading(true);
      const data = await authAPI.login(credentials);
      setUser(data.user);
      setError(null);
      // Redirect to the originally requested page or dashboard
      const from = location.state?.from?.pathname || "/create-entry";
      navigate(from, { replace: true });
      return data;
    } catch (err) {
      setError(err.response?.data?.message || "Login failed");
      throw err;
    } finally {
      setLoading(false);
    }
  };

  const signup = async (userData) => {
    try {
      setLoading(true);
      const data = await authAPI.signup(userData);
      setUser(data.user);
      setError(null);
      navigate("/dashboard");
      return data;
    } catch (err) {
      setError(err.response?.data?.message || "Signup failed");
      throw err;
    } finally {
      setLoading(false);
    }
  };

  const logout = async () => {
    try {
      setLoading(true);
      await authAPI.logout();
      setUser(null);
      setError(null);
      navigate("/login");
    } catch (err) {
      setError(err.response?.data?.message || "Logout failed");
      throw err;
    } finally {
      setLoading(false);
    }
  };

  const forgotPassword = async (email) => {
    try {
      setLoading(true);
      const data = await authAPI.forgotPassword(email);
      setError(null);
      return data;
    } catch (err) {
      setError(err.response?.data?.message || "Password reset request failed");
      throw err;
    } finally {
      setLoading(false);
    }
  };

  const value = {
    user,
    loading,
    error,
    login,
    signup,
    logout,
    forgotPassword,
    isAuthenticated: !!user,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

// Hook for using auth context
// export const useAuth = () => {
export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}

// import React, { createContext, useState, useContext, useEffect } from "react";
// import { checkAuthStatus } from "../services/auth";

// // Default value for auth cotext
// export const initialValue = {
//   isAuthenticated: false,
//   setIsAuthenticated: () => {},
// }

// // const AuthContext = createContext(null);
// const AuthContext = createContext(initialValue)

// export function AuthProvider({ children }) {
//   const [user, setUser] = useState(null);
//   const [loading, setLoading] = useState(true);

//   useEffect(() => {
//     const checkAuth = async () => {
//       try {
//         const { isAuthenticated, user } = await checkAuthStatus();
//         if (isAuthenticated) {
//           setUser(user);
//         }
//       } catch (error) {
//         console.error("Auth check failed:", error);
//       } finally {
//         setLoading(false);
//       }
//     };
//     checkAuth();
//   }, []);

//   return (
//     <AuthContext.Provider value={{ user, setUser, loading }}>
//       {!loading && children}
//     </AuthContext.Provider>
//   );
// }

// export const useAuth = () => useContext(AuthContext);
