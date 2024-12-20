import React from "react";
import { Navigate } from "react-router-dom";

// This component checks if the user is authenticated, based on the access token
const PrivateRoute = ({ element, ...rest }) => {
  const accessToken = localStorage.getItem("access_token");

  // If no access token is found, redirect to the login page
  if (!accessToken) {
    return <Navigate to="/" replace />;
  }

  // If access token exists, render the protected component
  return element;
};

export default PrivateRoute;
