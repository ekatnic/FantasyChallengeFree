// src/api/auth.js
import axios from "axios";

axios.defaults.withCredentials = true;

export const signup = async (userData) => {
  const response = await axios.post(
    `${process.env.REACT_APP_API_BASE_URL}/api/signup/`,
    userData
  );
  //   const response = await axios.post("/api/signup/", userData);
  return response.data;
};

export const login = async (credentials) => {
  const response = await axios.post(
    `${process.env.REACT_APP_API_BASE_URL}/api/login/`,
    userData
  );
  //   const response = await axios.post("/api/login/", credentials);
  return response.data;
};

export const logout = async () => {
  const response = await axios.post(
    `${process.env.REACT_APP_API_BASE_URL}/api/logout/`
  );
  //   const response = await axios.post("/api/logout/");
  return response.data;
};

export const forgotPassword = async (email) => {
  const response = await axios.post(
    `${process.env.REACT_APP_API_BASE_URL}/api/forgot-password/`,
    { email }
  );
  //   const response = await axios.post("/api/forgot-password/", { email });
  return response.data;
};

export const confirmForgotPassword = async (data) => {
  const response = await axios.post(
    `${process.env.REACT_APP_API_BASE_URL}/api/confirm-forgot-password/`,
    data
  );
  //   const response = await axios.post("/api/confirm-forgot-password/", data);
  return response.data;
};

export const changePassword = async (passwords) => {
  const response = await axios.post(
    `${process.env.REACT_APP_API_BASE_URL}/api/change-password/`,
    passwords
  );
  //   const response = await axios.post("/api/change-password/", passwords);
  return response.data;
};

export const checkAuthStatus = async () => {
  const response = await axios.get(
    `${process.env.REACT_APP_API_BASE_URL}/api/auth-status/`
  );
  //   const response = await axios.get("/api/auth-status/");
  return response.data;
};
