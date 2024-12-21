import React, { useState } from "react";
import { useNavigate, useLocation, Link } from "react-router-dom";
import {
  TextField,
  Button,
  Box,
  Typography,
  Container,
  Alert,
} from "@mui/material";
import { login } from "../../services/auth";
import { useAuth } from "../../contexts/AuthContext";

export function LoginForm() {
  const navigate = useNavigate();
  const location = useLocation();
  const { setUser } = useAuth();
  const [formData, setFormData] = useState({
    username: "",
    password: "",
  });
  const [error, setError] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");

    try {
      const response = await login(formData);
      setUser(response.user);
      navigate("/dashboard");
    } catch (err) {
      setError(err.response?.data?.errors || "Invalid credentials");
    }
  };

  return (
    <Container component="main" maxWidth="xs">
      <Box
        sx={{
          marginTop: 8,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
        }}
      >
        <Typography component="h1" variant="h5">
          Sign In
        </Typography>
        {location.state?.message && (
          <Alert severity="success" sx={{ width: "100%", mt: 2 }}>
            {location.state.message}
          </Alert>
        )}
        {error && (
          <Alert severity="error" sx={{ width: "100%", mt: 2 }}>
            {error}
          </Alert>
        )}
        <Box component="form" onSubmit={handleSubmit} sx={{ mt: 1 }}>
          <TextField
            margin="normal"
            required
            fullWidth
            label="Email Address"
            name="username"
            autoFocus
            value={formData.username}
            onChange={(e) =>
              setFormData({ ...formData, username: e.target.value })
            }
          />
          <TextField
            margin="normal"
            required
            fullWidth
            label="Password"
            name="password"
            type="password"
            value={formData.password}
            onChange={(e) =>
              setFormData({ ...formData, password: e.target.value })
            }
          />
          <Button
            type="submit"
            fullWidth
            variant="contained"
            sx={{ mt: 3, mb: 2 }}
          >
            Sign In
          </Button>
          <Box sx={{ mt: 2, textAlign: "center" }}>
            <Link to="/forgot-password">Forgot password?</Link>
          </Box>
        </Box>
      </Box>
    </Container>
  );
}
