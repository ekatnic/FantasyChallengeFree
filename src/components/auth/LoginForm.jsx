import { useState } from "react";
import { Link as RouterLink } from "react-router-dom";
import { useAuth } from "../../contexts/AuthContext";
import {
  Container,
  Paper,
  Typography,
  TextField,
  Button,
  Link,
  Box,
  Alert,
} from "@mui/material";

import CSRFToken from "../../services/csrftoken";

export function LoginForm() {
  const { login, error } = useAuth();
  const [credentials, setCredentials] = useState({
    username: "",
    password: "",
  });

  const handleChange = (e) => {
    setCredentials({ ...credentials, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      await login(credentials);
    } catch (err) {
      console.error("Login failed:", err);
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
        <Paper elevation={3} sx={{ p: 4, width: "100%" }}>
          <Typography component="h1" variant="h5" align="center" gutterBottom>
            Log In
          </Typography>
          {error && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {error}
            </Alert>
          )}
          <Box component="form" onSubmit={handleSubmit} sx={{ mt: 1 }}>
            <CSRFToken />
            <TextField
              margin="normal"
              required
              fullWidth
              name="username"
              label="Username"
              autoComplete="username"
              autoFocus
              value={credentials.username}
              onChange={handleChange}
            />
            <TextField
              margin="normal"
              required
              fullWidth
              name="password"
              label="Password"
              type="password"
              autoComplete="current-password"
              value={credentials.password}
              onChange={handleChange}
            />
            <Button
              type="submit"
              fullWidth
              variant="contained"
              sx={{ mt: 3, mb: 2 }}
            >
              Log In
            </Button>
            <Box sx={{ textAlign: "center" }}>
              <Link
                component={RouterLink}
                to="/forgot-password"
                variant="body2"
              >
                Forgot password?
              </Link>
              <Box sx={{ mt: 1 }}>
                <Link component={RouterLink} to="/signup" variant="body2">
                  Don't have an account? Sign up
                </Link>
              </Box>
            </Box>
          </Box>
        </Paper>
      </Box>
    </Container>
  );
}

// import React, { useState } from "react";
// import { useNavigate, useLocation, Link } from "react-router-dom";
// import {
//   TextField,
//   Button,
//   Box,
//   Typography,
//   Container,
//   Alert,
// } from "@mui/material";
// import { login } from "../../services/auth";
// import { useAuth } from "../../contexts/AuthContext";
// import CSRFToken from "../../services/csrftoken";

// export function LoginForm() {
//   const navigate = useNavigate();
//   const location = useLocation();
//   const { setUser } = useAuth();
//   const [formData, setFormData] = useState({
//     username: "",
//     password: "",
//   });
//   const [error, setError] = useState("");

//   const handleSubmit = async (e) => {
//     e.preventDefault();
//     setError("");

//     try {
//       const response = await login(formData);
//       setUser(response.user);
//       navigate("/create-entry");
//     } catch (err) {
//       setError(err.response?.data?.errors || "Invalid credentials");
//     }
//   };

//   return (
//     <Container component="main" maxWidth="xs">
//       <Box
//         sx={{
//           marginTop: 8,
//           display: "flex",
//           flexDirection: "column",
//           alignItems: "center",
//         }}
//       >
//         <Typography component="h1" variant="h5">
//           Sign In
//         </Typography>
//         {location.state?.message && (
//           <Alert severity="success" sx={{ width: "100%", mt: 2 }}>
//             {location.state.message}
//           </Alert>
//         )}
//         {error && (
//           <Alert severity="error" sx={{ width: "100%", mt: 2 }}>
//             {error}
//           </Alert>
//         )}
//         <Box component="form" onSubmit={handleSubmit} sx={{ mt: 1 }}>
//           <CSRFToken />
//           <TextField
//             margin="normal"
//             required
//             fullWidth
//             label="Email Address"
//             name="username"
//             autoFocus
//             value={formData.username}
//             onChange={(e) =>
//               setFormData({ ...formData, username: e.target.value })
//             }
//           />
//           <TextField
//             margin="normal"
//             required
//             fullWidth
//             label="Password"
//             name="password"
//             type="password"
//             value={formData.password}
//             onChange={(e) =>
//               setFormData({ ...formData, password: e.target.value })
//             }
//           />
//           <Button
//             type="submit"
//             fullWidth
//             variant="contained"
//             sx={{ mt: 3, mb: 2 }}
//           >
//             Sign In
//           </Button>
//           <Box sx={{ mt: 2, textAlign: "center" }}>
//             <Link to="/forgot-password">Forgot password?</Link>
//           </Box>
//         </Box>
//       </Box>
//     </Container>
//   );
// }
