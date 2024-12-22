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

// import CSRFToken from "../../services/csrftoken";

export function SignupForm() {
  const { signup, error } = useAuth();
  const [formData, setFormData] = useState({
    username: "",
    email: "",
    password: "",
    password2: "",
  });

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (formData.password !== formData.password2) {
      alert("Passwords don't match!");
      return;
    }
    try {
      await signup(formData);
    } catch (err) {
      console.error("Signup failed:", err);
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
            Sign Up
          </Typography>
          {error && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {error}
            </Alert>
          )}
          <Box component="form" onSubmit={handleSubmit} sx={{ mt: 1 }}>
            <TextField
              margin="normal"
              required
              fullWidth
              name="username"
              label="Username"
              autoComplete="username"
              autoFocus
              value={formData.username}
              onChange={handleChange}
            />
            <TextField
              margin="normal"
              required
              fullWidth
              name="email"
              label="Email Address"
              type="email"
              autoComplete="email"
              value={formData.email}
              onChange={handleChange}
            />
            <TextField
              margin="normal"
              required
              fullWidth
              name="password"
              label="Password"
              type="password"
              autoComplete="new-password"
              value={formData.password}
              onChange={handleChange}
            />
            <TextField
              margin="normal"
              required
              fullWidth
              name="password2"
              label="Confirm Password"
              type="password"
              value={formData.password2}
              onChange={handleChange}
            />
            <Button
              type="submit"
              fullWidth
              variant="contained"
              sx={{ mt: 3, mb: 2 }}
            >
              Sign Up
            </Button>
            <Box sx={{ textAlign: "center" }}>
              <Link component={RouterLink} to="/login" variant="body2">
                Already have an account? Log in
              </Link>
            </Box>
          </Box>
        </Paper>
      </Box>
    </Container>
  );
}
// import CSRFToken from "../../services/csrftoken";
// import React, { useState } from "react";
// import { useNavigate } from "react-router-dom";
// import {
//   TextField,
//   Button,
//   Box,
//   Typography,
//   Container,
//   Alert,
// } from "@mui/material";
// import { signup } from "../../services/auth";

// export function SignupForm() {
//   const navigate = useNavigate();
//   const [formData, setFormData] = useState({
//     email: "",
//     password1: "",
//     password2: "",
//     first_name: "",
//     last_name: "",
//   });
//   const [error, setError] = useState("");

//   const handleSubmit = async (e) => {
//     e.preventDefault();
//     setError("");

//     try {
//       await signup(formData);
//       navigate("/login", {
//         state: { message: "Account created successfully! Please log in." },
//       });
//     } catch (err) {
//       setError(err.response?.data?.errors || "An error occurred during signup");
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
//           Sign Up
//         </Typography>
//         {error && (
//           <Alert severity="error" sx={{ width: "100%", mt: 2 }}>
//             {error}
//           </Alert>
//         )}
//         <Box component="form" onSubmit={handleSubmit} sx={{ mt: 1 }}>
//           <TextField
//             margin="normal"
//             required
//             fullWidth
//             label="First Name"
//             name="first_name"
//             autoFocus
//             value={formData.first_name}
//             onChange={(e) =>
//               setFormData({ ...formData, first_name: e.target.value })
//             }
//           />
//           <TextField
//             margin="normal"
//             required
//             fullWidth
//             label="Last Name"
//             name="last_name"
//             value={formData.last_name}
//             onChange={(e) =>
//               setFormData({ ...formData, last_name: e.target.value })
//             }
//           />
//           <TextField
//             margin="normal"
//             required
//             fullWidth
//             label="Email Address"
//             name="email"
//             type="email"
//             value={formData.email}
//             onChange={(e) =>
//               setFormData({ ...formData, email: e.target.value })
//             }
//           />
//           <TextField
//             margin="normal"
//             required
//             fullWidth
//             label="Password"
//             name="password1"
//             type="password"
//             value={formData.password1}
//             onChange={(e) =>
//               setFormData({ ...formData, password1: e.target.value })
//             }
//           />
//           <TextField
//             margin="normal"
//             required
//             fullWidth
//             label="Confirm Password"
//             name="password2"
//             type="password"
//             value={formData.password2}
//             onChange={(e) =>
//               setFormData({ ...formData, password2: e.target.value })
//             }
//           />
//           <Button
//             type="submit"
//             fullWidth
//             variant="contained"
//             sx={{ mt: 3, mb: 2 }}
//           >
//             Sign Up
//           </Button>
//         </Box>
//       </Box>
//     </Container>
//   );
// }
