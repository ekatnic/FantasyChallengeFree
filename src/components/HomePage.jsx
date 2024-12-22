import { Box, Typography, Button, Container } from "@mui/material";
import { Link } from "react-router-dom";

const HomePage = () => {
  return (
    <Container component="main" maxWidth="md">
      <Box
        sx={{
          mt: 8,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          textAlign: "center",
        }}
      >
        <Typography component="h1" variant="h3" gutterBottom>
          FANTASY SHOWDOWN
        </Typography>
        <Typography variant="h6" color="textSecondary" sx={{ mb: 4 }}>
          Login, Signup, Reset those passwords, forget your password, wahtever
          you want
        </Typography>
        <Box sx={{ display: "flex", gap: 2 }}>
          <Button
            component={Link}
            to="/signup"
            variant="contained"
            color="primary"
          >
            Sign Up
          </Button>
          <Button
            component={Link}
            to="/login"
            variant="outlined"
            color="primary"
          >
            Log In
          </Button>
        </Box>
      </Box>
    </Container>
  );
};

export default HomePage;
