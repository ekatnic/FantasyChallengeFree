import { useAuth } from "../contexts/AuthContext";
import { Container, Typography, Paper, Box } from "@mui/material";

export function Dashboard() {
  const { user } = useAuth();

  return (
    <Container maxWidth="lg">
      <Box sx={{ mt: 4 }}>
        <Paper elevation={3} sx={{ p: 3 }}>
          <Typography variant="h4" gutterBottom>
            Dashboard
          </Typography>
          <Typography variant="body1">
            Welcome to your dashboard, {user.username}!
          </Typography>
        </Paper>
      </Box>
    </Container>
  );
}
