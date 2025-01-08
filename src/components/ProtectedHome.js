import React from "react";
import { Typography, Paper, Box, Button } from "@mui/material";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";

export default function ProtectedHome() {
  const { user } = useAuth();
  const navigate = useNavigate();

  return (
    <Paper sx={{ p: 4, mt: 4 }}>
      <Typography variant="h4" component="h1" gutterBottom>
        Welcome to the Playoff Challenge
      </Typography>
      <Box sx={{ mt: 3, mb: 3 }}>
        <Typography variant="body1" gutterBottom>
          Create a lineup of 12 players. Once the playoffs start you will not be able to change your lineup. The catch is that you can only select <strong>ONE PLAYER PER TEAM</strong>. 
        </Typography>
        <Typography variant="body1" gutterBottom>
          <br/>
          This is the free version of our competition. If you want to compete for the cash price, head over to <a href="https://playoff-showdown.com">playoff-showdown.com</a>
        </Typography>
        <Typography variant="body2" color="text.secondary" gutterBottom>
          Website developed by Ethan Katnic, Spenser Wyatt, and Angus Watters.
        </Typography>
      </Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", mt: 3 }}>
        <Button variant="contained" color="primary" onClick={() => navigate("/rules")}>
          Rules
        </Button>
        <Button variant="contained" color="primary" onClick={() => navigate("/my-entries")}>
          My Entries
        </Button>
        <Button variant="contained" color="primary" onClick={() => navigate("/create-entry")}>
          Create Entry
        </Button>
      </Box>
    </Paper>
  );
}