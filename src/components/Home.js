// components/Home.js
import React from "react";
import { useNavigate } from "react-router-dom";
import { Typography, Paper, Box, Button } from "@mui/material";

const Home = () => {
  const navigate = useNavigate();
  
  return (
    <Paper sx={{ p: 4, mt: 4 }}>
      <Typography variant="h4" component="h1" gutterBottom>
        Welcome to the Playoff Challenge
      </Typography>
      <Box sx={{ mt: 3, mb: 3 }}>
        <Typography variant="body1" gutterBottom>
          Create a lineup of 12 players. Once the playoffs start you will not be able to change your lineup. The catch is that you can only select ONE PLAYER PER TEAM. 
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
        <Button variant="contained" color="primary" onClick={() => navigate("/login")}>
          Login
        </Button>
        <Button variant="contained" color="primary" onClick={() => navigate("/signup")}>
          Sign Up
        </Button>
      </Box>
    </Paper>
  );
};

export default Home;
