import React, { useState, useEffect } from "react";
import {
  Box,
  Typography,
  Card,
  CardContent,
  CardHeader,
  Grid,
  Button,
  Alert,
  Container,
  List,
  ListItem,
  ListItemText,
  Divider
} from "@mui/material";
import { getPlayers, postEntry } from "../services/api";
import PlayerSelect from './PlayerSelect';
import Navbar from './Navbar';

export function CreateEntry() {
  const [formData, setFormData] = useState({});

  const [submissionError, setSubmissionError] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [players, setPlayers] = useState([]);
  const [allPlayers, setallPlayers] = useState([]);
  const [selectedPlayers, setSelectedPlayers] = useState([]);
  const [remainingTeams, setRemainingTeams] = useState([]);


  useEffect(() => {
    const fetchPlayers = async () => {
      try {
        const data = await getPlayers();
        setPlayers(data);
        setallPlayers(data);
        setLoading(false);
      } catch (error) {
        setError(error);
        setLoading(false);
      }
    };
    fetchPlayers();
  }, []);

  useEffect(() => {
    // Collect unique team names
    const uniqueTeams = [...new Set(players.map(player => player.team))];

    // Filter out teams of selected players
    const filteredTeams = uniqueTeams.filter(team => {
      return !Object.values(formData).some(playerId => {
        const player = players.find(p => p.id === playerId);
        return player && player.team === team;
      });
    });

    setRemainingTeams(filteredTeams);
  }, [formData, players]);

  const handleSubmit = async (e) => {
    e.preventDefault(); // Prevent the default form submission behavior
    try {
      const data = await postEntry(formData);
      console.log('Entry created successfully:', data);
      // Handle success (e.g., show a success message, redirect, etc.)
    } catch (error) {
      setSubmissionError('Error creating entry. Please try again.');
    }
  };

  const handleChange = (field, value) => {
    setFormData((prev) => ({
      ...prev,
      [field]: value,
    }));

    // Update selected players and teams
    setSelectedPlayers((prev) => {
      const newSelectedPlayers = { ...prev };
      const previousPlayerId = formData[field];
      if (previousPlayerId) {
        delete newSelectedPlayers[previousPlayerId];
      }
      if (value) {
        newSelectedPlayers[value] = allPlayers.find(player => player.id === value);
      }
      return newSelectedPlayers;
    });
  };

  if (loading) return <div>Loading...</div>;
  if (error) return <div>Error: {error.message}</div>;

  // Collect unique team names
  const uniqueTeams = [...new Set(players.map(player => player.team))];

  return (
    <Container maxWidth="lg">
      <Navbar />
      <Box sx={{ my: 4 }}>
        {submissionError && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {submissionError}
          </Alert>
        )}
        <Grid container spacing={3}>
          <Grid item xs={12} md={3}>
            <Grid container spacing={2}>
              <Grid item xs={12}>
                <Card>
                  <CardHeader
                    title="Full Rules"
                    titleTypographyProps={{ variant: "h6" }}
                  />
                  <CardContent>
                    <Typography variant="body2">
                      <ul>
                        <li>Create a lineup of 12 players</li>
                        <li>Only one player per team allowed</li>
                        <li>Points will NOT be doubled in the Super Bowl</li>
                      </ul>
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>

              <Grid item xs={12}>
                <Card>
                  <CardHeader
                    title="Scaled FLEX Rules"
                    titleTypographyProps={{ variant: "h6" }}
                  />
                  <CardContent>
                    <Typography variant="body2">
                      <strong>Scaled FLEX Points:</strong>
                      <ul>
                        <li>50%+ ownership: No multiplier</li>
                        <li>25-50%: 1.2x multiplier</li>
                        <li>12.5-25%: 1.3x multiplier</li>
                        <li>5-12.5%: 1.5x multiplier</li>
                        <li>0-5%: 1.75x multiplier</li>
                      </ul>
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
            </Grid>
          </Grid>

          <Grid item xs={12} md={6}>
            <Card>
              <CardHeader
                title="Create Your Fantasy Football Playoff Entry"
                titleTypographyProps={{ variant: "h4" }}
              />
              <CardContent>
                <form onSubmit={handleSubmit}>
                  <Grid container spacing={2}>
                    <Grid item xs={12} sm={6}>
                      <PlayerSelect
                        label="Quarterback"
                        field="quarterback"
                        position="QB"
                        players={players}
                        remainingTeams={remainingTeams}
                        formData={formData}
                        handleChange={handleChange}
                        selectedPlayers={selectedPlayers}
                      />
                    </Grid>

                    <Grid item xs={12} sm={6}>
                      <PlayerSelect
                        label="Running Back 1"
                        field="running_back1"
                        position="RB"
                        players={players}
                        remainingTeams={remainingTeams}
                        formData={formData}
                        handleChange={handleChange}
                        selectedPlayers={selectedPlayers}
                      />
                    </Grid>

                    <Grid item xs={12} sm={6}>
                      <PlayerSelect
                        label="Running Back 2"
                        field="running_back2"
                        position="RB"
                        players={players}
                        remainingTeams={remainingTeams}
                        formData={formData}
                        handleChange={handleChange}
                        selectedPlayers={selectedPlayers}
                      />
                    </Grid>

                    <Grid item xs={12} sm={6}>
                      <PlayerSelect
                        label="Wide Receiver 1"
                        field="wide_receiver1"
                        position="WR"
                        players={players}
                        remainingTeams={remainingTeams}
                        formData={formData}
                        handleChange={handleChange}
                        selectedPlayers={selectedPlayers}
                      />
                    </Grid>

                    <Grid item xs={12} sm={6}>
                      <PlayerSelect
                        label="Wide Receiver 2"
                        field="wide_receiver2"
                        position="WR"
                        players={players}
                        remainingTeams={remainingTeams}
                        formData={formData}
                        handleChange={handleChange}
                        selectedPlayers={selectedPlayers}
                      />
                    </Grid>

                    <Grid item xs={12} sm={6}>
                      <PlayerSelect
                        label="Tight End"
                        field="tight_end"
                        position="TE"
                        players={players}
                        remainingTeams={remainingTeams}
                        formData={formData}
                        handleChange={handleChange}
                        selectedPlayers={selectedPlayers}
                      />
                    </Grid>

                    <Grid item xs={12} sm={6}>
                      <PlayerSelect
                        label="Flex 1"
                        field="flex1"
                        position="FLEX"
                        players={players}
                        remainingTeams={remainingTeams}
                        formData={formData}
                        handleChange={handleChange}
                        selectedPlayers={selectedPlayers}
                      />
                    </Grid>

                    <Grid item xs={12} sm={6}>
                      <PlayerSelect
                        label="Flex 2"
                        field="flex2"
                        position="FLEX"
                        players={players}
                        remainingTeams={remainingTeams}
                        formData={formData}
                        handleChange={handleChange}
                        selectedPlayers={selectedPlayers}
                      />
                    </Grid>

                    <Grid item xs={12} sm={6}>
                      <PlayerSelect
                        label="Flex 3"
                        field="flex3"
                        position="FLEX"
                        players={players}
                        remainingTeams={remainingTeams}
                        formData={formData}
                        handleChange={handleChange}
                        selectedPlayers={selectedPlayers}
                      />
                    </Grid>

                    <Grid item xs={12} sm={6}>
                      <PlayerSelect
                        label="Flex 4"
                        field="flex4"
                        position="FLEX"
                        players={players}
                        remainingTeams={remainingTeams}
                        formData={formData}
                        handleChange={handleChange}
                        selectedPlayers={selectedPlayers}
                      />
                    </Grid>

                    <Grid item xs={12} sm={6}>
                      <PlayerSelect
                        label="Scaled Flex"
                        field="scaled_flex"
                        position="FLEX"
                        players={players}
                        remainingTeams={remainingTeams}
                        formData={formData}
                        handleChange={handleChange}
                        selectedPlayers={selectedPlayers}
                      />
                    </Grid>

                    <Grid item xs={12} sm={6}>
                      <PlayerSelect
                        label="Defense"
                        field="defense"
                        position="DEF"
                        players={players}
                        remainingTeams={remainingTeams}
                        formData={formData}
                        handleChange={handleChange}
                        selectedPlayers={selectedPlayers}
                      />
                    </Grid>

                    <Grid item xs={12}>
                      <Button
                        type="submit"
                        variant="contained"
                        color="primary"
                        fullWidth
                      >
                        Submit Entry
                      </Button>
                    </Grid>
                  </Grid>
                </form>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={3}>
            <Card>
              <CardHeader
                title="Available Teams"
                titleTypographyProps={{ variant: "h6" }}
              />
              <CardContent>
                <List>
                  {uniqueTeams.map((team, index) => (
                    <React.Fragment key={index}>
                      <ListItem>
                        <ListItemText
                          primary={team}
                          slotProps={{
                            primary: {
                              style: {
                                color: remainingTeams.includes(team) ? 'green' : 'red'
                              }
                            }
                          }}
                        />
                      </ListItem>
                      {index < uniqueTeams.length - 1 && <Divider />}
                    </React.Fragment>
                  ))}
                </List>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </Box>
    </Container>
  );
}

export default CreateEntry;
