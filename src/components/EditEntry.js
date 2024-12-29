import React, { useState, useEffect } from "react";
import { Box, Alert, Container, Grid, TextField, Button } from "@mui/material";
import { useParams } from "react-router-dom";
import { DndProvider } from "react-dnd";
import { HTML5Backend } from "react-dnd-html5-backend";
import { getPlayers, getEntry, updateEntry } from "../services/api";
import { processEntryData } from "../services/apiUtils";
import { handleSort, sortPlayers, filterPlayers, handleAddPlayer } from "../componentUtils";
import AvailableTeams from "./AvailableTeams";
import Roster from "./Roster";
import ScaledFlexRules from "./ScaledFlexRules";
import PlayerFilterAndTable from "./PlayerFilterAndTable";
import {
  rosterPositions,
  positionOrder,
  rbPositions,
  wrPositions,
  tePositions,
} from "../constants";

const BASE_URL = process.env.REACT_APP_API_BASE_URL || ""; // can remove when we replace home

const EditEntry = () => {
  const { id } = useParams();
  const [roster, setRoster] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [players, setPlayers] = useState([]);
  const [allPlayers, setAllPlayers] = useState([]);
  const [filterPosition, setFilterPosition] = useState("All");
  const [filterTeam, setFilterTeam] = useState("All");
  const [sortConfig, setSortConfig] = useState([
    { key: "position", direction: "ascending" },
    { key: "team", direction: "ascending" },
    { key: "name", direction: "ascending" },
  ]);
  const [teamError, setTeamError] = useState(null);
  const [rosterName, setRosterName] = useState("");
  const [searchTerm, setSearchTerm] = useState("");

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [playersData, entryData] = await Promise.all([
          getPlayers(),
          getEntry(id),
        ]);
        setPlayers(playersData);
        setAllPlayers(playersData);
        const { rosterName, roster } = processEntryData(entryData);
        setRoster(roster);
        setRosterName(rosterName);
        setLoading(false);
      } catch (error) {
        setError(error);
        setLoading(false);
      }
    };
    fetchData();
  }, [id]);

  const handleRemovePlayer = (position) => {
    setRoster((prev) => {
      const newRoster = { ...prev };
      delete newRoster[position];
      return newRoster;
    });

    // Clear any previous team error
    setTeamError(null);
  };

  const sortedPlayers = sortPlayers(players, sortConfig, positionOrder);

  const filteredPlayers = filterPlayers(
    sortedPlayers,
    roster,
    allPlayers,
    filterPosition,
    filterTeam,
    searchTerm,
    rbPositions,
    wrPositions,
    tePositions
  );

  const uniqueTeams = [...new Set(players.map((player) => player.team))];

  const isRosterFull = rosterPositions.every((position) => roster[position]);

  const handleSubmit = async () => {
    try {
      await updateEntry(id, { roster, rosterName });
      window.location.href = `${BASE_URL}/user_home/`;
    } catch (error) {
      //setSubmissionError(error.message);
    }
  };

  if (loading) return <div>Loading...</div>;
  if (error) return <div>Error: {error.message}</div>;

  return (
    <DndProvider backend={HTML5Backend}>
      <Grid container spacing={3}>
        <Grid item xs={12} md={3}>
          <Box mt={14}>
            <AvailableTeams
              uniqueTeams={uniqueTeams}
              roster={roster}
              allPlayers={allPlayers}
            />
          </Box>
          <Grid item xs={12}>
            <ScaledFlexRules />
          </Grid>
        </Grid>
        <Grid item xs={12} md={6}>
          <PlayerFilterAndTable
            filterPosition={filterPosition}
            setFilterPosition={setFilterPosition}
            filterTeam={filterTeam}
            setFilterTeam={setFilterTeam}
            uniqueTeams={uniqueTeams}
            searchTerm={searchTerm}
            setSearchTerm={setSearchTerm}
            filteredPlayers={filteredPlayers}
            handleAddPlayer={(player) =>
              handleAddPlayer(
                player,
                roster,
                setRoster,
                allPlayers,
                rbPositions,
                wrPositions,
                tePositions,
                setTeamError
              )
            }
            handleSort={(key) => handleSort(key, sortConfig, setSortConfig)}
          />
        </Grid>
        <Grid item xs={12} md={3}>
          <Box sx={{ mt: 4 }}>
            <TextField
              fullWidth
              label="Roster Name"
              value={rosterName}
              onChange={(e) => setRosterName(e.target.value)}
              margin="normal"
            />
            <Roster
              rosterPositions={rosterPositions}
              roster={roster}
              allPlayers={allPlayers}
              handleRemovePlayer={handleRemovePlayer}
              handleAddPlayer={(player) =>
                handleAddPlayer(
                  player,
                  roster,
                  setRoster,
                  allPlayers,
                  rbPositions,
                  wrPositions,
                  tePositions,
                  setTeamError
                )
              }
            />
            <Button
              variant="contained"
              color="primary"
              fullWidth
              sx={{ mt: 2 }}
              disabled={!isRosterFull}
              onClick={handleSubmit}
            >
              Update Entry
            </Button>
          </Box>
        </Grid>
      </Grid>
    </DndProvider>
  );
};

export default EditEntry;
