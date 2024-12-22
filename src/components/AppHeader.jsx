import { LogoutButton } from "../components/auth/LogoutButton";
import { useAuth } from "../contexts/AuthContext";

export function AppHeader() {
  const { user } = useAuth();

  return (
    <header
      style={{
        display: "flex",
        justifyContent: "space-between",
        padding: "1rem 0",
      }}
    >
      <h1>Playoff showdown</h1>
      {user && <LogoutButton />}
    </header>
  );
}
