import { Auth } from "aws-amplify";

async function signUp(username, password, email) {
  try {
    const { user } = await Auth.signUp({
      username,
      password,
      attributes: {
        email, // Optional: Add more attributes like phone_number, given_name, etc.
      },
    });
    console.log(user);
  } catch (error) {
    console.error("Error signing up:", error);
  }
}

async function signIn(username, password) {
  try {
    const user = await Auth.signIn(username, password);
    console.log(user);
  } catch (error) {
    console.error("Error signing in:", error);
  }
}

async function signOut() {
  try {
    await Auth.signOut();
    console.log("Signed out");
  } catch (error) {
    console.error("Error signing out:", error);
  }
}
