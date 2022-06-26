import axios from "axios";
import { useContext, useState } from "react";
import { useNavigate } from "react-router-dom";
import { AuthContext } from "../../context/AuthContext";

import Avatar from '@mui/material/Avatar';
import Button from '@mui/material/Button';
import TextField from '@mui/material/TextField';
import Link from '@mui/material/Link';
import Grid from '@mui/material/Grid';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import Container from '@mui/material/Container';

const Login = () => {


    const [email, setEmail] = useState('')
    const [password, setPassword] = useState('')

const { loading, error, dispatch } = useContext(AuthContext);

const navigate = useNavigate();

const handleSubmit = async (event) => {
  event.preventDefault();
  const data = new FormData(event.currentTarget);

  const credentials = {email, password}
  console.log(credentials)
  dispatch({ type: "LOGIN_START" });
    try { 
      const res = await axios.post("/auth/login", credentials);
      dispatch({ type: "LOGIN_SUCCESS", payload: res.data.user });
      localStorage.setItem("access_token", res.data.access_token);
      navigate("/")
    } catch (err) {
      dispatch({ type: "LOGIN_FAILURE", payload: err.response.data });
    }
}


return (
  
    <Container component="main" maxWidth="xs">
        <Box
          sx={{
            marginTop: 8,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
          }}
        >
          <Avatar sx={{ m: 1, bgcolor: 'secondary.main' }}>
          </Avatar>
          <Typography component="h1" variant="h5">
            LOGIN
          </Typography>
          <Box component="form"  noValidate onSubmit={handleSubmit} sx={{ mt: 1 }}>
            <TextField
              margin="normal"
              required
              fullWidth
              id="email"
              label="Email Address"
              name="email"
              autoComplete="email"
              autoFocus
              value={email} onChange={(e) => setEmail(e.target.value)}
            />
            <TextField
              margin="normal"
              required
              fullWidth
              name="password"
              label="Password"
              type="password"
              id="password"
              autoComplete="current-password"
              value={password} onChange={(e) => setPassword(e.target.value)}
            />
            
            <Button
              type="submit"
              fullWidth
              variant="contained"
              sx={{ mt: 3, mb: 2 }}
            >
              Sign In
            </Button>

            <Grid container>
              <Grid item xs>
                <Link href="#" variant="body2">
                  Forgot password?
                </Link>
              </Grid>
              
              <Grid item>
                <span> Don't have an account? &nbsp;</span>
                <Link href="#" variant="body2">
                 Sign Up
                </Link>
              </Grid>
            </Grid>
          </Box>
        </Box>
     
      </Container>
  );
};
export default Login;