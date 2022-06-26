import axios from 'axios'
import React, { useState } from 'react';
import { useNavigate } from "react-router-dom";

import Avatar from '@mui/material/Avatar';
import Button from '@mui/material/Button';
import TextField from '@mui/material/TextField';
import FormControlLabel from '@mui/material/FormControlLabel';
import Checkbox from '@mui/material/Checkbox';
import Link from '@mui/material/Link';
import Grid from '@mui/material/Grid';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import Container from '@mui/material/Container';


const SignUp = () => {

    const [name, setName] = useState('')
    const [email, setEmail] = useState('')
    const [phone, setPhone] = useState('')
    const [password, setPassword] = useState('')
    const [confirmPassword, setConfirmPassword] = useState('')
    const [loading, setLoading] = useState(false)

    const navigate = useNavigate();

    const handleSubmit = (event) => {
        event.preventDefault();
        const data = new FormData(event.currentTarget);

        if(password===confirmPassword) {
            const user = {name, email, phone, password}
            userRegister(user)
        } else {
            alert("Password do not Match")
        }

    };


    const userRegister = async (user)=>{
       
           await axios.post("/auth/register", user)
            .then(res => {
                setLoading(false)
                navigate("/login")
            })
           .catch(err => {
            setLoading(false)
            console.log(err);
        })
    }

  return (
    // <div>
    //     <div className='row justify-content-center mt-5'>
    //     <div className="col-md-5 my-4">
    //         <div>
    //             <h1 className=' heading'>SIGN UP</h1>

    //             <div className='m-2'>
    //             <input type="text" className='form-control' placeholder='Name' 
    //              value={name} onChange={(e) => setName(e.target.value)} />
    //         </div>

    //         <div className='m-2'>
    //             <input type="email" className='form-control' placeholder='Email' 
    //             value={email} onChange={(e) => setEmail(e.target.value)} />
    //         </div>

    //         <div className='m-2'>
    //             <input type="number" className='form-control' placeholder='Mobile' 
    //             value={phone} onChange={(e) => setPhone(e.target.value)} />
    //         </div>

    //         <div className='m-2'>
    //             <input type="password" className="form-control" placeholder="Password" 
    //             value={password} onChange={(e) => setPassword(e.target.value)} />
    //         </div>

    //         <div className='m-2'>
    //             <input type="password" className="form-control" placeholder="Confirm Password" 
    //             value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} />
    //         </div>

    //         <div className='m-2'>
    //             <button className='btn card_btn w-100' disabled = {loading} onClick={handleRegister} >SUBMIT</button>
    //         </div>
    //         </div>
    //     </div>
    // </div>

    // </div>
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
            SIGN UP
          </Typography>
          
          <Box component="form" noValidate onSubmit={handleSubmit} sx={{ mt: 3 }}>
            <Grid container spacing={2}>
                
              <Grid item xs={12}>
                <TextField
                  autoComplete="name"
                  name="name"
                  required
                  fullWidth
                  id="name"
                  label="Name"
                  value={name} onChange={(e) => setName(e.target.value)}
                />
              </Grid>
              
              <Grid item xs={12}>
                <TextField
                  required
                  fullWidth
                  id="email"
                  label="Email Address"
                  name="email"
                  autoComplete="email"
                  value={email} onChange={(e) => setEmail(e.target.value)}
                />
              </Grid>

              <Grid item xs={12}>
                <TextField
                  required
                  fullWidth
                  id="phone"
                  type="tel"
                  pattern="[0-9]{3}-[0-9]{2}-[0-9]{3}"
                  label="Mobile number"
                  name="phone"
                  autoComplete="phone"
                  value={phone} onChange={(e) => setPhone(e.target.value)}
                />
              </Grid>

              <Grid item xs={12}>
                <TextField
                  required
                  fullWidth
                  name="password"
                  label="Password"
                  type="password"
                  id="password"
                  autoComplete="new-password"
                  value={password} onChange={(e) => setPassword(e.target.value)}
                />
              </Grid>

              <Grid item xs={12}>
                <TextField
                  required
                  fullWidth
                  name="confirm password"
                  label="Confirm Password"
                  type="password"
                  id="confirm_password"
                  autoComplete="new-password"
                  value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)}
                />
              </Grid>

              <Grid item xs={12}>
                <FormControlLabel
                  control={<Checkbox value="allowExtraEmails" color="primary" />}
                  label="I want to receive inspiration, marketing promotions and updates via email."
                />
              </Grid>

            </Grid>

            <Button
              type="submit"
              fullWidth
              variant="contained"
              sx={{ mt: 3, mb: 2 }}
              disabled = {loading} 
            >
              Sign Up
            </Button>

            <Grid container justifyContent="flex-end">
              <Grid item>
                <span> Already have an account? &nbsp;</span>
                <Link href="#" variant="body2">
                 Sign in
                </Link>
              </Grid>
            </Grid>

          </Box>
        </Box>
       
      </Container>
  )
}

export default SignUp