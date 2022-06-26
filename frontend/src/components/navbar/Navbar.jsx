import "./navbar.css";
import { Link, useNavigate } from "react-router-dom";
import { useContext } from "react";
import { AuthContext } from "../../context/AuthContext";

const Navbar = () => {

  const { user, dispatch } = useContext(AuthContext);
  

  const navigate = useNavigate();
  
  const handleLogout = async () => {
    localStorage.removeItem('access_token')
    dispatch({ type: "LOGOUT" });
    navigate("/")
  }

  return (
    <div className="navbar">
        <div className="navContainer">
          <Link to="/" style={{color:"inherit", textDecoration:"none"}}>
            <span className="logo">BookMyStay</span>
          </Link>
          {user ? (<button className="navButton" onClick={handleLogout}>Logout</button> ) : 
           (
            <div className="navItems">
                <button className="navButton"><Link to="/register">Register</Link></button>
                <button className="navButton"><Link to="/login">Login</Link></button>
            </div> 
          )}
        </div>
    </div>
  )
}

export default Navbar