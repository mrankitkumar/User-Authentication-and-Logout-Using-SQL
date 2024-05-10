
const express=require("express");
const mysql = require('mysql');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const bodyParser = require("body-parser");
const app=express();

app.set("view engine", "ejs");
app.use(express.static('public'));
app.use(cookieParser());


// app.use(cookiesparser);
app.use(bodyParser.urlencoded({extented:false}));
const port=3000;
const JWT_SECRET = 'ankit';

const connection = mysql.createConnection({
    connectionLimit:100,
    host: 'localhost',
    user: 'root',
    password: 'password',
    database: 'user_auth_sql',
    debug:false

  });
  
  connection.connect((err) => {
    if (err) {
      console.error('Error connecting to database:', err);
      return;
    }
    console.log('Connected to database');
  });

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.cookies.token; 

  if (!token) {
    return res.redirect('/');
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.redirect('/');
    }
    req.username = decoded.username;
    next();
  });
};






  app.get('/dashboard',verifyToken,function(req,res)
  {
    res.render('dashboard');
  
  });

  //user landing page 
app.get('/',function(req,res)
{
    
   res.render('login');

});

//login user
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  const sql = 'SELECT * FROM users WHERE username = ?';
  connection.query(sql, [username], (err, results) => {
    if (err || results.length === 0) {
      res.status(401).render('login', { error: 'Invalid username or password' });
      return;
    }

    const user = results[0];
    if (!bcrypt.compareSync(password, user.password)) {
      res.status(401).render('login', { error: 'Invalid username or password' });
      return;
    }

    const token = jwt.sign({ username: user.username }, JWT_SECRET);
    res.cookie('token', token, { httpOnly: true });
    res.redirect('/dashboard'); 
  });
});





app.get('/register',function(req,res)
{
   res.render('register');

});


// Registration  user
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);

    await connection.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword]);
    res.redirect('/');
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error registering user' });
  }
  console.log(req.body.username);
  console.log(req.body.password);

});

  // Logout 
  app.post('/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/'); 
  });
  


app.listen(port,()=>{

  console.log('port running 3000');
});