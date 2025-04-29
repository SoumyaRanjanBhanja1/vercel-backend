const express = require('express');
const bodyParser = require('body-parser');
const mysql = require("mysql2");
const cors = require("cors");
const nodemailer=require("nodemailer");
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express();
const port = 10000;

app.use(bodyParser.json());
app.use(cors());

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password:'Sa1$####',
  database: 'Mma',
});

db.connect((err) => {
  if (err) {
    console.error('Error connecting to MySQL:', err);
    return;
  }
  console.log('Connected to MySQL');
});




const jwtSecretKey = '1234';
app.post('/api/Signup', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate input data
    if (!email || !password) {
      return res.status(400).json({ message: 'Invalid input data' });
    }

    // Check if the email is already in use
    db.query('SELECT * FROM tiger1 WHERE email = ?', [email], async (selectErr, selectResults) => {
      if (selectErr) {
        console.error('MySQL error:', selectErr);
        return res.status(500).json({ message: 'Signup failed' });
      }

      if (selectResults.length > 0) {
        return res.status(409).json({ message: 'Email already in use' });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      db.query('INSERT INTO tiger1 (email, password) VALUES (?, ?)', [email, hashedPassword], (insertErr, insertResults) => {
        if (insertErr) {
          console.error('MySQL error:', insertErr);
          return res.status(500).json({ message: 'Signup failed' });
        }
        res.status(201).json({ message: 'Signup successful' });
      });
    });
  } catch (error) {
    console.error('Error during signup', error);
    res.status(500).json({ message: 'Signup failed' });
  }
});


app.post('/api/Login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate input data
    if (!email || !password) {
      return res.status(400).json({ message: 'Invalid input data' });
    }

    // Check if the user exists in the database
    db.query('SELECT * FROM tiger1 WHERE email = ?', [email], async (err, results) => {
      if (err) {
        console.error('MySQL error:', err);
        return res.status(500).json({ message: 'Login failed' });
      }

      if (results.length === 0) {
        return res.status(401).json({ message: 'Login failed: User not found' });
      }

      // Compare the hashed password with the input password
      const user = results[0];
      const isPasswordValid = await bcrypt.compare(password, user.password);

      if (!isPasswordValid) {
        return res.status(401).json({ message: 'Login failed: Invalid password' });
      }

      // Generate and send a JWT token 
      const token = jwt.sign({ email: user.email }, jwtSecretKey, { expiresIn: '20s' });
      res.json({ message: 'Login successful', token });
    });
  } catch (error) {
    console.error('Error during login', error);
    res.status(500).json({ message: 'Login failed' });
  }
});


const forgotPasswordTransporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'bhanjasoumyaranjan113@gmail.com',
    pass: 'omsemvpmlgcvrexl'
  }
});

// Route to handle sending OTP and storing email and OTP in separate tables
app.post('/api/forgot-password', (req, res) => {
  const { email } = req.body;
  const otp = Math.floor(100000 + Math.random() * 900000); // Generate OTP

  // Check if the email exists in the database
  const checkEmailSql = `SELECT * FROM tiger WHERE email = ?`;
  db.query(checkEmailSql, [email], (checkErr, checkResult) => {
      if (checkErr) {
          console.error('Error checking email:', checkErr);
          res.status(500).json({ message: 'Error checking email' });
      } else {
          if (checkResult.length > 0) {
              // Email exists, proceed to insert email and OTP into the 'otps' table
              const insertOtpSql = `INSERT INTO otps (email, otp) VALUES (?, ?)`;
              db.query(insertOtpSql, [email, otp], (insertOtpErr, insertOtpResult) => {
                  if (insertOtpErr) {
                      console.error('Error storing email and OTP:', insertOtpErr);
                      res.status(500).json({ message: 'Error storing OTP' });
                  } else {
                      // Send OTP to the user's email
                      const mailOptions = {
                          from: 'bhanjasoumyaranjan113@gmail.com',
                          to: email,
                          subject: 'Password Reset OTP',
                          text: `Your OTP for password reset is: ${otp}`
                      };

                      forgotPasswordTransporter.sendMail(mailOptions, (error, info) => {
                          if (error) {
                              console.error('Error sending email:', error);
                              res.status(500).json({ message: 'Error sending email' });
                          } else {
                              res.status(200).json({ message: 'OTP sent to your email' });
                          }
                      });
                  }
              });
          } else {
              // Email does not exist in the database
              res.status(404).json({ message: 'Email not found' });
          }
      }
  });
});

app.post('/api/verify-otp', (req, res) => {
  const { email, otp } = req.body;

  // Check if the provided OTP matches the stored OTP in the database
  const sql = `SELECT otp FROM otps WHERE email = ?`;
  db.query(sql, [email], (err, result) => {
      if (err) {
          console.error('Error retrieving OTP:', err);
          res.status(500).json({ message: 'Error verifying OTP' });
      } else {
          if (result.length > 0) {
              const storedOTP = result[0].otp;
              if (otp === storedOTP) {
                  // If OTP is verified successfully, you can proceed with further actions like allowing the user to reset their password
                  res.status(200).json({ message: 'OTP verified successfully' });
              } else {
                  res.status(400).json({ message: 'Invalid OTP' });
              }
          } else {
              res.status(404).json({ message: 'Email not found' });
          }
      }
  });
});

app.post('/api/reset-password', (req, res) => {
  const { email, newPassword } = req.body;

  // Hash the new password
  bcrypt.hash(newPassword, 10, (err, hashedPassword) => {
    if (err) {
      console.error('Error hashing password:', err);
      res.status(500).json({ message: 'Internal server error' });
      return;
    }

    const updatePasswordQuery = 'UPDATE Monday39 SET password = ? WHERE email = ?';
    db.query(updatePasswordQuery, [hashedPassword, email], (error, results) => {
      if (error) {
        console.error('Error updating password:', error);
        res.status(500).json({ message: 'Internal server error' });
        return;
      }

      if (results.affectedRows === 0) {
        res.status(404).json({ message: 'User not found' });
        return;
      }

      // Delete records from otps table
      const deleteOTPsQuery = 'DELETE FROM otps WHERE email = ?';
      db.query(deleteOTPsQuery, [email], (deleteError, deleteResults) => {
        if (deleteError) {
          console.error('Error deleting OTP records:', deleteError);
          res.status(500).json({ message: 'Internal server error' });
          return;
        }

        res.status(200).json({ message: 'Password reset successfully' });
      });
    });
  });
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
