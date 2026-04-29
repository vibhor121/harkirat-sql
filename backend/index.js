require('dotenv').config()

const { Pool } = require('pg')
const express = require('express')
const jwt = require('jsonwebtoken')

const JWT_SECRET = 'singhisking'

const pool = new Pool({ connectionString: process.env.DATABASE_URL })

const app = express()
app.use(express.json())


app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body
  try {
    const result = await pool.query(
      'INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id',
      [username, email, password]
    )
    res.json({ message: 'User created successfully', id: result.rows[0].id })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.post('/signin', async (req, res) => {
  const { username, password } = req.body
  try {
    const result = await pool.query(
      'SELECT * FROM users WHERE username = $1 AND password = $2',
      [username, password]
    )
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' })
    }
    const user = result.rows[0]
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' })
    res.json({ message: 'Signed in successfully', token })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.listen(3000, () => console.log('Server running on port 3000'))
