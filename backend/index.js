require('dotenv').config()

const { Pool } = require('pg')
const express = require('express')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')
const { z } = require('zod')

const JWT_SECRET = process.env.JWT_SECRET
const SALT_ROUNDS = 10

const pool = new Pool({ connectionString: process.env.DATABASE_URL })

const app = express()
app.use(express.json())

// Zod schema for signup input validation
const signupSchema = z.object({
  username: z
    .string()
    .min(3, 'Username must be at least 3 characters')
    .max(30, 'Username must be at most 30 characters')
    .regex(/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers, and underscores'),

  email: z
    .string()
    .email('Invalid email address'),

  password: z
    .string()
    .min(6, 'Password must be at least 6 characters')
    .max(100, 'Password is too long'),
})

app.post('/signup', async (req, res) => {
  const result = signupSchema.safeParse(req.body)

  if (!result.success) {
    const errors = result.error.issues.map(e => ({
      field: e.path[0],
      message: e.message,
    }))
    return res.status(400).json({ errors })
  }

  const { username, email, password } = result.data
  try {
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS)
    const dbResult = await pool.query(
      'INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id',
      [username, email, hashedPassword]
    )
    res.json({ message: 'User created successfully', id: dbResult.rows[0].id })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.post('/signin', async (req, res) => {
  const { username, password } = req.body
  try {
    const result = await pool.query(
      'SELECT * FROM users WHERE username = $1',
      [username]
    )
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' })
    }
    const user = result.rows[0]
    const passwordMatch = await bcrypt.compare(password, user.password)
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid credentials' })
    }
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' })
    res.json({ message: 'Signed in successfully', token })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.listen(3000, () => console.log('Server running on port 3000'))
