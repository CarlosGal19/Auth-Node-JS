import express from 'express'
import jwt from 'jsonwebtoken'
import cookieParser from 'cookie-parser'
import cors from 'cors'

import { PORT, SECRET_KEY } from './config.js'
import { UserRepository } from './user-repository.js'

const app = express()

app.set('view engine', 'ejs')

// Middleware para parsear JSON, cookies y logs
app.use(cors({
  origin: 'http://localhost:5173',
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization']
}))
app.use(express.json())
app.use(cookieParser())

// Ruta de prueba
app.get('/', (req, res) => {
  res.render('Example', { username: 'Carlos' })
})

// Ruta de inicio de sesión
app.post('/login', async (req, res) => {
  const { username, password } = req.body
  try {
    const user = await UserRepository.login({ username, password })
    const token = jwt.sign({
      username: user.username,
      id: user._id
    }, SECRET_KEY, {
      expiresIn: '1h'
    })

    res.cookie('access_token', token, {
      httpOnly: true,
      sameSite: 'Strict',
      secure: false,
      maxAge: 1000 * 60 * 60
    }).status(200).send({
      user,
      token
    })
  } catch (error) {
    return res.status(400).send({ error: error.message })
  }
})

// Ruta de registro
app.post('/register', (req, res) => {
  const { username, password } = req.body
  try {
    const id = UserRepository.create({ username, password })
    return res.status(200).send({ id })
  } catch (error) {
    return res.status(400).send({ error: error.message })
  }
})

// Ruta de protección
app.get('/protected', (req, res) => {
  const token = req.cookies.access_token
  if (!token) {
    return res.status(401).send({ error: 'Token Unauthorized' })
  }
  try {
    const data = jwt.verify(token, SECRET_KEY)
    res.render('Protected', { data: data.username })
  } catch (error) {
    return res.status(401).send({ error: 'Unauthorized' })
  }
})

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`)
})
