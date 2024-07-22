import DBLocal from 'db-local'
import { SALT_ROUNDS } from './config.js'

import bcrypt from 'bcrypt'

const { Schema } = new DBLocal({
  path: './db'
})

const User = Schema('User', {
  _id: {
    type: String,
    required: true
  },
  username: {
    type: String,
    required: true
  },
  password: {
    type: String,
    required: true
  }
})

export class UserRepository {
  static create ({ username, password }) {
    // Validate username
    if (typeof username !== 'string' || username.length < 3) {
      throw new Error('Invalid username')
    }

    // Validate password
    if (typeof password !== 'string' || password.length < 8) {
      throw new Error('Invalid password')
    }

    // Validate that username is unique
    const user = User.findOne({ username })
    if (user) {
      throw new Error('Username already exists')
    }

    const id = Date.now().toString()

    // Hash password
    const hashedPassword = bcrypt.hashSync(password, SALT_ROUNDS)

    User.create({
      _id: id,
      username,
      password: hashedPassword
    }).save()

    return id
  }

  static login ({ username, password }) {
    // Validate username
    if (typeof username !== 'string' || username.length < 3) {
      throw new Error('Invalid username')
    }
    // Validate password
    if (typeof password !== 'string' || password.length < 8) {
      throw new Error('Invalid password')
    }

    const user = User.findOne({ username })
    if (!user) {
      throw new Error('User not found')
    }

    const isValid = bcrypt.compareSync(password, user.password)

    if (!isValid) {
      throw new Error('Invalid password')
    }

    const { password: _, ...userData } = user

    return userData
  }
}
