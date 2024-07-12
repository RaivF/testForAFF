const express = require('express')
const bodyParser = require('body-parser')
const cors = require('cors')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const fs = require('fs')
const path = require('path')
const peopleList = require('./people')

const app = express()
app.use(bodyParser.json())
app.use(cors())

const USERS_FILE = '/tmp/users.json'
const JWT_SECRET = 'your_jwt_secret_key'

// Функция для чтения данных пользователей из файла
const readUsersFromFile = () => {
	try {
		if (!fs.existsSync(USERS_FILE)) {
			fs.writeFileSync(USERS_FILE, JSON.stringify([]))
		}
		const usersData = fs.readFileSync(USERS_FILE, 'utf8')
		return JSON.parse(usersData)
	} catch (error) {
		console.error('Ошибка при чтении файла пользователей:', error)
		return []
	}
}

// Функция для записи данных пользователей в файл
const writeUsersToFile = users => {
	try {
		fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 3))
	} catch (error) {
		console.error('Ошибка при записи файла пользователей:', error)
	}
}

// Регистрация нового пользователя
app.post('/api/register', async (req, res) => {
	const { userName, email, password } = req.body
	const users = readUsersFromFile()

	const existingUser = users.find(user => user.email === email)

	if (existingUser) {
		return res.status(400).json({ message: 'Email уже зарегистрирован' })
	}

	const hashedPassword = await bcrypt.hash(password, 10)
	const newUser = { userName, email, password: hashedPassword }
	users.push(newUser)
	writeUsersToFile(users)

	return res.status(201).json({ message: 'Регистрация успешна' })
})

// Логин пользователя
app.post('/api/login', async (req, res) => {
	const { email, password } = req.body
	const users = readUsersFromFile()

	const user = users.find(user => user.email === email)
	if (!user) {
		return res.status(400).json({ message: 'Неверный email или пароль' })
	}

	const isPasswordValid = await bcrypt.compare(password, user.password)
	if (!isPasswordValid) {
		return res.status(400).json({ message: 'Неверный email или пароль' })
	}

	const token = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: '1h' })

	res.json({ token })
})

// Миддлвар для проверки токена
const authenticate = (req, res, next) => {
	const token = req.headers['authorization']
	if (!token) {
		return res.status(401).json({ message: 'Токен не предоставлен' })
	}

	try {
		const decoded = jwt.verify(token, JWT_SECRET)
		req.user = decoded
		next()
	} catch (error) {
		res.status(401).json({ message: 'Неверный токен' })
	}
}

// Получение списка пользователей (только для авторизованных пользователей)
app.get('/api/users', authenticate, (req, res) => {
	const users = readUsersFromFile()
	res.json(users)
})
//Получение данных пользователей
app.get('/api/people', (req, res) => {
	return res.status(200).json(peopleList)
})

// Получение данных конкретного пользователя (только для авторизованных пользователей)
app.get('/api/users/:email', authenticate, (req, res) => {
	const { email } = req.params
	const users = readUsersFromFile()
	const user = users.find(user => user.email === email)

	if (!user) {
		return res.status(404).json({ message: 'Пользователь не найден' })
	}

	res.json(user)
})

app.listen(8081, () => {
	console.log('Server is running on port 8080')
})
