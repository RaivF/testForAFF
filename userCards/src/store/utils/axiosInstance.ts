import axios from 'axios'

const axiosInstance = axios.create({
	baseURL: 'https://serverssv1.vercel.app', // новый URL для всех запросов
	headers: {
		'Content-Type': 'application/json',
	},
})

axiosInstance.interceptors.request.use(
	config => {
		const token = localStorage.getItem('token') // получение токена из локального хранилища

		if (token) {
			config.headers['Authorization'] = `Bearer ${token}`
		}
		return config
	},
	error => {
		return Promise.reject(error)
	}
)

export default axiosInstance
