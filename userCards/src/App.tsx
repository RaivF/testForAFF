import React, { useEffect } from 'react'
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom'
import Register from './components/Auth/Register'
import Login from './components/Auth/Login'
import { UsersList } from './pages/UsersList'
import { UserDetails } from './pages/UserDetails'
import { useAppDispatch, useAppSelector } from './store/store'
import { actionsSession } from './store/sessionSlice'

const App: React.FC = () => {
	const dispatch = useAppDispatch()
	useEffect(() => {
		const userSessionToken = localStorage.getItem('token')

		if (userSessionToken) {
			dispatch(actionsSession.signIn({ token: userSessionToken }))
		}
	}, [])

	const { sessionInfo } = useAppSelector(state => state.session)

	return (
		<Router>
			<Routes>
				<Route path='/register' element={<Register />} />
				<Route path='/' element={<Login />} />
				{sessionInfo.token && (
					<>
						<Route path='/users' element={<UsersList />} />
						<Route path='/users/:id' element={<UserDetails />} />
					</>
				)}
			</Routes>
		</Router>
	)
}

export default App
