import { useNavigate } from 'react-router-dom'
import style from './Header.module.css'
import { actionsSession } from '../../store/sessionSlice'
import { useAppDispatch } from '../../store/store'

export const Header = ({ children }: { children: JSX.Element }) => {
	const navigate = useNavigate()
	const dispatch = useAppDispatch()
	const path = window.location.pathname

	const clickHandler = () => {
		navigate(-1)
	}
	const clickHandlerLogout = () => {
		dispatch(actionsSession.signOut())
		localStorage.removeItem('token')
		navigate('/')
	}
	return (
		<div className={style.header}>
			<div className={style.back_container}>
				<button
					className={
						path === '/users' ? (style.buttons, style.hide) : style.buttons
					}
					onClick={clickHandler}
				>
					Назад
				</button>
			</div>
			<div className={style.back_min_container}>
				<button
					className={
						path === '/users'
							? (style.back_min_buttons, style.hide)
							: style.back_min_buttons
					}
					onClick={clickHandler}
				>
					<img src='/back.png' alt='' />
				</button>
			</div>
			{children}
			<div className={style.logout_min_container}>
				<button
					className={style.logout_min_buttons}
					onClick={() => {
						clickHandlerLogout()
					}}
				>
					<img src='/logout.png' alt='' />
				</button>
			</div>
			<div className={style.logout_container}>
				<button
					className={style.buttons}
					onClick={() => {
						clickHandlerLogout()
					}}
				>
					Выход
				</button>
			</div>
		</div>
	)
}
