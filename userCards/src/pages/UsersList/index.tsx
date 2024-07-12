import React, { useEffect } from 'react'

import { useAppDispatch, useAppSelector } from '../../store/store'
import style from './styles/UsersList.module.css'
import { thunks } from '../../store/cardsSlice'
import { useNavigate } from 'react-router-dom'
import { Header } from '../../components/Layout/Header'
import UserCard from './components/UserCard'

export const UsersList: React.FC = () => {
	const dispatch = useAppDispatch()
	const { list } = useAppSelector(state => state.cards)
	const navigate = useNavigate()

	useEffect(() => {
		dispatch(thunks.getData())
	}, [dispatch])

	const goToAbout = (e: string) => {
		navigate(`/users/${e}`)
	}

	return (
		<div>
			<Header>
				<div className={style.content}>
					<h1>Наша команда</h1>

					<div className={style.description}>
						<p>
							Это опытные специалисты, хорошо разбирающиеся во всех задачах,
							которые ложатся на их плечи, и умеющие находить выход из любых,
							даже самых сложных ситуаций.
						</p>
					</div>
				</div>
			</Header>
			<div className={style.containerCardList}>
				{list?.map(
					(data: {
						id: string
						name: string
						img: string
						surname: string
					}) => (
						<div key={data.id} onClick={() => goToAbout(data.id)}>
							<UserCard data={data} />
						</div>
					)
				)}
			</div>
		</div>
	)
}

export default UsersList
