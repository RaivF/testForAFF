import { useParams } from 'react-router-dom'
import style from './styles/UserDetails.module.css'
import { useCurrentUser } from '../../hooks/useCurrentUser'
import { Header } from '../../components/Layout/Header'

export const UserDetails = () => {
	const params = useParams()
	const currentUser = useCurrentUser(params.id!) || errorOBJ

	return (
		<div className={style.container}>
			<Header>
				<div className={style.profile}>
					<div className={style.imageProfile}>
						<img src={currentUser.img} alt='Profile' />
					</div>
					<div className={style.nameAndStatus}>
						<h1>{`${currentUser.name} ${currentUser.surname}`}</h1>
						<div className={style.status}>{currentUser.status}</div>
					</div>
				</div>
			</Header>
			<main className={style.mainContent}>
				<div className={style.description}>
					{currentUser.description.split('\n\n').map((paragraph, index) => (
						<p key={index}>{paragraph}</p>
					))}
					v{/* <p>{currentUser.description}</p> */}
				</div>
				<div className={style.contacts}>
					<div className={style.contactItem}>
						<img src='/phone.png' alt='Phone' />
						<span>{currentUser.phone}</span>
					</div>
					<div className={style.contactItem}>
						<img src='/email.png' alt='Email' />
						<span>{currentUser.email}</span>
					</div>
				</div>
			</main>
		</div>
	)
}

const errorOBJ = {
	name: '*заглушка*',
	img: 'img 2',
	id: '2',
	surname: '',
	status: ' вы нашли пасхалку =)',
	description:
		' перейдите в основной список и выберете о ком хотите получить информацию',
	email: '',
	phone: '',
}
