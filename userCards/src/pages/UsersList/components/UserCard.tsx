import style from '../styles/UserCard.module.css'
type CardProp = {
	data: {
		name: string
		id: string
		img: string
		surname: string
	}
}

const UserCard = (props: CardProp) => {
	return (
		<div className={style.card}>
			<div className={style.imgProfileContainer}>
				<img
					className={style.imgProfile}
					src={props.data.img}
					alt={props.data.name}
				/>
			</div>
			<span className={style.cardInfo}>{props.data.name}</span>
			<span className={style.cardInfo}>{props.data.surname}</span>
			<div className={style.heartContainer}>
				<div>
					<img className={style.heart} src='/heart.png' alt='' />
				</div>
			</div>
		</div>
	)
}

export default UserCard
