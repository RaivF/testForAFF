import { useAppSelector } from '../store/store'

export const useCurrentUser = (id: string) => {
	const list = useAppSelector(state => state.cards.list)
	return list.find(item => item.id === id)
}
