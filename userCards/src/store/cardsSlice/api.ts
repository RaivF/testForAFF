import axiosInstance from '../utils/axiosInstance'
import { IUserEntity } from '../types'
export const fetchUsers = async (): Promise<IUserEntity[]> => {
	try {
		const response = await axiosInstance.get('/api/people')
		return response.data
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
	} catch (error: any) {
		throw { message: error.message || 'ошибка связи с севером' }
	}
}
