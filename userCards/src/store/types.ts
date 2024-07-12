export interface IUserEntity {
	id: string
	name: string
	img: string
	description: string
	email: string
	phone: string
	surname: string
	status: string
}

export type userLoginType = {
	isLogged: boolean
	login: string
}

export type IError = {
	message: string
	code: number
}

export interface InitialState {
	CurrentPeople: IUserEntity[]
	list: IUserEntity[]
	isLoading: boolean
	error: IError | null
}
