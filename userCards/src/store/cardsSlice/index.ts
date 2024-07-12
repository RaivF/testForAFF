import { AsyncThunk, PayloadAction, createSlice } from '@reduxjs/toolkit'
import { IError, InitialState, IUserEntity } from '../types'
import { getData } from './thunks'

export const initialState: InitialState = {
	list: [],
	CurrentPeople: [],
	isLoading: false,
	error: null,
}

export const cardsSlice = createSlice({
	name: 'cardsSlice',
	initialState: initialState,
	reducers: {
		setData: (state: InitialState, action: PayloadAction<IUserEntity[]>) => {
			return { ...state, list: action.payload }
		},
		setIsLoading: (state: InitialState, action: PayloadAction<boolean>) => {
			return { ...state, isLoading: action.payload }
		},
		setCurrentPeople: (
			state: InitialState,
			action: PayloadAction<IUserEntity[]>
		) => {
			return { ...state, CurrentPeople: action.payload }
		},

		setError: (state: InitialState, action: PayloadAction<IError | null>) => {
			return { ...state, IError: action.payload }
		},
	},
})

export const actionsCard = cardsSlice.actions
export const thunks: {
	getData: AsyncThunk<void, void, object>
} = {
	getData,
}

export default cardsSlice.reducer
