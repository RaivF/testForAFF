import { createSlice, PayloadAction } from '@reduxjs/toolkit'

export interface SessionState {
	sessionInfo: {
		token: string | null
	}
}

export const initialState: SessionState = {
	sessionInfo: {
		token: null,
	},
}

const sessionSlice = createSlice({
	name: 'session',
	initialState,
	reducers: {
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		signIn: (state, action: PayloadAction<any>) => {
			state.sessionInfo.token = action.payload.token
			localStorage.setItem('token', action.payload.token)
		},
		signOut: state => {
			state.sessionInfo.token = null
			localStorage.removeItem('token')
		},
	},
})

export const actionsSession = sessionSlice.actions

export default sessionSlice.reducer
