import { createStore } from 'vuex';

const store = createStore({
  state() {
    let token = localStorage.getItem("token")
    return {
      apiToken: token,
    }
  },
  mutations: {
    setApiToken(state, payload) {
      localStorage.setItem("token", payload.token)
      state.apiToken = payload.token;
    }
  },
  getters: {
    apiToken(state) {
      return state.apiToken;
    },
  },
})

export default store;
