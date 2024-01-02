import { createStore } from 'vuex';
import config from './Config.js';

const store = createStore({
  state: () => ({
    user: "",
    isLoggedIn: false,
  }),
  mutations: {
    setIsLoggedIn(state, payload) {
      state.isLoggedIn = payload.loggedIn;
    },
    setUser(state, payload) {
      state.user = payload.user;
    }
  },
  actions: {
    async login(context, payload) {
     const response = await fetch(config.backendAddress + "/login", {
       method: 'POST',
        body: JSON.stringify({
          user: payload.user,
          password: payload.password,
        })
      });

      const responseData = await response.json();
      if (responseData.status != config.backendResultOk) {
        context.commit('setIsLoggedIn', {
          loggedIn: true,
        })

        context.commit('setUser', {
          user: payload.user,
        })
      } else {
        // TODO throw error?
        console.log(responseData);
        context.commit('setIsLoggedIn', {
          loggedIn: false,
        })
      }
    }
  },
  getters: {
    isLoggedIn(state) {
      return state.isLoggedIn;
    },
  },
})

export default store;
