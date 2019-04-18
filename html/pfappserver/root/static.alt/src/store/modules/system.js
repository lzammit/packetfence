/**
* "system" store module
*/
import Vue from 'vue'
import apiCall from '@/utils/api'

const api = {
  getSummary: (id) => {
    return apiCall.getQuiet(`system_summary`).then(response => {
      return response.data
    })
  }
}

const types = {
  LOADING: 'loading',
  SUCCESS: 'success',
  ERROR: 'error'
}

// Default values
const state = {
  summary: false,
  message: '',
  requestStatus: ''
}

const getters = {
  isLoading: state => state.requestStatus === types.LOADING,
  version: state => state.summary.version
}

const actions = {
  getSummary: ({ commit, state }) => {
    if (state.summary) {
      return Promise.resolve(state.summary)
    }
    commit('SYSTEM_REQUEST')
    return new Promise((resolve, reject) => {
      api.getSummary().then(data => {
        commit('SYSTEM_SUCCESS', data)
        resolve(state.summary)
      }).catch(err => {
        commit('SYSTEM_ERROR', err.response)
        reject(err)
      })
    })
  }
}

const mutations = {
  SYSTEM_REQUEST: (state) => {
    state.requestStatus = types.LOADING
    state.message = ''
  },
  SYSTEM_SUCCESS: (state, data) => {
    Vue.set(state, 'summary', data)
    state.requestStatus = types.SUCCESS
    state.message = ''
  },
  SYSTEM_ERROR: (state, data) => {
    state.requestStatus = types.ERROR
    const { response: { data: { message } = {} } = {} } = data
    if (message) {
      state.message = message
    }
  }
}

export default {
  namespaced: true,
  state,
  getters,
  actions,
  mutations
}
