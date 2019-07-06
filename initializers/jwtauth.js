const Actionhero = require('actionhero')
const jsonwebtoken = require('jsonwebtoken')

module.exports = class JWTAuthInit extends Actionhero.Initializer {
  constructor () {
    super()
    this.name = 'JWTAuthInit'
    this.loadPriority = 998
    this.startPriority = 998
    this.stopPriority = 998
  }

  async initialize () {
    const api = Actionhero.api
    api.jwtauth = {}

    api.jwtauth.processToken = async (token) => {
      return new Promise((resolve, reject) => {
        jsonwebtoken.verify(token, api.config.jwtauth.secret, {}, (err, data) => {
          err ? reject(err) : resolve(data)
        })
      })
    }

    api.jwtauth.generateToken = async (data, options) => {
      return new Promise((resolve, reject) => {
        options = options || {}

        if (!options.algorithm) {
          options.algorithm = api.config.jwtauth.algorithm
        }

        try {
          var token = jsonwebtoken.sign(data, api.config.jwtauth.secret, options)
          return resolve(token)
        } catch (err) {
          return reject(err)
        }
      })
    }

    return true
  }
}
