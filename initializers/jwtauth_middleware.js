const ActionHero = require('actionhero')

module.exports = class JWTAuthMiddleware extends ActionHero.Initializer {
  constructor () {
    super()
    this.name = 'JWTAuthMiddleware'
    this.loadPriority = 999
    this.startPriority = 999
    this.stopPriority = 999
  }

  async initialize () {
    const api = ActionHero.api
    const jwtMiddleware = {
      name: 'jwt token validator',
      global: true,
      preProcessor: (data) => {
        return new Promise((resolve, reject) => {
          // for actions that want to ignore JWT alltogether
          if (data.actionTemplate.ignoreJWT) {
            return resolve()
          }

          // is it required to have a valid token to access an action?
          var tokenRequired = false
          if (data.actionTemplate.authenticate && api.config.jwtauth.enabled[data.connection.type]) {
            tokenRequired = true
          }

          // get request data from the required sources
          var token = ''
          var req = {
            headers: data.params.httpHeaders || (data.connection.rawConnection.req ? data.connection.rawConnection.req.headers : undefined) || data.connection.mockHeaders || {},
            uri: data.connection.rawConnection.req ? data.connection.rawConnection.req.uri : {}
          }

          var authHeader = req.headers.authorization || req.headers.Authorization || false

          // extract token from http headers
          if (authHeader) {
            var parts = authHeader.split(' ')
            if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') {
              // return error if token was required and missing
              if (tokenRequired) {
                return reject({
                  code: 401,
                  message: 'Invalid Authorization Header'
                })
              } else {
                return resolve()
              }
            }
            token = parts[1]
          }

          // if GET parameter for tokens is allowed, use it
          if (!token && api.config.jwtauth.enableGet && req.uri.query && req.uri.query.token) {
            token = req.uri.query.token
          }
          // return error if token was missing but marked as required
          if (tokenRequired && !token) {
            return reject({
              code: 401,
              message: 'Authorization Header Not Set'
            })
          } else if (token) { // process token and save in connection
            api.jwtauth.processToken(token)
              .then(tokenData => {
                data.connection._jwtTokenData = tokenData
                data.connection._jwtToken = token
                return true
              })
              .then(resolve)
              .catch(e => {
                data.response.error = e
                reject(e)
              })
          } else {
            return resolve()
          }
        })
      }
    }
    api.actions.addMiddleware(jwtMiddleware)
  }
}
