'use strict'

exports['default'] = {
  jwtauth: (api) => {
    return {
      enabled: {
        web: true,
        websocket: true,
        socket: false,
        testServer: false
      },
      secret: api.config.serverToken + 'Change Me!',
      algorithm: 'HS512',
      enableGet: false // enables token as GET parameters in addition to Authorization headers
    }
  }
}

exports['test'] = {
  jwtauth: (api) => {
    return {
      enabled: {
        web: false,
        websocket: false,
        socket: false,
        testServer: false
      },
      secret: api.config.serverToken + 'Change Me!',
      algorithm: 'HS512',
      enableGet: false // enables token as GET parameters in addition to Authorization headers
    }
  }
}

exports['production'] = {
  jwtauth: (api) => {
    return {
      enabled: {
        web: true,
        websocket: true,
        socket: false,
        testServer: false
      },
      secret: api.config.serverToken + 'Change Me!',
      algorithm: 'HS512',
      enableGet: false // enables token as GET parameters in addition to Authorization headers
    }
  }
}
