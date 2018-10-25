const equal = require('deep-equal')
const jwt = require('./util/jwt')

class Authenticator {
  constructor (options) {
    this.options = { accept: [ 'Basic', 'Bearer', 'Apikey' ], ...options }
    this.schemesAvailable = {
      Basic: async token => {
        const [ username, password ] = Buffer.from(token, 'base64').toString('utf8').split(':')
        return { username, password }
      },
      Apikey: async token => {
        return jwt.decode({ token, issuer: this.options.issuer, secret: this.options.secret })
      },
      Bearer: async token => {
        return jwt.decode({ token, issuer: this.options.issuer, secret: this.options.secret })
      }
    }
    this.schemes = this.options.accept
      .filter(name => this.schemesAvailable[name] !== undefined)
      .map(name => { return [ name, this.schemesAvailable[name] ] })
      .reduce((schemes, [ name, decoder ]) => { schemes[name] = decoder; return schemes }, {})
  }

  authenticate () {
    return async function (req, res, next) {
      // Obtain authentication scheme and claims from presented credentials.
      try {
        const credentials = req.headers.authorization.trim()
        const [ scheme, token ] = credentials.split(' ')
        const decode = this.schemes[scheme]
        req.authentication = { scheme, claims: await decode(token) }
      } catch (error) {
        req.authentication = undefined
      }

      // Validate authentication scheme and claims.
      if (req.authentication && this.options.validate) req.authentication = this.options.validate(req.authentication)

      // Install 'authenticated' property.
      req.authenticated = !!req.authentication

      // Override 'send' function to issue new credentials when needed.

      let send = res.send
      res.send = async function () {
        // Issue new credentials when the ones provided by the client are defunct.
        if (req.authenticated && this.options.reissue) {
          let authentication = this.options.reissue(req.authentication)
          if (!equal(authentication, req.authentication)) {
            let token = await jwt.encode({ payload: authentication.claims, issuer: this.options.issuer, secret: this.options.secret })
            let credentials = `${authentication.scheme} ${token}`
            res.header('authorization', credentials)
          }
        }
        send.apply(res, arguments)
      }
      .bind(this)

      next()
    }
    .bind(this)
  }

  authenticated () {
    return function (req, res, next) {
      if (!req.authenticated) {
        res.status(401).send()
        return
      }
      next()
    }
  }

  authorized (filter) {
    return async function (req, res, next) {
      if (!req.authenticated || (filter && !await filter(req.authentication.claims))) {
        res.status(403).send()
        return
      }
      next()
    }
  }
}

module.exports = {
  Authenticator
}
