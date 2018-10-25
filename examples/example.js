const { Authenticator } = require('../lib')
const express = require('express')
const equal = require('deep-equal')
const request = require('request')

// Account credentials.
let username = 'johnny'
let password = 'test1234'
let account = 1234
let role = 'admin'

async function main () {
  // Create Express server.
  let app = express()

  // Create authenticator.
  let authenticator = new Authenticator({
    accept: [ 'Basic', 'Bearer', 'Apikey' ],
    issuer: 'example-app',
    secret: 'cTxkDG3yENmtZ859REAnjmnNt',
    validate: function (credentials) {
      // Validate that claims made in client-provided credentials are valid, usually by
      // checking against a database table of usernames and passwords. If validation fails,
      // return null, undefined, or false.
      if (credentials.scheme === 'Basic') {
        // If unknown credentials, reject them.
        if (!equal(credentials.claims, { username, password })) return null

        // Override client-provided claims with validated claims.
        // Include authorization information (such as role) as needed.
        return { ...credentials, claims: { account, role }}
      }

      // Assume other schemes (Bearer and Apikey) don't expire and don't need to be validated.
      return credentials
    },
    reissue: function (credentials) {
      // Invalidate any client-supplied Basic username/password credentials.
      // Issue new credentials by returning them to the caller.
      if (credentials.scheme === 'Basic') return { scheme: 'Bearer', claims: { sub: account }}

      // Assume other schemes (Bearer and Apikey) don't expire and don't need to be reissued.
      return credentials
    }
  })

  // Enrich requests with authentication information. If a client is authenticated,
  // the request will have 'authenticated' field equal to true and the 'authentication'
  // field will carry the authentication scheme and authentication claims.
  app.use(authenticator.authenticate())

  // Routes that require users to be authenticated. If a client request is not
  // authanticated, response will be 401 Unauthorized (unauthenticated).
  app.use('/', authenticator.authenticated())

  // Routes that require users to have the admin role. If a client request is authenticated
  // but not authorized, response will be 403 Forbidden (unauthorized).
  app.use('/', authenticator.authorized(async claims => claims.role === 'admin'))

  // Default route.
  app.post('/', (req, res) => {
    res.status(200).json({ authenticated: req.authenticated, authentication: req.authentication })
  })

  // Run server.
  let server = app.listen(process.env.PORT || 3000, 'localhost', () => {
    const address = server.address()
    const base = `http://${address.address}:${address.port}`
    console.log(`Server running on ${base}`)

    // Make a credentialed HTTP GET for the web root.
    const credentials = 'Basic ' + Buffer.from(`${username}:${password}`).toString('base64')
    request.post({ url: `${base}/`, body: '', headers: { authorization: credentials }}, (error, response, body) => {
      if (error) console.log(error)
      console.log(`Response status code: ${response.statusCode}`)
      console.log('Response body:')
      console.log(body)
      console.log('Response headers:')
      console.log(response.headers)

      // Shutdown server.
      server.close()
    })
  })
}

// Run main() and catch any errors.
async function run (f) { try { await f() } catch (error) { console.log(error.message) } }
run(main)
