const assert = require('assert')
const bodyParser = require('body-parser')
const equal = require('deep-equal')
const express = require('express')
const request = require('request')

// Dependencies.
const { Authenticator } = require('../lib')

// Globals.
let server
let baseUrl
let body = JSON.stringify({ hello: 'world' })
let username = 'johnny'
let password = 'test1234'
let account = 1234
let role = 'admin'
let bearer

describe('testing', function () {
  after(function (done) {
    // Shutdown server.
    server.close(() => {
      done()
    })
  })

  describe('authentication', function () {
    before(function (done) {
      // Create Express server.
      let app = express()
      app.use(bodyParser.json()) // JSON body parser

      // Create authenticator.
      let authenticator = new Authenticator({
        accept: [ 'Basic', 'Bearer', 'Apikey' ],
        issuer: 'integration-test',
        secret: 'FvfDKN5vjB7B6r4qXDVNNQwQk',
        validate: function (credentials) {
          if (credentials.scheme === 'Basic') {
            if (!equal(credentials.claims, { username, password })) return null
            return { ...credentials, claims: { account, role }}
          }
          return credentials
        },
        reissue: function (credentials) {
          if (credentials.scheme === 'Basic') return { scheme: 'Bearer', claims: { sub: account }}
          return credentials
        }
      })

      // All requests should be enriched with authentication information.
      app.use(authenticator.authenticate())

      // Requests that require users to be authenticated.
      app.use('/private', authenticator.authenticated())

      // Default route.
      app.post('/', (req, res) => {
        res.status(200).json({ authenticated: req.authenticated, authentication: req.authentication })
      })

      // This route requires authentication through global middleware.
      app.post('/private', (req, res) => {
        res.status(200).json({ authenticated: req.authenticated, authentication: req.authentication })
      })

      // This route explicitly requires authentication through local moddleware.
      app.post('/private2', authenticator.authenticated(), (req, res) => {
        res.status(200).json({ authenticated: req.authenticated, authentication: req.authentication })
      })

      // Run server.
      server = app.listen(process.env.PORT || 3000, 'localhost', () => {
        const address = server.address()
        baseUrl = `http://${address.address}:${address.port}`
        done()
      })
    })

    describe('when accessing an unprotected route without being authenticated', function () {
      it('request should succeed', function (done) {
        request.post({ url: `${baseUrl}/`, body }, (error, response, body) => {
          if (error) console.log(error)
          assert.strictEqual(response.statusCode, 200)
          assert.deepStrictEqual({ authenticated: false }, JSON.parse(body))
          done()
        })
      })
    })

    describe('when accessing protected routes without being authenticated', function () {
      it('request to /private should fail', function (done) {
        request.post({ url: `${baseUrl}/private`, body }, (error, response, body) => {
          assert.strictEqual(response.statusCode, 401)
          assert.strictEqual(body, '')
          done()
        })
      })

      it('request to /private2 should fail', function (done) {
        request.post({ url: `${baseUrl}/private2`, body }, (error, response, body) => {
          assert.strictEqual(response.statusCode, 401)
          assert.strictEqual(body, '')
          done()
        })
      })
    })

    describe('when accessing protected routes while authenticated', function () {
      it('request to /private should succeed', function (done) {
        const credentials = 'Basic ' + Buffer.from(`${username}:${password}`).toString('base64')
        request.post({ url: `${baseUrl}/private`, body, headers: { authorization: credentials }}, (error, response, body) => {
          assert.strictEqual(response.statusCode, 200)
          assert.deepStrictEqual({ authenticated: true, authentication: { scheme: 'Basic', claims: { account, role }}}, JSON.parse(body))
          done()
        })
      })

      it('request to /private2 should succeed', function (done) {
        const credentials = 'Basic ' + Buffer.from(`${username}:${password}`).toString('base64')
        request.post({ url: `${baseUrl}/private2`, body, headers: { authorization: credentials }}, (error, response, body) => {
          assert.strictEqual(response.statusCode, 200)
          assert.deepStrictEqual({ authenticated: true, authentication: { scheme: 'Basic', claims: { account, role }}}, JSON.parse(body))
          done()
        })
      })
    })

    describe('when presenting Basic credentials', function () {
      it('response should contain Bearer credentials', function (done) {
        const credentials = 'Basic ' + Buffer.from(`${username}:${password}`).toString('base64')
        request.post({ url: `${baseUrl}/private`, body, headers: { authorization: credentials }}, (error, response, body) => {
          assert.strictEqual(response.statusCode, 200)
          assert.deepStrictEqual({ authenticated: true, authentication: { scheme: 'Basic', claims: { account, role }}}, JSON.parse(body))
          assert(response.headers.authorization)
          assert(response.headers.authorization.startsWith('Bearer '))
          bearer = response.headers.authorization
          done()
        })
      })
    })

    describe('when presenting Bearer credentials', function () {
      it('authentication should decrypt claims', function (done) {
        const credentials = bearer
        request.post({ url: `${baseUrl}/private`, body, headers: { authorization: credentials }}, (error, response, body) => {
          assert.strictEqual(response.statusCode, 200)
          body = JSON.parse(body)
          assert(body)
          assert(body.authentication)
          assert(body.authentication.claims)
          assert.strictEqual(body.authenticated, true)
          assert.strictEqual(body.authentication.scheme, 'Bearer')
          assert.strictEqual(body.authentication.claims.iss, 'integration-test')
          assert.strictEqual(body.authentication.claims.sub, account)
          assert(!response.headers.authorization)
          done()
        })
      })
    })
  })
})
