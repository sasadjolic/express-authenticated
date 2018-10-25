const jwt = require('node-webtokens')

async function encode ({ payload, issuer, secret }) {
  return new Promise(function (resolve, reject) {
    try {
      jwt.generate('PBES2-HS512+A256KW', 'A256GCM', { ...payload, iss: issuer }, secret, (error, token) => {
        if (error) { reject(error); return }
        if (token.error) { reject(token.error); return }
        resolve(token)
      })
    } catch (error) {
      reject(error)
    }
  })
}

function decode ({ token, issuer, secret }) {
  return new Promise(function (resolve, reject) {
    try {
      jwt.parse(token)
        // .setTokenLifetime(120000)
        .setAlgorithmList('PBES2-HS512+A256KW', 'A256GCM')
        .setIssuer([issuer])
        .verify(secret, (error, token) => {
          if (error) { reject(error); return }
          if (token.error) { reject(token.error); return }
          resolve(token.payload)
        })
    } catch (error) {
      reject(error)
    }
  })
}

module.exports = {
  encode,
  decode
}
