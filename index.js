const express = require('express')
const crypto = require("node:crypto");
const {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse
} = require('@simplewebauthn/server')


if (!globalThis.crypto) {
    globalThis.crypto = crypto;
}

const PORT = 3000
const app = express();

app.use(express.static('./public'))
app.use(express.json())

// States
const userStore = {}
const challengeStore = {}

app.post('/register', (req, res) => {
    const { username, password } = req.body
    const id = `user_${Date.now()}`

    const user = {
        id,
        username,
        password
    }

    userStore[id] = user

    console.log(`Register successfull`, userStore[id])

    return res.json({ id })

})

app.post('/register-challenge', async (req, res) => {
    const { userId } = req.body

    // check whether the entered user id is registered or not 
    if (!userStore[userId]) return res.status(404).json({ error: 'user not found!' })

    // userid is stored here
    const user = userStore[userId]

    const challengePayload = await generateRegistrationOptions({
        rpID: 'localhost',
        rpName: 'My Localhost Machine',
        attestationType: 'none',
        userName: user.username,
        timeout: 30_000,
    })

    challengeStore[userId] = challengePayload.challenge

    // user use this challenge to sign-in
    return res.json({ options: challengePayload })

})

app.post('/register-verify', async (req, res) => {
    const { userId, cred } = req.body

    if (!userStore[userId]) return res.status(404).json({ error: 'user not found!' })
    const user = userStore[userId]
    const challenge = challengeStore[userId]

    const verificationResult = await verifyRegistrationResponse({
        expectedChallenge: challenge,
        expectedOrigin: 'http://localhost:3000',
        expectedRPID: 'localhost',
        response: cred,
    })

    if (!verificationResult.verified) return res.json({ error: 'could not verfied' });
    // the passkey of the user is stored in the backend from the below code
    userStore[userId].passkey = verificationResult.registrationInfo

    return res.json({ verified: true })
})

app.post('/login-challenge', async (req, res) => {
    const { userId } = req.body
    if (!userStore[userId]) return res.status(404).json({ error: 'user not found!' })

    const opts = await generateAuthenticationOptions({
        rpID: 'localhost',
    })

    // to store the challenge in the database 
    challengeStore[userId] = opts.challenge

    // the challenge is returned to the user
    return res.json({ options: opts })

})

app.post('/login-verify', async (req, res) => {
    const { userId, cred }  = req.body

    if (!userStore[userId]) return res.status(404).json({ error: 'user not found!' })
    const user = userStore[userId]
    const challenge = challengeStore[userId]

    const result = await verifyAuthenticationResponse({
        expectedChallenge: challenge,
        expectedOrigin: 'http://localhost:3000',
        expectedRPID: 'localhost',
        response: cred,
        authenticator: {
            credentialPublicKey: user.passkey.credentialPublicKey,
            counter: user.passkey.counter,
        },
    })

    if (!result.verified) return res.json({ error: 'something went wrong' })
    
    // Login the user: Session, Cookies, JWT
    user.passkey.counter = result.authenticationInfo.newCounter;
    return res.json({ verified: true });
})

app.listen(PORT, () => console.log(`Server started on PORT:${PORT}`))