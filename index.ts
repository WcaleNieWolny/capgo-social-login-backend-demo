import axios from 'axios'
import { Hono } from 'hono'
import { JSONFilePreset } from 'lowdb/node'
import queryString from 'query-string';
import { readFileSync } from 'node:fs'
import jsonwebtoken from 'jsonwebtoken'
import { logger } from 'hono/logger'
import { cors } from 'hono/cors'
import jwkToPem from 'jwk-to-pem'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { jwt, sign } from 'hono/jwt'


const app = new Hono()
app.use(logger())

const db = await JSONFilePreset('db.json', { users: [] as { id: string, email: string, first_name: string, last_name: string }[] })
let appleKeys = [] as { n: string, kid: string }[]

function getClientId(platform: 'ios' | 'android') {
  return platform === 'android' ? (process.env.ANDROID_SERVICE_ID ?? '') : (process.env.IOS_SERVICE_ID ?? '')
}

const getClientSecret = (platform: "ios" | "android") => {

  const time = new Date().getTime() / 1000; // Current time in seconds since Epoch
  const privateKey = readFileSync(process.env.PRIVATE_KEY_FILE ?? '');

  console.log(privateKey)

  const headers = {
    kid: process.env.KEY_ID,
    typ: undefined,
    alg: 'ES256'
  }

  const claims = {
    'iss': process.env.TEAM_ID ?? '',
    'iat': time, // The time the token was generated
    'exp': time + 86400 * 180, // Token expiration date
    'aud': 'https://appleid.apple.com',
    'sub': getClientId(platform)
  }

  const token = jsonwebtoken.sign(claims, privateKey, {
    algorithm: 'ES256',
    header: headers
  });

  return token
}

const BASE_REDIRECT = process.env.BASE_REDIRECT_URL

app.post('/login/callback', async (c) => {
  const body = (await c.req.formData())

  const platform = c.req.header("ios-plugin-version") ? 'ios' : 'android'
  const clientSecret = getClientSecret(platform)

  const userStr = body.get('user')

  if (userStr) {
    if (typeof userStr != 'string') {
      console.error("Tried to upload file?")
      c.redirect(`${BASE_REDIRECT}?success=false`)
      return
    }

    const user = JSON.parse(userStr) as { name: { firstName: string, lastName: string }, email: string  }
    console.log(user)

    const requestBody = {
      grant_type: 'authorization_code',
      code: body.get('code'),
      redirect_uri: process.env.REDIRECT_URI,
      client_id: getClientId(platform),
      client_secret: clientSecret,
    }

    console.log(requestBody)

    const appleRes = await axios.request({
      method: "POST",
      url: "https://appleid.apple.com/auth/token",
      data: queryString.stringify(requestBody),
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    }).catch(function (error) {
      if (error.response) {
        // The request was made and the server responded with a status code
        // that falls out of the range of 2xx
        console.log(error.response.data);
        console.log(error.response.status);
        console.log(error.response.headers);
      } else if (error.request) {
        // The request was made but no response was received
        // `error.request` is an instance of XMLHttpRequest in the browser 
        // and an instance of http.ClientRequest in node.js
        console.log(error.request);
      } else {
        // Something happened in setting up the request that triggered an Error
        console.log('Error', error.message);
      }
    })

    if (!appleRes) {
      return c.redirect(`${BASE_REDIRECT}?success=false`)
    }

    const appleData = appleRes.data as { access_token: string, refresh_token: string, id_token: string }
    const parsedJwt = jsonwebtoken.decode(appleData.id_token, { complete: true })
    if (!parsedJwt || typeof parsedJwt.payload === 'string' || !parsedJwt.payload.sub || typeof parsedJwt.payload.sub != 'string') {
      console.log(`no jwt?? JWT: ${parsedJwt} Data: ${JSON.stringify(appleData)}`)
      return c.redirect(`${BASE_REDIRECT}?success=false`)
    }

    await db.update(({ users }) => users.push({
      first_name: user.name.firstName,
      last_name: user.name.lastName,
      email: user.email,
      id: (parsedJwt.payload.sub as any) ?? ''
    }))

    return c.redirect(`${BASE_REDIRECT}?success=true&access_token=${appleData.access_token}&refresh_token=${appleData.refresh_token}&id_token=${appleData.id_token}`)
  }

  // firstName = '&first_name=' + user.name.firstName
  // lastName = '&last_name=' + user.name.lastName
  // email = '&email=' + user.email
 
  if (platform != 'ios') {
    return c.redirect(`${BASE_REDIRECT}?success=true&code=${body.get('code')}&client_secret=${clientSecret}`)
  } else {
    return c.redirect(`${BASE_REDIRECT}?success=true&ios_no_code=true`)
  }
})

// userInfoZodSchema and googleExchangeZodSchema are not extenisive
const googleExchangeZodSchema = z.object({
  access_token: z.string(),
  expires_in: z.number(),
  refresh_token: z.string().optional(),
})

const userInfoZodSchema = z.object({
  email: z.string()
})

const googleDb = await JSONFilePreset('google_db.json', { users: [] as { email: string, refresh_token: string, access_token: string }[] })


app.use('/auth/google_offline', cors())
app.post(
  '/auth/google_offline',
  zValidator(
    'json',
    z.object({
      serverAuthCode: z.string(),
      platform: z.enum(["android", "ios", "web"])
    })
  ),
  async (c) => {
    const { serverAuthCode, platform } = c.req.valid('json')
    const url = new URL('https://oauth2.googleapis.com/token')
    const params = url.searchParams

    params.set("code", serverAuthCode)
    params.set('client_id', process.env.GOOGLE_CLIENT_ID ?? '')
    params.set('client_secret', process.env.GOOGLE_CLIENT_SECRET ?? '')
    params.set('redirect_uri', platform === 'web' ? 'postmessage' : '')
    params.set('grant_type', 'authorization_code')

    console.log(url)

    // exchange serverAuthCode for access_token and refresh token
    const googleResponse = await fetch(url, {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      method: 'POST'
    })
    
    // verify the response
    if (googleResponse.status !== 200) {
      console.log(`Google response returned an invalid status. Stauts: ${googleResponse.status} Text: ${await googleResponse.text()}`)
      c.json({ error: 'google_exchange_error' }, 500)
      return
    }

    const rawBody = await googleResponse.json()
    const parsed = googleExchangeZodSchema.safeParse(rawBody)
    if (!parsed.success) {
      console.log('Cannot parse exchange response', parsed.error)
      c.json({ error: 'google_exchange_error_parse' }, 500)
      return
    }

    const access = parsed.data
    // fetch the userinfo
    const userinfoResponse = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
      headers: {
        "Authorization": `Bearer ${access.access_token}`,
        "Content-Type": "application/json"
      }
    })

    if (userinfoResponse.status !== 200) {
      console.log(`Google userinfo returned an invalid status. Stauts: ${userinfoResponse.status} Text: ${await userinfoResponse.text()}`)
      c.json({ error: 'google_user_info_error' }, 500)
      return
    }

    const parsedUserInfo = userInfoZodSchema.safeParse(await userinfoResponse.json())
    if (!parsedUserInfo.success) {
      console.log('Cannot parse user info', parsedUserInfo.error)
      c.json({ error: 'google_userinfo_error_parse' }, 500)
      return
    }

    const { email } = parsedUserInfo.data
    const user = googleDb.data.users.find(usr => usr.email === email)
    if (user) {
      const refreshToken = access.refresh_token ?? user.refresh_token
      if (user.refresh_token != refreshToken) {
        user.refresh_token = refreshToken
      }
      user.access_token = access.access_token
      await googleDb.write()
    } else {
      if (!access.refresh_token) {
        // this should never happen
        console.error("User not found, and refresh token was not provided?")
        c.json({ error: 'user_not_found_and_no_refresh_token' }, 500)
        return
      }
      googleDb.data.users.push({
        email: email,
        access_token: access.access_token,
        refresh_token: access.refresh_token ?? '' 
      })
      await googleDb.write()
    }

    const jwt = await sign({
      sub: email,
      exp: Math.floor(Date.now() / 1000) + access.expires_in,
    }, process.env.CUSTOM_JWT_SECRET ?? '')

    return c.json({ jwt })
    // ... use your validated data
  }
)

app.use('/auth/get_google_user', cors())
app.use(
  '/auth/get_google_user',
  jwt({
    secret: process.env.CUSTOM_JWT_SECRET ?? '',
  })
)
app.get('/auth/get_google_user', async (c) => {
  const email = c.get('jwtPayload').sub
  if (email === null) {
    return c.json({error: 'invalid_request'}, 400);
  }

  const user = googleDb.data.users.find(usr => usr.email === email)
  if (!user) {
    return c.json({ error: 'user_not_found' }, 500)
  }

  const userinfoResponse = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
    headers: {
      "Authorization": `Bearer ${user.access_token}`,
      "Content-Type": "application/json"
    }
  })

  if (userinfoResponse.status !== 200) {
    console.log(`Google userinfo returned an invalid status. Stauts: ${userinfoResponse.status} Text: ${await userinfoResponse.text()}`)
    c.json({ error: 'google_user_info_error' }, 500)
    return
  }

  return c.text(await userinfoResponse.text())
})

app.post('/auth/google_validation', async (c) => {
  let authHeader = c.req.header('Authorization')

  if (!authHeader) {
    return c.json({ error: 'No auth header' }, 401)
  }

  if (authHeader && authHeader.startsWith('Bearer ')) {
    authHeader = authHeader.substring(7)
  }

  const googleValidationRes = await fetch(`https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=${authHeader}`)
  if (googleValidationRes.status !== 200) {
    return c.json({ error: 'Google could not verify access token' }, 401)
  }

  const googleRes = await googleValidationRes.json() as { email: string }
  return c.text(`Hello ${googleRes.email}!`)
})

// TODO: add a last fetch, if key is not found locally and last fetch was > 5 mins ago refetch
async function getApplePublicKey(kid: String) {
  if (appleKeys.length === 0) {
    const res = await axios.get('https://appleid.apple.com/auth/keys').catch(function (error) {
      if (error.response) {
        // The request was made and the server responded with a status code
        // that falls out of the range of 2xx
        console.log(error.response.data);
        console.log(error.response.status);
        console.log(error.response.headers);
      } else if (error.request) {
        // The request was made but no response was received
        // `error.request` is an instance of XMLHttpRequest in the browser 
        // and an instance of http.ClientRequest in node.js
        console.log(error.request);
      } else {
        // Something happened in setting up the request that triggered an Error
        console.log('Error', error.message);
      }
    })

    if (!res) {
      return null
    }

    appleKeys = res.data.keys
  }

  return appleKeys.find(key => key.kid === kid)
}

app.use('/userdata', cors())
app.get('/userdata', async (c) => {
  let authHeader = c.req.header('Authorization')

  if (!authHeader) {
    return c.json({ error: 'No auth header' }, 401)
  }

  if (authHeader && authHeader.startsWith('Bearer ')) {
    authHeader = authHeader.substring(7)
  }

  const parsedJwt = jsonwebtoken.decode(authHeader, { complete: true })
  if (parsedJwt == null) {
    return c.json({ error: 'JWT is null?' }, 400)
  }

  if (!parsedJwt.header.kid) {
    return c.json({ error: 'No kid in JWT header' }, 403)
  }

  if (!parsedJwt.payload.sub) {
    return c.json({ error: 'No sub in JWT payload' }, 403)
  }

  const userId = typeof parsedJwt.payload.sub == 'string' ? parsedJwt.payload.sub : parsedJwt.payload.sub()

  const key = await getApplePublicKey(parsedJwt.header.kid)

  if (!key) {
    return c.json({ error: 'Cannot find apple public key' }, 500)
  }

  let pemKey: string | null = null
  try {
    pemKey = jwkToPem(key as any)
  } catch (e) {
    console.error('Cannot convert apple key', e)
    return c.json({ error: 'Cannot convert apple key', more_detailed: JSON.stringify(e) }, 500)
  }

  if (!pemKey) {
    return c.json({ error: 'Cannot find apple public PEM key' }, 500)
  }
  

  let verifyErr = null
  console.log(authHeader, key)

  try {
    jsonwebtoken.verify(authHeader, pemKey, {
      audience: [process.env.ANDROID_SERVICE_ID ?? '', process.env.IOS_SERVICE_ID ?? ''],
    });
  } catch (err) {
    verifyErr = { error: err }
  }

  if (verifyErr != null) {
    return c.json(verifyErr, 500)
  }
  
  // User is legit :)
  const data = db.data.users.find(user => user.id === userId)
  if (!data) {
    return c.json({ error: 'cannot find user data for valid JWT' }, 500)
  }

  return c.json(data)
})

export default { 
  port: 3000, 
  fetch: app.fetch, 
} 