import { Router, Request, Response, NextFunction } from 'express'
import crypto from 'node:crypto'
import { config } from '../config/index.js'
import { registerSchema } from '../schemas/authSchema.js'
import { validate } from '../middlewares/validateMiddleware.js'
import { authService } from '../services/authService.js'
import { googleAuthService } from '../services/googleAuthService.js'

const router = Router()

const isProd = config.nodeEnv === 'production'

const cookieOptions = {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? ('none' as const) : ('lax' as const),
    path: '/'
}
const REFRESH_MAX_AGE = 7 * 24 * 60 * 60 * 1000

const googleRegistroSchema = registerSchema.pick({
    rol: true,
    direccion: true,
    pais: true,
    provincia: true,
    ciudad: true
})

router.get('/', (req: Request, res: Response, next: NextFunction) => {
    try {
        const state = crypto.randomBytes(16).toString('hex')
        res.cookie('oauth_state', state, { ...cookieOptions, maxAge: 5 * 60 * 1000 })
        res.redirect(googleAuthService.generarUrl(state))
    } catch (error) {
        next(error)
    }
})

router.get('/callback', async (req: Request, res: Response) => {
    const errorUrl = `${config.frontendUrl}/login?error=google`
    try {
        const { code, state } = req.query as { code?: string; state?: string }
        if (!code || !state || state !== req.cookies.oauth_state) {
            return res.redirect(errorUrl)
        }
        res.clearCookie('oauth_state', cookieOptions)

        const perfil = await googleAuthService.identificar(code)
        const user = await googleAuthService.buscarUsuario(perfil)

        if (user) {
            const { refreshToken } = authService.emitirSesion(user)
            res.cookie('refreshToken', refreshToken, { ...cookieOptions, maxAge: REFRESH_MAX_AGE })
            return res.redirect(`${config.frontendUrl}/auth/google/exito`)
        }

        res.cookie('googleRegistro', googleAuthService.firmarPendiente(perfil), {
            ...cookieOptions,
            maxAge: 15 * 60 * 1000
        })
        res.redirect(`${config.frontendUrl}/register?google=1`)
    } catch (error) {
        console.error(error)
        res.redirect(errorUrl)
    }
})

router.get('/pendiente', (req: Request, res: Response, next: NextFunction) => {
    try {
        const { email, nombre } = googleAuthService.leerPendiente(req.cookies.googleRegistro)
        res.json({ email, nombre })
    } catch (error) {
        next(error)
    }
})

router.post('/registro', validate(googleRegistroSchema), async (req: Request, res: Response, next: NextFunction) => {
    try {
        const pendiente = googleAuthService.leerPendiente(req.cookies.googleRegistro)
        const { rol, direccion, pais, provincia, ciudad } = req.body

        const { user } = await authService.register(
            pendiente.email, null, pendiente.nombre, rol, direccion,
            { pais, provincia, ciudad }, pendiente.googleId
        )

        const { refreshToken } = authService.emitirSesion(user)
        res.clearCookie('googleRegistro', cookieOptions)
        res.cookie('refreshToken', refreshToken, { ...cookieOptions, maxAge: REFRESH_MAX_AGE })
        res.status(201).json({ message: 'usuario registrado' })
    } catch (error) {
        next(error)
    }
})

export default router