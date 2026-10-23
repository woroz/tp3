import jwt from 'jsonwebtoken';
import { config } from '../config/index.js';
import { prisma } from '../utils/prisma.js';
import { AppError } from '../utils/error.js';
import {googleClient } from '../utils/googleCliente.js';
type PerfilGoogle = { googleId: string; email: string; nombre: string };

export const googleAuthService = {
    generarUrl(state: string) {
        return googleClient.generateAuthUrl({
            scope: ['openid', 'email', 'profile'],
            state,
            prompt: 'select_account'
        });
    },

    async identificar(code: string): Promise<PerfilGoogle> {
        const { tokens } = await googleClient.getToken(code);
        if (!tokens.id_token) throw new AppError('Google no devolvio el id_token', 400);

        const ticket = await googleClient.verifyIdToken({
            idToken: tokens.id_token,
            audience: config.google.clientId
        });
        const payload = ticket.getPayload();

        if (!payload?.sub || !payload.email || !payload.email_verified) {
            throw new AppError('La cuenta de google no tiene email verificado', 403);
        }

        return {
            googleId: payload.sub,
            email: payload.email,
            nombre: (payload.name ?? payload.email).slice(0, 30)
        };
    },

    async buscarUsuario({ googleId, email }: PerfilGoogle) {
        const usuario = await prisma.usuario.findUnique({
            where: { googleId },
            include: { profesor: true, alumno: true }
        });
        if (usuario) return usuario;

        const usuarioEmail = await prisma.usuario.findUnique({
            where: { email },
            include: { profesor: true, alumno: true }
        });
        if (usuarioEmail) {
            return await prisma.usuario.update({
                where: { id_usuario: usuarioEmail.id_usuario },
                data: { googleId },
                include: { profesor: true, alumno: true }
            });
        }

        return null;
    },

    firmarPendiente(perfil: PerfilGoogle) {
        return jwt.sign(perfil, config.jwt.googleRegistroSecret, { expiresIn: '15m' });
    },

    leerPendiente(token?: string): PerfilGoogle {
        if (!token) throw new AppError('La sesion de registro con google vencio', 401);
        try {
            return jwt.verify(token, config.jwt.googleRegistroSecret) as PerfilGoogle;
        } catch {
            throw new AppError('La sesion de registro con google vencio', 401);
        }
    }
};