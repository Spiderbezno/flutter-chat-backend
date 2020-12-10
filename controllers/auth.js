const { response } = require('express');
const bcrypt = require('bcryptjs');
const Usuario = require('../models/usuario');
const { generarJWT } = require('../helpers/jwt');

const crearUsuario = async (req, res = response) => {

    const { email } = req.body;
    try {
        const existeEmail = await Usuario.findOne({ email });
        if (existeEmail) {
            return res.status(400).json({
                ok: false,
                msg: 'El correo ya esta registrado'
            });
        }
        const usuario = new Usuario(req.body);

        // Encriptar contraseña
        const salt = bcrypt.genSaltSync();
        usuario.password = bcrypt.hashSync(usuario.password, salt);

        await usuario.save();

        // Generar JWT
        const token = await generarJWT(usuario.id);

        res.json({
            ok: true,
            usuario,
            token,
        });

    } catch (error) {
        console.log(error);
        res.status(500).json({
            ok: false,
            msg: 'Hable con el admonistrador'
        });
    }
}

const login = async (req, res = response) => {
    const { email, password } = req.body;
    try {
        const usuarioDB = await Usuario.findOne({ email });
        if (!usuarioDB) {
            return res.status(404).json({
                ok: false,
                msg: 'Correo no encontrado'
            });
        }

        // Validar el paasword
        const validPassoword = bcrypt.compareSync(password, usuarioDB.password);
        if (!validPassoword) {
            return res.status(400).json({
                ok: false,
                msg: 'Password no valido'
            });
        }

        // Geenrar el JWT 
        const token = await generarJWT(usuarioDB.id);

        res.json({
            ok: true,
            usuarioDB,
            token,
        });
    } catch (error) {
        console.log(error);
        res.status(500).json({
            ok: false,
            msg: 'Hable con el admonistrador'
        });
    }

}

const renewToken = async (req, res = response) => {

    const uid = req.uid;

    // Generar nuevo JWT
    const token = await generarJWT(uid);

    const usuario = await Usuario.findById(uid);

    res.json({
        ok: true,
        usuario,
        token,
    });
}

module.exports = {
    crearUsuario,
    login,
    renewToken
}