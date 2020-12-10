/*
    path: api/login
*/

const { Router } = require('express');
const { check } = require('express-validator');
const { crearUsuario, login, renewToken } = require('../controllers/auth');
const { validarCampos } = require('../middlewares/validar-campos');
const { validarJWT } = require('../middlewares/validar-jwt');

const router = Router();

router.post('/new',  [
    check('nombre', 'El nombre es obligatorio').notEmpty(),
    check('email', 'El email es obligatorio').notEmpty(),
    check('email', 'El email no es correcto').isEmail(),
    check('password', 'El password es obligatorio').notEmpty(),
    validarCampos
],crearUsuario);

router.post('/', [
    check('email', 'El email es obligatorio').notEmpty(),
    check('email', 'El email no es correcto').isEmail(),
    check('password', 'El password es obligatorio').notEmpty()
], login);

router.get('/renew', validarJWT, renewToken);

module.exports = router;