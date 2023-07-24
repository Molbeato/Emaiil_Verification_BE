const { getAll, create, getOne, remove, update, login, verifyCode, getLoggedUser, resetUserPassword, newUserPassword } = require('../controllers/user.controllers');
const express = require('express');
const verifyJWT = require('../utils/verifyJWT');

const userRouter = express.Router();

userRouter.route('/')
    .get(verifyJWT, getAll)
    .post(create);

userRouter.route('/verify/:code')
    .get(verifyCode)

userRouter.route('/login')
    .post(login)

userRouter.route('/me')
    .get(verifyJWT, getLoggedUser)

userRouter.route('/reset_password')
    .post(resetUserPassword)

userRouter.route('/reset_password/:code')
    .post(newUserPassword)

userRouter.route('/:id')
    .get(verifyJWT, getOne)
    .delete(verifyJWT, remove)
    .put(update);

module.exports = userRouter;