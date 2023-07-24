const catchError = require('../utils/catchError');
const User = require('../models/User');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sendEmail = require('../utils/sendEmail');
const EmailCode = require('../models/EmailCode');

const getAll = catchError(async(req, res) => {
    const results = await User.findAll({include: EmailCode});
    return res.json(results);
});

const create = catchError(async(req, res) => {
    const { email, password, firstName, lastName, country, image, isVerified, frontBaseUrl} = req.body;
    const encryptedPassword = await bcrypt.hash(password, 10)
    const result = await User.create({
        email,
        password: encryptedPassword,
        firstName,
        lastName,
        country,    
        image,
        isVerified
    });

    const code = require('crypto').randomBytes(32).toString("hex")
    const link = `${frontBaseUrl}/auth/verify_email/${code}`

    await EmailCode.create({
        code,
        userId: result.id
    })

    await sendEmail ({
        to: email,
        subject: "Email verification",
        html: `
        <h1>Hello ${firstName}!</h1>
        <p>Thank you for signing up on my user app!</p>
        <p>Verify your email by clicking this link</p>
        <a href= "${link}">${link}</a>
        `
    });
    return res.status(201).json(result);
});

const getOne = catchError(async(req, res) => {
    const { id } = req.params;
    const result = await User.findByPk(id);
    if(!result) return res.sendStatus(404);
    return res.json(result);
});

const remove = catchError(async(req, res) => {
    const { id } = req.params;
    await User.destroy({ where: {id} });
    return res.sendStatus(204);
});

const update = catchError(async(req, res) => {
    const { id } = req.params;
    const result = await User.update(
        req.body,
        { where: {id}, returning: true }
    );
    if(result[0] === 0) return res.sendStatus(404);
    return res.json(result[1][0]);
});

const verifyCode = catchError(async(req, res) => {
    const { code } = req.params;
    const emailCode = await EmailCode.findOne({ where: { code } })
    if(!emailCode) return res.status(401).json({ message: "Invalid code" })
    const user = await User.findByPk(emailCode.userId)
    user.isVerified = true;
    await user.save()
    await emailCode.destroy()

    return res.json(user)
});

const login = catchError(async(req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ where: { email ,isVerified: true }});
    if (!user) return res.status(401).json({ message: "Invalid credentials"})
    const isValid = await bcrypt.compare(password, user.password)
    if (!isValid) return res.status(401).json({ message: "Invalid credentials"})
  
    const token = jwt.sign(
        { user },
        process.env.TOKEN_SECRET,
        { expiresIn: "1d"} )

    return res.json({ user, token })
});

const getLoggedUser = catchError(async(req,res) => {
    const user = req.user
    return res.json(user)
});

const resetUserPassword = catchError(async(req,res) =>{
    const { email, frontBaseUrl } = req.body;
    const user = await User.findOne({ where: { email } })
    if (!user) return res.status(401).json({ message: "Invalid credentials"})
  
    const code = require('crypto').randomBytes(32).toString("hex")
    const link = `${frontBaseUrl}/auth/reset_password/${code}`

    await EmailCode.create({
        code,
        userId: user.id
    })

    await sendEmail ({
        to: email,
        subject: "Password Reset",
        html: `
        <h1>You've requested a password reset!</h1>
        <p>Did you request a password reset?</p>
        <p>If you didn't please ignore this email</p>
        <a href= "${link}">${link}</a>
        `
    });

    return res.status(201).json(user);
})

const newUserPassword = catchError(async(req,res) => {
    const { password } = req.body
    const { code } = req.params;

    const emailCode = await EmailCode.findOne({ where: { code } })
    if(!emailCode) return res.status(401).json({ message: "Invalid code" })

    const newEncryptedPassword = await bcrypt.hash(password, 10)

    const user = await User.findByPk(emailCode.userId)
    await user.save()
    await emailCode.destroy()

    const result = await User.update({
        password: newEncryptedPassword
    }, {where: {} })

    return res.status(201).json(result);
})


module.exports = {
    getAll,
    create,
    getOne,
    remove,
    update,
    login,
    verifyCode,
    getLoggedUser,
    resetUserPassword,
    newUserPassword
}