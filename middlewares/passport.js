const { Strategy } = require('passport-google-oauth2');
const passport = require('passport');
const { nanoid } = require('nanoid');
const bcrypt = require('bcrypt');

const { User } = require('../models/user');

const { GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, BASE_URL } = process.env;

// параметры при авторизации
const googleParams = {
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: `${BASE_URL}/api/auth/google/callback`,
    passReqCallback: true,
}
// передаем коллбек
const googleCallback = async(req, accessToken, refreshToken, profile, done) => {
    try {
        const { email, displayName } = profile; // из профиля пользователя берем email, displayName
        const user = await User.findOne({ email }); // ищем есть ли в базе пользователь с таким email 
        if (user) {
            done(null, user); // если есть,то передаем первым аргументом(ошибку или null) вторым-имя пользователя(req.user=user)
        }
        const password = nanoid(); // генерим пароль
        const hashPassword = await bcrypt.hash(password, 10); // хешируем пароль
        const newUser = await User.create({ email, name: displayName, password: hashPassword }); // иначе регистрируем пользователя и сохраняем в базе
        done(null, newUser); // передаем в req.user записываем того кого только что зарегистрировали (req.user=user)
    } catch (error) {
        done(error, false) // передаем дальше ошибку
    }
}
// создаем стратегию
const googleStrategy = new Strategy(googleParams, googleCallback);

// прописываем паспорт по стратегии
passport.use('google', googleStrategy);

module.exports = passport;