// Реалізуйте мідлвер для перевірки авторизації користувача
// У випадку неавторизованого користувача вертаємо помилку 401
// В іншому випадку продовжуємо обробку запиту
const passport = require("passport");

module.exports = (req, res, next) => {
    passport.authenticate(
        'jwt',
        {
            session: false,
        },
        (error, user) => {
            if (error || !user) {
                res.status(401).send('Unauthorized');
                return;
            }

            req.user = user;
            next();
        }
    )(req, res, next);
};
