const bcrypt = require("bcrypt");

const jwt = require("../utils/jwt");
const { User } = require('../models');

exports.register = async (req, res, next) => {
  try {
    // 1. Створіть нового користувача з унікальним username та зашифрованим паролем
    // 2. Підготуйте payload для генерації jwt токена
    // 3. Згенеруйте jwt токен

    const { username, password } = req.body;

    const existingUser = await User.findOne({
      username,
    });

    if (existingUser) {
      res.status(422).send("Username already in use!");
      return;
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const user = await User.create({
      username,
      password: hashedPassword,
    });

    const payload = {
      _id: user.id,
    };

    const token = jwt.generateJwt(payload);

    user.token = token;
    await user.save();

    res.json({
      user,
      "token": user.token,
    });
  } catch (error) {
    console.log(error);
    res.status(500).send(error);
  }
};

exports.login = async (req, res, next) => {
  try {
    // 1. Виконайте валідацію полей username, password
    // 2. Підготуйте payload та згенеруйте jwt токен

    const { username, password } = req.body;

    const user = await User.findOne({
      username,
    });

    if (!user) {
      res.status(400).send("Username or password is wrong!");
      return;
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      res.status(400).send("Username or password is wrong!");
      return;
    }

    const payload = {
      _id: user.id,
    };

    const token = jwt.generateJwt(payload);

    user.token = token;
    await user.save();

    res.json({
      user,
      "token": user.token,
    });
  } catch (error) {
    console.log(error);
    res.status(500).send(error);
  }
};

exports.getProfile = async (req, res, next) => {
  try {
    // 1. Забороніть використання роута для неавторизованих користувачів
    // 2. У відповідь передайте дані авторизованого користувача

    if (!req.user) {
      res.status(401).send("Not authorized!");
      return;
    }

    res.json(req.user);
  } catch (error) {
    console.log(error);
    res.status(500).send(error);
  }
};
