import jwt from 'jsonwebtoken';
import userRepository from '../repositories/UserRepository.js';
import { UserSchema, LoginSchema } from '../models/UserSchema.js';
import { MongoIdSchema } from '../models/DatabaseSchema.js';
import { SecurityUtils } from '../utils/SecurityUtils.js';
import { InvalidIDFormatError } from '../errors/ValidationError.js';
import { UserDbOutputSchemaPublic } from '../models/DatabaseSchema.js';

export const login = async (req, res) => {
  try {
    const { username, password } = LoginSchema.parse(req.body);
    const user = await userRepository.findForLogin({ username });

    if (!user || !(await SecurityUtils.comparePassword(password, user.password))) {
      return res.status(401).json({ error: "UNAUTHORIZED", message: "Invalid username or password" });
    }
    const sanitizedUser = UserDbOutputSchemaPublic.parse(user);
    const accessToken = jwt.sign(
      { id: sanitizedUser.id, username: sanitizedUser.username },
      process.env.JWT_SECRET,
      { expiresIn: '15m' }
    );

    const refreshToken = jwt.sign(
      { id: sanitizedUser.id },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: '7d' }
    );

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'Strict' : 'Lax',
      path: '/',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    return res.status(200).json({
      message: "Login Successful",
      accessToken,
      user: sanitizedUser
    });
  } catch (error) {
    if (error.name === 'ZodError' || error.errors) return res.status(400).json({
      error: "BAD_REQUEST",
      message: "Invalid input format",
      details: error.errors
    });
    console.error("[LOGIN_ERROR]:", error.message);
    return res.status(500).json({ error: "INTERNAL_SERVER_ERROR", message: "An unexpected error occurred" });
  }
};

export const refresh = async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) return res.status(401).json({ error: "UNAUTHORIZED", message: "Refresh token missing" });

    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

    const newAccessToken = jwt.sign(
      { id: decoded.id },
      process.env.JWT_SECRET,
      { expiresIn: '15m' }
    );

    const newRefreshToken = jwt.sign(
      { id: decoded.id },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: '7d' }
    );

    res.cookie('refreshToken', newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'Strict' : 'Lax',
      path: '/',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    return res.status(200).json({ accessToken: newAccessToken });
  } catch (error) {
    return res.status(403).json({ error: "FORBIDDEN", message: "Invalid or expired refresh token" });
  }
};

export const logout = async (req, res) => {
  res.clearCookie('refreshToken', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'Strict' : 'Lax',
    path: '/'
  });

  return res.status(200).json({ message: "Logout successful" });
};

export const registerUser = async (req, res) => {
  try {
    const validatedData = UserSchema.parse(req.body);

    const existingUser = await userRepository.findOne({ username: validatedData.username });
    if (existingUser) return res.status(409).json({ error: "CONFLICT", message: "This username is already taken" });

    const hashedPassword = await SecurityUtils.hashPassword(validatedData.password);

    const newUser = await userRepository.create({
      username: validatedData.username,
      password: hashedPassword
    });

    // Cria tokens
    const accessToken = jwt.sign(
      { id: newUser.id, username: newUser.username },
      process.env.JWT_SECRET,
      { expiresIn: '15m' }
    );

    const refreshToken = jwt.sign(
      { id: newUser.id },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: '7d' }
    );

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'Strict' : 'Lax',
      path: '/',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    return res.status(201).json({
      message: "User created and logged in successfully",
      accessToken,
      user: newUser
    });
  } catch (error) {
    if (error.name === 'ZodError' || error.errors) return res.status(400).json({
      error: "BAD_REQUEST",
      message: "Invalid input format",
      details: error.errors
    });
    console.error("[REGISTER_USER_ERROR]:", error.message);
    return res.status(500).json({ error: "INTERNAL_SERVER_ERROR", message: "An unexpected error occurred" });
  }
};

export const getUserById = async (req, res) => {
  try {
    const { id } = MongoIdSchema.parse(req.params);
    const authenticatedUserId = req.user.id;

    if (id !== authenticatedUserId) {
      return res.status(403).json({
        error: "FORBIDDEN",
        message: "Access denied. You are only authorized to manage your own profile"
      });
    }

    const user = await userRepository.findById(id);
    if (!user) return res.status(404).json({ error: "NOT_FOUND", message: "User not found" });

    return res.status(200).json({ message: "User retrieved successfully", user });
  } catch (error) {
    if (error.name === 'ZodError' || error.errors) return res.status(400).json({
      error: "BAD_REQUEST",
      message: "Invalid input format",
      details: error.errors
    });
    if (error.name === 'InvalidIDFormatError' || error instanceof InvalidIDFormatError) return res.status(400).json({ error: "BAD_REQUEST", message: error.message || "Invalid ID format" });
    console.error("[GET_USER_BY_ID_ERROR]:", error.message);
    return res.status(500).json({ error: "INTERNAL_SERVER_ERROR", message: "An unexpected error occurred" });
  }
};

export const updateUserById = async (req, res) => {
  try {
    const { id } = MongoIdSchema.parse(req.params);
    const authenticatedUserId = req.user.id;

    if (id !== authenticatedUserId) {
      return res.status(403).json({
        error: "FORBIDDEN",
        message: "Access denied. You are only authorized to manage your own profile"
      });
    }

    const validatedData = UserSchema.partial().parse(req.body);

    if (validatedData.password) {
      validatedData.password = await SecurityUtils.hashPassword(validatedData.password);
    }

    const user = await userRepository.updateById(id, validatedData);

    if (!user) return res.status(404).json({ error: "NOT_FOUND", message: "User not found" });

    return res.status(200).json({
      message: "User updated successfully",
      user
    });
  } catch (error) {
    if (error.name === 'ZodError' || error.errors) return res.status(400).json({
      error: "BAD_REQUEST",
      message: "Invalid input format",
      details: error.errors
    });
    if (error.name === 'InvalidIDFormatError' || error instanceof InvalidIDFormatError) return res.status(400).json({ error: "BAD_REQUEST", message: error.message || "Invalid ID format" });
    console.error("[UPDATE_USER_BY_ID_ERROR]:", error.message);
    return res.status(500).json({ error: "INTERNAL_SERVER_ERROR", message: "An unexpected error occurred" });
  }
};

export const deleteUserById = async (req, res) => {
  try {
    const { id } = MongoIdSchema.parse(req.params);
    const authenticatedUserId = req.user.id;

    if (id !== authenticatedUserId) {
      return res.status(403).json({
        error: "FORBIDDEN",
        message: "Access denied. You are only authorized to manage your own profile"
      });
    }

    const deleted = await userRepository.deleteById(id);
    if (!deleted) return res.status(404).json({ error: "NOT_FOUND", message: "User not found" });

    return res.status(200).json({ message: "User deleted successfully" });
  } catch (error) {
    if (error.name === 'ZodError' || error.errors) return res.status(400).json({
      error: "BAD_REQUEST",
      message: "Invalid input format",
      details: error.errors
    });
    if (error.name === 'InvalidIDFormatError' || error instanceof InvalidIDFormatError) return res.status(400).json({ error: "BAD_REQUEST", message: error.message || "Invalid ID format" });
    console.error("[DELETE_USER_BY_ID_ERROR]:", error.message);
    return res.status(500).json({ error: "INTERNAL_SERVER_ERROR", message: "An unexpected error occurred" });
  }
};
