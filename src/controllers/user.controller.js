import jwt from 'jsonwebtoken';
import UserRepository from '../repositories/user.repository.js';
import { UserSchema, LoginSchema } from '../models/user.model.js';
import { MongoIdSchema } from '../models/database.model.js';
import { HashingUtils } from '../utils/hashing.util.js';
import { UserDbOutputPublicSchema } from '../models/database.model.js';
import { isProd, JWT_SECRET, JWT_REFRESH_SECRET } from '../config/env.js';
import asyncHandler from '../middlewares/async.handler.middleware.js';
import { ok, created, unauthorized, forbidden, notFound, conflict } from '../utils/response.util.js';

const REFRESH_COOKIE_OPTIONS = {
  httpOnly: true,
  secure: isProd,
  sameSite: isProd ? 'Strict' : 'Lax',
  path: '/',
  maxAge: 7 * 24 * 60 * 60 * 1000,
  signed: true
};

const clearRefreshCookie = (res) => {
  const { maxAge, ...clearOptions } = REFRESH_COOKIE_OPTIONS;
  res.clearCookie('refreshToken', clearOptions);
};

const createNewJWT = (payload, SECRET, expiresIn) => {
  return jwt.sign(payload, SECRET, { expiresIn });
};

export const login = asyncHandler(async (req, res) => {
  const { username, password } = LoginSchema.parse(req.body);
  const user = await UserRepository.findForLogin({ username });

  if (!user || !(await HashingUtils.comparePassword(password, user.password))) {
    return unauthorized(res, 'Invalid username or password');
  }

  const sanitizedUser = UserDbOutputPublicSchema.parse(user);
  const { id: sanitizedId, username: sanitizedUsername } = sanitizedUser;

  const accessToken  = createNewJWT({ id: sanitizedId, username: sanitizedUsername }, JWT_SECRET, '15m');
  const refreshToken = createNewJWT({ id: sanitizedId }, JWT_REFRESH_SECRET, '7d');

  res.cookie('refreshToken', refreshToken, REFRESH_COOKIE_OPTIONS);

  return ok(res, 'Login Successful', { accessToken, user: sanitizedUser });
});

export const refresh = asyncHandler(async (req, res) => {
  const refreshToken = req.signedCookies.refreshToken;
  if (!refreshToken) {
    return unauthorized(res, 'Refresh token missing');
  }

  const decoded = jwt.verify(refreshToken, JWT_REFRESH_SECRET);

  const user = await UserRepository.findById(decoded.id);
  if (!user) {
    return unauthorized(res, 'User no longer exists');
  }
  const { id: userId, username: userUsername } = user;

  const newAccessToken  = createNewJWT({ id: userId, username: userUsername }, JWT_SECRET, '15m');
  const newRefreshToken = createNewJWT({ id: userId }, JWT_REFRESH_SECRET, '7d');

  res.cookie('refreshToken', newRefreshToken, REFRESH_COOKIE_OPTIONS);

  return ok(res, null, { accessToken: newAccessToken });
});

export const logout = asyncHandler(async (req, res) => {
  clearRefreshCookie(res);
  return ok(res, 'Logout successful');
});

export const registerUser = asyncHandler(async (req, res) => {
  const validatedData = UserSchema.parse(req.body);

 const alreadyExists = await UserRepository.exists({ username: validatedData.username });
  if (alreadyExists) {
    return conflict(res, 'This username is already taken');
  }

  const hashedPassword = await HashingUtils.hashPassword(validatedData.password);

  const newUser = await UserRepository.create({
    username: validatedData.username,
    password: hashedPassword
  });
  const { id: newUserId, username: newUserUsername } = newUser;

  const accessToken  = createNewJWT({ id: newUserId, username: newUserUsername }, JWT_SECRET, '15m');
  const refreshToken = createNewJWT({ id: newUserId }, JWT_REFRESH_SECRET, '7d');

  res.cookie('refreshToken', refreshToken, REFRESH_COOKIE_OPTIONS);

  return created(res, 'User created and logged in successfully', { accessToken, user: newUser });
});

export const getUserById = asyncHandler(async (req, res) => {
  const { id } = MongoIdSchema.parse(req.params);

  if (id !== req.user.id) {
    return forbidden(res, 'Access denied. You are only authorized to manage your own profile');
  }

  const user = await UserRepository.findById(id);
  if (!user) return notFound(res, 'User not found');

  return ok(res, 'User retrieved successfully', { user });
});

export const updateUserById = asyncHandler(async (req, res) => {
  const { id } = MongoIdSchema.parse(req.params);

  if (id !== req.user.id) {
    return forbidden(res, 'Access denied. You are only authorized to manage your own profile');
  }

  const validatedData = UserSchema.partial().parse(req.body);

  if (validatedData.password) {
    validatedData.password = await HashingUtils.hashPassword(validatedData.password);
  }

  const user = await UserRepository.updateById(id, validatedData);
  if (!user) return notFound(res, 'User not found');

  const { id: userUpdateId, username: userUpdateUsername } = user;

  const accessToken  = createNewJWT({ id: userUpdateId, username: userUpdateUsername }, JWT_SECRET, '15m');
  const refreshToken = createNewJWT({ id: userUpdateId }, JWT_REFRESH_SECRET, '7d');

  res.cookie('refreshToken', refreshToken, REFRESH_COOKIE_OPTIONS);

  return ok(res, 'User updated successfully', { accessToken, user });
});

export const deleteUserById = asyncHandler(async (req, res) => {
  const { id } = MongoIdSchema.parse(req.params);

  if (id !== req.user.id) {
    return forbidden(res, 'Access denied. You are only authorized to manage your own profile');
  }

  const deleted = await UserRepository.deleteById(id);
  if (!deleted) return notFound(res, 'User not found');

  clearRefreshCookie(res);
  return ok(res, 'User deleted successfully');
});