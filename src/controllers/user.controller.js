import jwt from 'jsonwebtoken';
import UserRepository from '../repositories/user.repository.js';
import { UserSchema, LoginSchema } from '../models/user.model.js';
import { MongoIdSchema, UserDbOutputPublicSchema } from '../models/database.model.js';
import { isProd, JWT_ACCESS_SECRET, JWT_REFRESH_SECRET } from '../config/env.js';
import { ok, created, unauthorized, forbidden, notFound, conflict } from '../utils/response.util.js';
import asyncHandler from '../middlewares/async.handler.middleware.js';
import HashingUtils from '../utils/hashing.util.js';


const BASE_COOKIE_OPTIONS = {
  httpOnly: true,
  secure:   isProd,
  sameSite: isProd ? 'Strict' : 'Lax',
  signed:   true,
};

const REFRESH_COOKIE_OPTIONS = {
  ...BASE_COOKIE_OPTIONS,
  path:   '/api/v1/auth/refresh',
  maxAge: 30 * 24 * 60 * 60 * 1000,
};

const ACCESS_COOKIE_OPTIONS = {
  ...BASE_COOKIE_OPTIONS,
  path:   '/',
  maxAge: 60 * 60 * 1000,
};

const clearAuthCookies = (res) => {
  const { maxAge: _a, ...clearAccess  } = ACCESS_COOKIE_OPTIONS;
  const { maxAge: _r, ...clearRefresh } = REFRESH_COOKIE_OPTIONS;
  res.clearCookie('accessToken',  clearAccess);
  res.clearCookie('refreshToken', clearRefresh);
};

const signToken = (payload, secret, expiresIn) =>
  jwt.sign(payload, secret, { algorithm: 'HS512', expiresIn });

const issueTokenPair = (userId, username) => ({
  accessToken:  signToken({ id: userId, username }, JWT_ACCESS_SECRET,  '1h'),
  refreshToken: signToken({ id: userId },           JWT_REFRESH_SECRET, '30d'),
});

const setAuthCookies = (res, { accessToken, refreshToken }) => {
  res.cookie('accessToken',  accessToken,  ACCESS_COOKIE_OPTIONS);
  res.cookie('refreshToken', refreshToken, REFRESH_COOKIE_OPTIONS);
};

export const registerUser = asyncHandler(async (req, res) => {
  const {
    username,
    email: { encrypted: emailEncrypted, hmac: emailHmac },
    password,
  } = UserSchema.parse(req.body);

  const [usernameTaken, emailTaken] = await Promise.all([
    UserRepository.exists({ username }),
    UserRepository.exists({ emailHmac }),
  ]);

  if (usernameTaken) return conflict(res, 'This username is already taken');
  if (emailTaken)    return conflict(res, 'This email address is already registered');

  const hashedPassword = await HashingUtils.hashPassword(password);

  const newUser = await UserRepository.create({
    username,
    email:     emailEncrypted,
    emailHmac,
    password:  hashedPassword,
  });

  const { id, username: u } = newUser;
  const tokens              = issueTokenPair(id, u);

  setAuthCookies(res, tokens);
  return created(res, 'User created and logged in successfully', { tokens, user: newUser });
});

export const login = asyncHandler(async (req, res) => {
  const {
    email: { hmac: emailHmac },
    password,
  } = LoginSchema.parse(req.body);

  const user = await UserRepository.findForLogin({ emailHmac });

  const passwordMatch = user
    ? await HashingUtils.comparePassword(password, user.password)
    : await HashingUtils.dummyCompare();

  if (!user || !passwordMatch) {
    return unauthorized(res, 'Invalid email or password');
  }

  const sanitizedUser       = UserDbOutputPublicSchema.parse(user);
  const { id, username }    = sanitizedUser;
  const tokens              = issueTokenPair(id, username);

  setAuthCookies(res, tokens);
  return ok(res, 'Login successful', { tokens, user: sanitizedUser });
});

export const refresh = asyncHandler(async (req, res) => {
  const refreshToken =
    req.signedCookies.refreshToken ?? req.headers['x-refresh-token'];

  if (!refreshToken) {
    return unauthorized(res, 'Refresh token missing');
  }

  const decoded = jwt.verify(refreshToken, JWT_REFRESH_SECRET, {
    algorithms: ['HS512'],
  });

  const userExists = await UserRepository.existsById(decoded.id);
  if (!userExists) return unauthorized(res, 'User no longer exists');

  const tokens = issueTokenPair(decoded.id, decoded.username);

  setAuthCookies(res, tokens);

  return ok(res, 'Tokens refreshed', { tokens });
});

export const logout = asyncHandler(async (req, res) => {
  clearAuthCookies(res);
  return ok(res, 'Logout successful');
});

export const getUserById = asyncHandler(async (req, res) => {
  const { id } = MongoIdSchema.parse(req.params);

  if (id !== req.user.id) {
    return forbidden(res, 'Access denied. You are only authorised to manage your own profile');
  }

  const user = await UserRepository.findById(id);
  if (!user) return notFound(res, 'User not found');

  return ok(res, 'User retrieved successfully', { user: user });
});

export const getUserByToken = asyncHandler(async (req, res) => {
  const { id } = MongoIdSchema.parse({ id: req.user.id });

  const user = await UserRepository.findById(id);
  if (!user) return notFound(res, 'User not found');

  return ok(res, 'User retrieved successfully', { user: user });
});

export const updateUserById = asyncHandler(async (req, res) => {
  const { id } = MongoIdSchema.parse(req.params);

  if (id !== req.user.id) {
    return forbidden(res, 'Access denied. You are only authorised to manage your own profile');
  }

  const validatedData = UserSchema.partial().parse(req.body);

  if (validatedData.email) {
    const { encrypted, hmac } = validatedData.email;
    validatedData.email    = encrypted;
    validatedData.emailHmac = hmac;
  }

  if (validatedData.password) {
    validatedData.password = await HashingUtils.hashPassword(validatedData.password);
  }

  const updated = await UserRepository.updateById(id, validatedData);
  if (!updated) return notFound(res, 'User not found');

  return ok(res, 'User updated successfully', { user: updated });
});

export const deleteUserById = asyncHandler(async (req, res) => {
  const { id } = MongoIdSchema.parse(req.params);

  if (id !== req.user.id) {
    return forbidden(res, 'Access denied. You are only authorised to manage your own profile');
  }

  const deleted = await UserRepository.deleteById(id);
  if (!deleted) return notFound(res, 'User not found');

  clearAuthCookies(res);
  return ok(res, 'User deleted successfully');
});