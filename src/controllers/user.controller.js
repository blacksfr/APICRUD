import jwt from 'jsonwebtoken';
import UserRepository from '../repositories/user.repository.js';
import { UserSchema, LoginSchema } from '../models/user.model.js';
import { MongoIdSchema, UserDbOutputPublicSchema } from '../models/database.model.js';
import { SID_NAME, CSRF_NAME, isProd, JWT_ACCESS_SECRET, JWT_REFRESH_SECRET } from '../config/env.js';
import { ok, created, unauthorized, forbidden, notFound, conflict } from '../utils/response.util.js';
import { generateCsrfToken } from '../config/csrf.config.js';
import { regenerateSessionId } from '../middlewares/regenerate.session.middleware.js';
import asyncHandler from '../middlewares/async.handler.middleware.js';
import HashingUtils from '../utils/hashing.util.js';
import logger from '../config/logger.config.js';

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

const clearSessionCookie = (res) => res.clearCookie(SID_NAME, { path: '/'});

const clearCsrfCookie = (res) => res.clearCookie(CSRF_NAME, { path: '/'});

const clearAuthCookies = (res) => {
  res.clearCookie('accessToken', {
    httpOnly: true,
    secure:   isProd,
    sameSite: isProd ? 'Strict' : 'Lax',
    signed:   true,
    path:     '/',
  });
  res.clearCookie('refreshToken', {
    httpOnly: true,
    secure:   isProd,
    sameSite: isProd ? 'Strict' : 'Lax',
    signed:   true,
    path:     '/api/v1/auth/refresh',
  });
}

export const clearAllSessionCookies = (res) => {
clearSessionCookie(res);
clearCsrfCookie(res);
clearAuthCookies(res);
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

  logger.info(
    { event: 'user_register_attempt', requestId: req.id, username },
    '[UserController] Registration attempt',
  );

  const [usernameTaken, emailTaken] = await Promise.all([
    UserRepository.exists({ username }),
    UserRepository.exists({ emailHmac }),
  ]);

  if (usernameTaken) {
    logger.warn(
      { event: 'user_register_conflict_username', requestId: req.id, username },
      '[UserController] Registration failed — username already taken',
    );
    return conflict(res, 'This username is already taken');
  }

  if (emailTaken) {
    logger.warn(
      { event: 'user_register_conflict_email', requestId: req.id },
      '[UserController] Registration failed — email already registered',
    );
    return conflict(res, 'This email address is already registered');
  }

  const hashedPassword = await HashingUtils.hashPassword(password);

  clearAllSessionCookies(res);
  
  regenerateSessionId(req, res);

  const newUser = await UserRepository.create({
    username,
    email:    emailEncrypted,
    emailHmac,
    password: hashedPassword,
  });

  const { id, username: u } = newUser;
  const tokens    = issueTokenPair(id, u);
  const csrfToken = generateCsrfToken(req, res);

  setAuthCookies(res, tokens);

  logger.info(
    { event: 'user_registered', requestId: req.id, userId: id, username: u },
    '[UserController] User registered and logged in successfully',
  );

  return created(res, 'User created and logged in successfully', { tokens, user: newUser, csrfToken });
});

export const login = asyncHandler(async (req, res) => {
  const {
    email: { hmac: emailHmac },
    password,
  } = LoginSchema.parse(req.body);

  logger.info(
    { event: 'user_login_attempt', requestId: req.id },
    '[UserController] Login attempt',
  );

  const user = await UserRepository.findForLogin({ emailHmac });

  const passwordMatch = user
    ? await HashingUtils.comparePassword(password, user.password)
    : await HashingUtils.dummyCompare();

  if (!user || !passwordMatch) {
    logger.warn(
      { event: 'user_login_failed', requestId: req.id, reason: !user ? 'user_not_found' : 'wrong_password' },
      '[UserController] Login failed — invalid credentials',
    );
    return unauthorized(res, 'Invalid email or password');
  }

  clearAllSessionCookies(res);

  regenerateSessionId(req, res);

  const sanitizedUser       = UserDbOutputPublicSchema.parse(user);
  const { id, username }    = sanitizedUser;
  const tokens              = issueTokenPair(id, username);
  const csrfToken           = generateCsrfToken(req, res);

  setAuthCookies(res, tokens);

  logger.info(
    { event: 'user_logged_in', requestId: req.id, userId: id, username },
    '[UserController] Login successful',
  );

  return ok(res, 'Login successful', { tokens, user: sanitizedUser, csrfToken });
});

export const refresh = asyncHandler(async (req, res) => {
  const refreshToken =
    req.signedCookies.refreshToken ?? req.headers['x-refresh-token'];

  if (!refreshToken) {
    logger.warn(
      { event: 'token_refresh_missing', requestId: req.id },
      '[UserController] Refresh token missing',
    );
    return unauthorized(res, 'Refresh token missing');
  }

  const decoded = jwt.verify(refreshToken, JWT_REFRESH_SECRET, {
    algorithms: ['HS512'],
  });

  const userExists = await UserRepository.existsById(decoded.id);

  if (!userExists) {
    logger.warn(
      { event: 'token_refresh_user_not_found', requestId: req.id, userId: decoded.id },
      '[UserController] Token refresh failed — user no longer exists',
    );
    return unauthorized(res, 'User no longer exists');
  }

  regenerateSessionId(req, res);

  const tokens    = issueTokenPair(decoded.id, decoded.username);
  const csrfToken = generateCsrfToken(req, res);

  setAuthCookies(res, tokens);

  logger.info(
    { event: 'tokens_refreshed', requestId: req.id, userId: decoded.id },
    '[UserController] Tokens refreshed successfully',
  );

  return ok(res, 'Tokens refreshed', { tokens, csrfToken });
});

export const logout = asyncHandler(async (req, res) => {
  clearAllSessionCookies(res);

  logger.info(
    { event: 'user_logged_out', requestId: req.id, userId: req.user?.id },
    '[UserController] User logged out',
  );

  return ok(res, 'Logout successful');
});

export const getUserById = asyncHandler(async (req, res) => {
  const { id } = MongoIdSchema.parse(req.params);

  if (id !== req.user.id) {
    logger.warn(
      { event: 'user_access_denied', requestId: req.id, requestedId: id, requesterId: req.user.id },
      '[UserController] Access denied — unauthorized profile access attempt',
    );
    return forbidden(res, 'Access denied. You are only authorised to manage your own profile');
  }

  const user = await UserRepository.findById(id);

  if (!user) {
    logger.warn(
      { event: 'user_not_found', requestId: req.id, userId: id },
      '[UserController] User not found',
    );
    return notFound(res, 'User not found');
  }

  logger.debug(
    { event: 'user_retrieved', requestId: req.id, userId: id },
    '[UserController] User retrieved by id',
  );

  return ok(res, 'User retrieved successfully', { user });
});

export const getUserByToken = asyncHandler(async (req, res) => {
  const { id } = MongoIdSchema.parse({ id: req.user.id });

  const user = await UserRepository.findById(id);

  if (!user) {
    logger.warn(
      { event: 'user_not_found', requestId: req.id, userId: id },
      '[UserController] User not found via token',
    );
    return notFound(res, 'User not found');
  }

  logger.debug(
    { event: 'user_retrieved', requestId: req.id, userId: id },
    '[UserController] User retrieved by token',
  );

  return ok(res, 'User retrieved successfully', { user });
});

export const updateUserById = asyncHandler(async (req, res) => {
  const { id } = MongoIdSchema.parse(req.params);

  if (id !== req.user.id) {
    logger.warn(
      { event: 'user_access_denied', requestId: req.id, requestedId: id, requesterId: req.user.id },
      '[UserController] Access denied — unauthorized profile update attempt',
    );
    return forbidden(res, 'Access denied. You are only authorised to manage your own profile');
  }

  const validatedData = UserSchema.partial().parse(req.body);

  if (validatedData.email) {
    const { encrypted, hmac } = validatedData.email;
    validatedData.email     = encrypted;
    validatedData.emailHmac = hmac;
  }

  if (validatedData.password) {
    validatedData.password = await HashingUtils.hashPassword(validatedData.password);
  }

  const updated = await UserRepository.updateById(id, validatedData);

  if (!updated) {
    logger.warn(
      { event: 'user_not_found', requestId: req.id, userId: id },
      '[UserController] Update failed — user not found',
    );
    return notFound(res, 'User not found');
  }

  logger.info(
    { event: 'user_updated', requestId: req.id, userId: id },
    '[UserController] User updated successfully',
  );

  return ok(res, 'User updated successfully', { user: updated });
});

export const deleteUserById = asyncHandler(async (req, res) => {
  const { id } = MongoIdSchema.parse(req.params);

  if (id !== req.user.id) {
    logger.warn(
      { event: 'user_access_denied', requestId: req.id, requestedId: id, requesterId: req.user.id },
      '[UserController] Access denied — unauthorized delete attempt',
    );
    return forbidden(res, 'Access denied. You are only authorised to manage your own profile');
  }

  const deleted = await UserRepository.deleteById(id);

  if (!deleted) {
    logger.warn(
      { event: 'user_not_found', requestId: req.id, userId: id },
      '[UserController] Delete failed — user not found',
    );
    return notFound(res, 'User not found');
  }

  clearAllSessionCookies(res);

  logger.info(
    { event: 'user_deleted', requestId: req.id, userId: id },
    '[UserController] User deleted successfully',
  );

  return ok(res, 'User deleted successfully');
});