const createBody = (message, payload) => ({
  ...(message && { message }),
  ...(payload && { ...payload })
});

export const ok = (res, message = null, payload = null) =>
  res.status(200).json(createBody(message, payload));

export const created = (res, message = null, payload = null) =>
  res.status(201).json(createBody(message, payload));

export const badRequest = (res, message = null, payload = null) =>
  res.status(400).json({ error: 'BAD_REQUEST', ...createBody(message, payload) });

export const unauthorized = (res, message = null, payload = null) =>
  res.status(401).json({ error: 'UNAUTHORIZED', ...createBody(message, payload) });

export const forbidden = (res, message = null, payload = null) =>
  res.status(403).json({ error: 'FORBIDDEN', ...createBody(message, payload) });

export const notFound = (res, message = null, payload = null) =>
  res.status(404).json({ error: 'NOT_FOUND', ...createBody(message, payload) });

export const conflict = (res, message = null, payload = null) =>
  res.status(409).json({ error: 'CONFLICT', ...createBody(message, payload) });

export const payloadTooLarge = (res, message = null, payload = null) =>
  res.status(413).json({ error: 'PAYLOAD_TOO_LARGE', ...createBody(message || 'Maximum limit is 1MB', payload) });

export const serviceUnavailable = (res, message = null, payload = null) =>
  res.status(503).json({ error: 'SERVICE_UNAVAILABLE', ...createBody(message || 'The server took too long to respond', payload) });

export const internal_server_error = (res, message = null, payload = null) =>
  res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', ...createBody(message || 'An unexpected error occurred', payload) });

//----

export const zodErrorProcess = (res, err) => badRequest(res, 'Invalid input format', {
  details: err.issues.map(issue => ({
    path: issue.path.join('.'),
    message: issue.message
  }))
});