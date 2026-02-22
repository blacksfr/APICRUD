export default (req, res, next) => {
  if (!req.timedout) next();
}