import { notFound } from "../utils/response.util.js";

export default (req, res) => {
  notFound(res, `The route [${req.method}] ${req.url} does not exist`);
}