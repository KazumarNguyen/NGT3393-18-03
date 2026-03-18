let jwt = require("jsonwebtoken");
let fs = require("fs");
let path = require("path");

// Load RSA keys
const privateKey = fs.readFileSync(
  path.join(__dirname, "../private.pem"),
  "utf8",
);
const publicKey = fs.readFileSync(
  path.join(__dirname, "../public.pem"),
  "utf8",
);

module.exports = {
  generateToken: function (userId) {
    return jwt.sign({ userId: userId }, privateKey, {
      algorithm: "RS256",
      expiresIn: "24h",
    });
  },

  verifyToken: function (req, res, next) {
    try {
      // Lấy token từ header Authorization
      const token = req.headers.authorization?.split(" ")[1];

      if (!token) {
        return res.status(401).send({
          message: "Vui lòng cung cấp token",
        });
      }

      // Verify token
      const decoded = jwt.verify(token, publicKey, { algorithms: ["RS256"] });
      req.userId = decoded.userId;
      next();
    } catch (error) {
      return res.status(401).send({
        message: "Token không hợp lệ hoặc hết hạn",
      });
    }
  },
};
