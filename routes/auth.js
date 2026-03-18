let express = require("express");
let router = express.Router();
let userController = require("../controllers/users");
let bcrypt = require("bcrypt");
let { generateToken, verifyToken } = require("../utils/authHandler");
let userModel = require("../schemas/users");
let {
  validatedResult,
  ChangePasswordValidator,
} = require("../utils/validator");

router.post("/register", async function (req, res, next) {
  try {
    let { username, password, email } = req.body;
    let newUser = await userController.CreateAnUser(
      username,
      password,
      email,
      "69b1265c33c5468d1c85aad8",
    );
    res.send(newUser);
  } catch (error) {
    res.status(404).send({
      message: error.message,
    });
  }
});
router.post("/login", async function (req, res, next) {
  try {
    let { username, password } = req.body;
    let user = await userController.GetAnUserByUsername(username);
    if (!user) {
      res.status(404).send({
        message: "thong tin dang nhap khong dung",
      });
      return;
    }
    if (user.lockTime && user.lockTime > Date.now()) {
      res.status(404).send({
        message: "ban dang bi ban",
      });
      return;
    }
    if (bcrypt.compareSync(password, user.password)) {
      user.loginCount = 0;
      await user.save();
      let token = generateToken(user._id);
      res.send({
        id: user._id,
        token: token,
      });
    } else {
      user.loginCount++;
      if (user.loginCount == 3) {
        user.loginCount = 0;
        user.lockTime = Date.now() + 3600 * 1000;
      }
      await user.save();
      res.status(404).send({
        message: "thong tin dang nhap khong dung",
      });
    }
  } catch (error) {
    res.status(404).send({
      message: error.message,
    });
  }
});

router.get("/me", verifyToken, async function (req, res, next) {
  try {
    let user = await userModel
      .findOne({
        _id: req.userId,
        isDeleted: false,
      })
      .select("-password");

    if (!user) {
      return res.status(404).send({
        message: "User not found",
      });
    }
    res.send(user);
  } catch (error) {
    res.status(404).send({
      message: error.message,
    });
  }
});

router.post(
  "/changepassword",
  verifyToken,
  ChangePasswordValidator,
  validatedResult,
  async function (req, res, next) {
    try {
      let { oldpassword, newpassword } = req.body;

      // Lấy user hiện tại từ token
      let user = await userController.GetAnUserById(req.userId);
      if (!user) {
        return res.status(404).send({
          message: "User not found",
        });
      }

      // Kiểm tra oldpassword
      if (!bcrypt.compareSync(oldpassword, user.password)) {
        return res.status(401).send({
          message: "Old password is incorrect",
        });
      }

      // Kiểm tra newpassword không được trùng oldpassword
      if (oldpassword === newpassword) {
        return res.status(400).send({
          message: "New password must be different from old password",
        });
      }

      // Set password mới - middleware sẽ tự động hash
      user.password = newpassword;
      await user.save();

      res.send({
        message: "Password changed successfully",
      });
    } catch (error) {
      res.status(404).send({
        message: error.message,
      });
    }
  },
);

module.exports = router;
