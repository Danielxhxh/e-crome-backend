const DoctorModel = require("../models/DoctorModel");
const KeyModel = require("../models/KeyModel");
const { body, validationResult } = require("express-validator");
const apiResponse = require("../helpers/apiResponse");
const auth = require("../middlewares/jwt");
const bcrypt = require("bcrypt");
//var mongoose = require("mongoose");
const jwt = require("jsonwebtoken");

const { bsw_keygen } = require("../../rust/pkg/rabe_wasm.js");
const msk = KeyModel.msk;
const pk = KeyModel.pk;

/**
 * Doc login.
 *
 * @param {string}      username
 * @param {string}      password
 *
 * @returns {Object}
 */
exports.login = [
  body("username")
    .isLength({ min: 1 })
    .trim()
    .withMessage("Username must be specified.")
    .escape(),

  body("password")
    .isLength({ min: 1 })
    .trim()
    .withMessage("Password must be specified.")
    .escape(),
  (req, res) => {
    try {
      const errors = validationResult(req);
      console.log(errors);
      if (!errors.isEmpty()) {
        let errData = {};
        errors.errors.forEach((element) => {
          errData[element.param] = element.msg;
        });
        return apiResponse.failResponse(res, errData);
      } else {
        const doctor = DoctorModel.find((el) => el.user == req.body.username);
        console.log("login", doctor);
        if (doctor) {
          //Compare given password with db's hash.
          bcrypt.compare(
            req.body.password,
            doctor.password,
            function (err, same) {
              if (same) {
                let jwtPayload = {
                  _id: doctor._id,
                  email: doctor.email,
                };
                //Prepare JWT token for authentication
                const jwtData = {
                  expiresIn: process.env.JWT_TIMEOUT_DURATION,
                };
                const secret = process.env.JWT_SECRET;
                //Generated JWT token with Payload and secret.
                const doctorData = {
                  jwt: jwt.sign(jwtPayload, secret, jwtData),
                };
                console.log(
                  JSON.parse(
                    Buffer.from(
                      doctorData.jwt.split(".")[1],
                      "base64"
                    ).toString()
                  )
                );
                return apiResponse.successResponse(res, doctorData);
              } else {
                return apiResponse.failResponse(res, {
                  password: "Password is incorrect.",
                });
              }
            }
          );
        } else {
          return apiResponse.failResponse(res, { username: "User not found." });
        }
      }
    } catch (err) {
      return apiResponse.errorResponse(res, err);
    }
  },
];

/**
 * Doc SK.
 *
 * @returns {Object}
 */
exports.docSK = [
  auth,
  function (err, req, res, next) {
    switch (err.code) {
      case "credentials_required":
        return apiResponse.failResponse(
          res,
          "No authorization token was found."
        );
      case "revoked_token":
        return apiResponse.failResponse(res, "The token has been revoked.");
      case "invalid_token":
      case "credentials_bad_scheme":
      case "credentials_bad_format":
        return apiResponse.failResponse(res, "Invalid token.");
    }
  },
  function (req, res) {
    try {
      console.log(
        jwt.verify(
          req.headers.authorization.substring(7),
          process.env.JWT_SECRET
        )
      );

      token_payload = JSON.parse(
        Buffer.from(
          req.headers.authorization.split(".")[1],
          "base64"
        ).toString()
      );
      const doctor = DoctorModel.find((el) => el._id == token_payload._id);
      console.log("doctor: ", doctor);
      if (doctor !== null) {
        if (doctor.sk == null) {
          sk_s = bsw_keygen(pk, msk, doctor.attributi);
          sk = sk_s;
        } else {
          sk = doctor.sk;
        }
        return apiResponse.successResponse(res, { sk });
      } else {
        return apiResponse.failResponseGeneric(res, "User not found.");
      }
    } catch (err) {
      return apiResponse.errorResponse(res, err);
    }
  },
];
