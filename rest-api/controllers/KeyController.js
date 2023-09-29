const apiResponse = require("../helpers/apiResponse");
//const auth = require("../middlewares/jwt");
//var mongoose = require("mongoose");
const KeyModel = require("../models/KeyModel");

const pk = KeyModel.pk;
const msk = KeyModel.msk;
const attributes = KeyModel.attributes;

/**
 * get PK.
 *
 * @returns {Object}
 */
exports.getPK = [
  function (req, res) {
    try {
      if (pk == null) {
        return apiResponse.errorResponse(res, "pk not found");
      }
      return apiResponse.successResponse(res, { pk });
    } catch (err) {
      return apiResponse.errorResponse(res, err);
    }
  },
];

/**
 * get Attributes.
 *
 * @returns {Object}
 */
exports.getAttributes = [
  function (req, res) {
    try {
      if (attributes == null) {
        return apiResponse.errorResponse(res, "attributes not found");
      }
      return apiResponse.successResponse(res, { attributes });
    } catch (err) {
      return apiResponse.errorResponse(res, err);
    }
  },
];
