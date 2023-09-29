var express = require("express");
const KeyController = require("../controllers/KeyController");

var router = express.Router();

router.get("/pk", KeyController.getPK);
router.get("/attributes", KeyController.getAttributes);

module.exports = router;
