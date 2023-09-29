var express = require("express");
const DoctorController = require("../controllers/DoctorController");

var router = express.Router();

router.post("/auth/login", DoctorController.login);
router.get("/sk", DoctorController.docSK);

module.exports = router;