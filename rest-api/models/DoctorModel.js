const fs = require("fs");
const docs = JSON.parse(fs.readFileSync("./data/doctors.json", "utf-8"));

module.exports = docs;

/* COME DOVREBBE ESSERE IN CASO DI UN DATABASE.
var mongoose = require("mongoose");

var DoctorSchema = new mongoose.Schema(
  {
    email: { type: String, required: true },
    user: { type: String, required: true },
    password: { type: String, required: true },
    attributi: [{type: String, required: true}]
  }
);

module.exports = mongoose.model("Doctor", DoctorSchema);
*/
