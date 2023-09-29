const fs = require("fs");
const key = JSON.parse(fs.readFileSync("./data/key.json", "utf-8"));

module.exports = key;
