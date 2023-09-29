var express = require("express");
var doctorRouter = require("./doctor");
var keyRouter = require("./key");

var app = express();

app.use("/doctor/", doctorRouter);
app.use("/key/", keyRouter);

module.exports = app;
