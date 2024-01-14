const crypto = require("crypto");
const id1 = crypto.randomBytes(20).toString("hex");
const id2 = crypto.randomBytes(20).toString("hex");
const pass = id1 + id2;
const password = pass
  .split("")
  .sort(function () {
    return 0.5 - Math.random();
  })
  .join("");
console.log(password);
