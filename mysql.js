require("dotenv").config()
var mysql = require('mysql');
const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const morgan = require("morgan")
const jwt = require("jsonwebtoken")

const app = express();
app.use(morgan("combined"));
app.use(cors());

app.use(bodyParser.json());

var db = mysql.createConnection({
  host: "svc.sel5.cloudtype.app",
  user: "root",
  password: "1234",
  database: "charity",
  port: 31675
});
app.post("/register", async (req, res) => {
  const { name, userid, email, password } = req.body;

  db.query(
    "SELECT userid FROM user WHERE userid = ?",
    [userid],
    async (error, results) => {
      if (error) {
        console.log(error);
        return res.send({ message: "An error occurred" });
      }

      if (results.length > 0) {
        return res.send({ message: "This email is already in use" });
      }

      try {
        const hashedPassword = await bcrypt.hash(password, 10); // 수정된 부분: salt 값으로 10을 사용

        db.query(
          "INSERT INTO user SET ?",
          { name: name, email: email, password: hashedPassword, userid: userid },
          (error, results) => {
            if (error) {
              console.log(error);
              return res.send({ message: "An error occurred" });
            } else {
              return res.send({ message: "User registered" });
            }
          }
        );
      } catch (error) {
        console.log(error);
        return res.send({ message: "An error occurred" });
      }
    }
  );
});

app.post("/login", async (req, res) => {
  const { userid, password } = req.body;

  // 데이터베이스에서 id로 사용자를 조회
  db.query("SELECT * FROM user WHERE userid = ?", [userid], async (error, results) => {
    if (error) {
      console.log(error);
      return res.status(500).send({ message: "Server error" });
    }

    if (results.length == 0) {
      return res.status(404).send({ message: "User not found" });
    }

    const user = results[0];

    // 비밀번호 검증
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).send({ message: "Password is incorrect" });
    }

    // JWT 생성
    const accessToken = jwt.sign(
      { userid: user.userid },
      process.env.ACCESS_TOKEN_SECRET
    );

    // 응답에 토큰 포함
    res.send({ message: "Logged in", accessToken: accessToken });
  });
});// 유저 정보 업데이트
app.put('/update', async (req, res) => {
  const { name, email, password } = req.body;
  const token = req.headers['authorization'];

  if (!token) {
    return res.status(403).send({ message: "No token provided" });
  }

  try {
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    const userid = decoded.userid;

    const hashedPassword = await bcrypt.hash(password, 10); 

    db.query(
      "UPDATE user SET name = ?, email = ?, password = ? WHERE userid = ?",
      [name, email, hashedPassword, userid],
      (error, results) => {
        if (error) {
          console.log(error);
          return res.send({ message: "An error occurred while updating." });
        } else {
          return res.send({ message: "User updated successfully." });
        }
      }
    );
  } catch (error) {
    console.log(error);
    return res.send({ message: "An error occurred while updating." });
  }
});

// 유저 삭제
app.delete('/delete', (req, res) => {
  const token = req.headers['authorization'];

  if (!token) {
    return res.status(403).send({ message: "No token provided" });
  }

  try {
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    const userid = decoded.userid;

    db.query(
      "DELETE FROM user WHERE userid = ?",
      [userid],
      (error, results) => {
        if (error) {
          console.log(error);
          return res.send({ message: "An error occurred while deleting." });
        } else {
          return res.send({ message: "User deleted successfully." });
        }
      }
    );
  } catch (error) {
    console.log(error);
    return res.send({ message: "An error occurred while deleting." });
  }
});

db.connect((err) => {
  if (err) throw err;
  console.log("Connetct to MySQL server");
})
app.listen(3001, () => console.log("Server is running on port 3001"));
