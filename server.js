const cookieParser = require("cookie-parser");
const express = require("express");
const jwt = require("jsonwebtoken");

require("dotenv").config();

const app = express();

const posts = [
  {
    username: "John",
    title: "Post 1",
  },
  {
    username: "Han",
    title: "Post 2",
  },
];

app.use(express.json());
app.use(cookieParser());

const refreshTokens = [];

app.get("/", (req, res) => {
  return res.send("hi");
});

app.post("/login", (req, res) => {
  const username = req.body.username;
  const user = { name: username };

  // jwt 를 이용해 토큰 생성, payload + secretText
  // accessToken 은 유효시간 짧게
  const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: "30s",
  });
  // refreshToken 은 그보다 길게
  const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET, {
    expiresIn: "1d",
  });

  refreshTokens.push(refreshToken);

  // refreshToken 은 쿠키에 저장하지만 주로 httpOnly 옵션을 줘서 js 를 이용해서 탈취하거나 조작할 수 없게 만듭니다.
  // accessToken 은 cookie 나 localstorage, 메모리에 저장할 수 있습니다.
  res.cookie("jwt", refreshToken, {
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000,
  });

  res.json({ accessToken: accessToken });
});

app.get("/posts", authMiddleware, (req, res) => {
  res.json(posts);
});

function authMiddleware(req, res, next) {
  const authHeader = req.headers["authorization"]; // 요청 헤더에서 토큰을 가져오는 부분
  const token = authHeader && authHeader.split(" ")[1]; // 요청 헤더에서 토큰을 가져오는 부분
  if (token == null) return res.sendStatus(401);

  // verify 메소드를 이용하면 sign 메소드를 이용해서 token 을 만들때 넣어줬던 user 정보를 가져오게 됩니다.
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    console.log(err);
    if (err) return res.sendStatus(403);
    req.user = user;
    next(); // next 를 이용해 다음으로 이동할 수 있습니다.
  });
}
// body -> parsing -> req.body
// cookies -> parsing -> req.cookies
app.get("/refresh", (req, res) => {
  const cookies = req.cookies; // refreshToken 은 cookie 에 담겨 있기에 쿠키에서 가져오게 됩니다.
  if (!cookies?.jwt) return res.sendStatus(401);

  // 원래는 데이터 베이스에서 refreshToken 을 찾아야 하지만 현재 메모리에 refreshToken 을 넣어 놨기에 거기에 같은게 있는지 찾기

  const refreshToken = cookies.jwt;
  // refreshToken 이 데이터베이스에 있는 토큰인지 확인
  if (!refreshTokens.includes(refreshToken)) {
    return res.sendStatus(403);
  }

  // refreshToken 을 verify 한 후에 유효한 것이라면 다시 accessToken 을 생성해서 json 으로 보내줍니다.
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);

    // accessToken 을 생성하기
    const accessToken = jwt.sign(
      { name: user.name },
      process.env.ACCESS_TOKEN_SECRET,
      {
        expiresIn: "30s",
      }
    );

    res.json({ accessToken });
  });
});

app.listen(process.env.PORT, () => {
  console.log(`${process.env.PORT} 연결 완료`);
});
