//This code runs tests for all the API endpoints of the appliction
const request = require("supertest");
const mongoose = require("mongoose");
const app = require("../../server");
const User = require("../../src/models/User");

describe("Auth Routes (/api/auth)", () => {
  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      if (!process.env.MONGODB_URL) {
        throw new Error("MONGODB_URL is not set (needed for tests)");
      }
      await mongoose.connect(process.env.MONGODB_URL);
    }
  });

  beforeEach(async () => {
    await User.deleteMany({});
  });

  afterAll(async () => {
    await mongoose.connection.close();
  });

  // =====================================================================================
  // POST /api/auth/signup
  // =====================================================================================
  describe("POST /api/auth/signup", () => {
    test("201: creates user, sets accessToken + refreshToken cookies, returns public profile (no tokens in body)", async () => {
      const payload = {
        name: "Test User",
        username: "testuser",
        email: "test@example.com",
        password: "Str0ngPassw0rd!",
      };

      const res = await request(app).post("/api/auth/signup").send(payload).expect(201);

      expect(res.body).toEqual(
        expect.objectContaining({
          id: expect.any(String),
          name: payload.name,
          username: payload.username,
          email: payload.email,
        })
      );

      expect(res.body.accessToken).toBeUndefined();
      expect(res.body.refreshToken).toBeUndefined();

      const setCookie = res.headers["set-cookie"];
      expect(setCookie).toBeDefined();
      expect(Array.isArray(setCookie)).toBe(true);

      const cookiesJoined = setCookie.join(" | ");
      expect(cookiesJoined).toMatch(/accessToken=/);
      expect(cookiesJoined).toMatch(/refreshToken=/);
      expect(cookiesJoined.toLowerCase()).toMatch(/httponly/);

      const created = await User.findOne({ email: payload.email.toLowerCase() }).lean();
      expect(created).toBeTruthy();
      expect(created.username).toBe(payload.username);
      expect(created.name).toBe(payload.name);
      expect(created.passwordHash).toBeTruthy();
      expect(created.passwordHash).not.toBe(payload.password);
    });

    test("400: rejects missing fields", async () => {
      const res = await request(app)
        .post("/api/auth/signup")
        .send({ email: "only@example.com" })
        .expect(400);

      expect(res.body).toEqual({ error: "All fields are required" });
    });

    test("409: rejects when a user already exists (email OR username)", async () => {
      await User.create({
        name: "Existing",
        username: "existinguser",
        email: "existing@example.com",
        passwordHash: "fake_hash",
      });

      const res1 = await request(app)
        .post("/api/auth/signup")
        .send({
          name: "New User",
          username: "newuser",
          email: "existing@example.com",
          password: "Str0ngPassw0rd!",
        })
        .expect(409);

      expect(res1.body).toEqual({ error: "User already exists" });

      const res2 = await request(app)
        .post("/api/auth/signup")
        .send({
          name: "New User",
          username: "existinguser",
          email: "new@example.com",
          password: "Str0ngPassw0rd!",
        })
        .expect(409);

      expect(res2.body).toEqual({ error: "User already exists" });
    });

    test("409: handles Mongo duplicate key error (code 11000) with friendly message", async () => {
      await User.create({
        name: "Existing",
        username: "dupeuser",
        email: "dupe@example.com",
        passwordHash: "fake_hash",
      });

      const res = await request(app)
        .post("/api/auth/signup")
        .send({
          name: "Another",
          username: "anotheruser",
          email: "dupe@example.com",
          password: "Str0ngPassw0rd!",
        })
        .expect(409);

      expect(["User already exists", "Email or username already taken"]).toContain(res.body.error);
    });
  });

  // =====================================================================================
  // POST /api/auth/login
  // =====================================================================================
  describe("POST /api/auth/login", () => {
    test("200: logs in with email, sets cookies, returns {success:true}", async () => {
      // Use signup route to ensure passwordHash is correct and consistent with app behavior
      await request(app).post("/api/auth/signup").send({
        name: "Login User",
        username: "loginuser",
        email: "login@example.com",
        password: "Str0ngPassw0rd!",
      });

      const res = await request(app)
        .post("/api/auth/login")
        .send({ emailOrUsername: "login@example.com", password: "Str0ngPassw0rd!" })
        .expect(200);

      expect(res.body).toEqual({ success: true });

      const setCookie = res.headers["set-cookie"];
      expect(setCookie).toBeDefined();
      const cookiesJoined = setCookie.join(" | ");
      expect(cookiesJoined).toMatch(/accessToken=/);
      expect(cookiesJoined).toMatch(/refreshToken=/);
    });

    test("200: logs in with username, sets cookies, returns {success:true}", async () => {
      await request(app).post("/api/auth/signup").send({
        name: "Login User",
        username: "loginuser2",
        email: "login2@example.com",
        password: "Str0ngPassw0rd!",
      });

      const res = await request(app)
        .post("/api/auth/login")
        .send({ emailOrUsername: "loginuser2", password: "Str0ngPassw0rd!" })
        .expect(200);

      expect(res.body).toEqual({ success: true });

      const setCookie = res.headers["set-cookie"];
      expect(setCookie).toBeDefined();
      const cookiesJoined = setCookie.join(" | ");
      expect(cookiesJoined).toMatch(/accessToken=/);
      expect(cookiesJoined).toMatch(/refreshToken=/);
    });

    test("400: rejects missing inputs", async () => {
      const res = await request(app).post("/api/auth/login").send({}).expect(400);
      expect(res.body).toEqual({ error: "All input is required" });
    });

    test("404: rejects invalid credentials (unknown user)", async () => {
      const res = await request(app)
        .post("/api/auth/login")
        .send({ emailOrUsername: "nope@example.com", password: "whatever" })
        .expect(404);

      expect(res.body).toEqual({ error: "Invalid credentials" });
    });

    test("404: rejects invalid credentials (wrong password)", async () => {
      await request(app).post("/api/auth/signup").send({
        name: "Login User",
        username: "loginuser3",
        email: "login3@example.com",
        password: "RightPass123!",
      });

      const res = await request(app)
        .post("/api/auth/login")
        .send({ emailOrUsername: "login3@example.com", password: "WrongPass123!" })
        .expect(404);

      expect(res.body).toEqual({ error: "Invalid credentials" });
    });
  });

  // =====================================================================================
  // POST /api/auth/refresh
  // =====================================================================================
  describe("POST /api/auth/refresh", () => {
    test("200: refreshes tokens when refreshToken cookie is present (rotates cookies)", async () => {
      const agent = request.agent(app);

      // Establish cookies (accessToken + refreshToken) via signup
      await agent.post("/api/auth/signup").send({
        name: "Refresh User",
        username: "refreshuser",
        email: "refresh@example.com",
        password: "Str0ngPassw0rd!",
      });

      const res = await agent.post("/api/auth/refresh").send({}).expect(200);
      expect(res.body).toEqual({ success: true });

      // Rotation should set cookies again
      const setCookie = res.headers["set-cookie"];
      expect(setCookie).toBeDefined();
      const cookiesJoined = setCookie.join(" | ");
      expect(cookiesJoined).toMatch(/accessToken=/);
      expect(cookiesJoined).toMatch(/refreshToken=/);
    });

    test("401: rejects when refreshToken cookie is missing", async () => {
      const res = await request(app).post("/api/auth/refresh").send({}).expect(401);
      expect(res.body).toEqual({ error: "Missing refresh token" });
    });

    test("401: rejects invalid refresh token cookie", async () => {
      const res = await request(app)
        .post("/api/auth/refresh")
        .set("Cookie", ["refreshToken=not_a_real_jwt"])
        .send({})
        .expect(401);

      expect(res.body).toEqual({ error: "Invalid refresh token" });
    });
  });

  // =====================================================================================
  // POST /api/auth/logout
  // =====================================================================================
  describe("POST /api/auth/logout", () => {
    test("200: clears auth cookies and returns {success:true}", async () => {
      const agent = request.agent(app);

      await agent.post("/api/auth/signup").send({
        name: "Logout User",
        username: "logoutuser",
        email: "logout@example.com",
        password: "Str0ngPassw0rd!",
      });

      const res = await agent.post("/api/auth/logout").send({}).expect(200);
      expect(res.body).toEqual({ success: true });

      // Clear cookie responses typically come back as Set-Cookie with an expired date/max-age=0
      const setCookie = res.headers["set-cookie"];
      expect(setCookie).toBeDefined();
      const cookiesJoined = setCookie.join(" | ").toLowerCase();

      expect(cookiesJoined).toMatch(/accesstoken=/);
      expect(cookiesJoined).toMatch(/refreshtoken=/);

      // At least one of these is commonly used to clear cookies; accept either.
      expect(cookiesJoined).toMatch(/max-age=0|expires=/);
    });
  });

  // =====================================================================================
  // GET /api/auth/me (protected)
  // =====================================================================================
  describe("GET /api/auth/me", () => {
    test("200: returns current user info when accessToken cookie is present", async () => {
      const agent = request.agent(app);

      await agent.post("/api/auth/signup").send({
        name: "Me User",
        username: "meuser",
        email: "me@example.com",
        password: "Str0ngPassw0rd!",
      });

      const res = await agent.get("/api/auth/me").expect(200);

      expect(res.body).toEqual(
        expect.objectContaining({
          userId: expect.any(String),
          username: "meuser",
        })
      );
    });

    test("401: rejects when accessToken cookie is missing", async () => {
      const res = await request(app).get("/api/auth/me").expect(401);
      expect(res.body).toEqual({ error: "Unauthenticated" });
    });

    test("401: rejects when accessToken cookie is invalid", async () => {
      const res = await request(app)
        .get("/api/auth/me")
        .set("Cookie", ["accessToken=not_a_real_jwt"])
        .expect(401);

      expect(res.body).toEqual({ error: "Invalid or expired token" });
    });
  });
});