require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();

const PORT = Number(process.env.PORT || 5000);
const COOKIE = process.env.COOKIE_NAME || "skilllink_session";
const SESSION_DAYS = Number(process.env.SESSION_DAYS || 1);

if (!process.env.postgresql://postgres:masterpay@4652@db.qphofcllcuvwtliobgqz.supabase.co:5432/postgres || !process.env.SkL!2026_9xK7mP2vQ8rL5tN4zW6aC1sD) {
  console.error("postgresql://postgres:masterpay@4652@db.qphofcllcuvwtliobgqz.supabase.co:5432/postgres and SkL!2026_9xK7mP2vQ8rL5tN4zW6aC1sDare required.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.NODE_ENV === "production" ||
    process.env.postgresql://postgres:masterpay@4652@db.qphofcllcuvwtliobgqz.supabase.co:5432/postgres.includes("sslmode=require")
      ? { rejectUnauthorized: false }
      : false,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

pool.on("error", (err) => {
  console.error("POSTGRES_POOL_ERROR:", err.message);
});

app.set("trust proxy", 1);

app.use(helmet());

const allowedOrigins = (process.env.https://skill-link-888.vercel.app || "")
  .split(",")
  .map((v) => v.trim())
  .filter(Boolean);

app.use(
  cors({
    origin(origin, callback) {
      if (!origin || allowedOrigins.length === 0) {
        return callback(null, true);
      }

      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(new Error("CORS origin not allowed"));
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

app.use(express.json({ limit: "2mb" }));
app.use(cookieParser());

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: true,
  legacyHeaders: false,
});

app.use("/api", apiLimiter);

const asyncRoute = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

const q = (text, params = []) => pool.query(text, params);

function issueToken(user) {
  return jwt.sign(
    {
      id: user.id,
      role: user.role,
    },
    process.env.SkL!2026_9xK7mP2vQ8rL5tN4zW6aC1sD,
    {
      expiresIn: `${SESSION_DAYS}d`,
    }
  );
}

function setSession(res, token) {
  res.cookie(COOKIE, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: SESSION_DAYS * 24 * 60 * 60 * 1000,
    path: "/",
  });
}

function clearSession(res) {
  res.clearCookie(COOKIE, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
  });
}

function safeUser(row) {
  if (!row) return null;

  const { password_hash, ...user } = row;

  return user;
}

async function audit(
  actorId,
  action,
  targetType = null,
  targetId = null,
  details = {}
) {
  try {
    await q(
      `INSERT INTO audit_logs
       (actor_id, action, target_type, target_id, details)
       VALUES ($1,$2,$3,$4,$5)`,
      [
        actorId || null,
        action,
        targetType,
        targetId || null,
        JSON.stringify(details),
      ]
    );
  } catch (err) {
    console.error("AUDIT_LOG_ERROR:", err.message);
  }
}

async function initDatabase() {
  await q(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      mobile TEXT,
      email TEXT UNIQUE,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'PARTNER'
        CHECK (role IN ('CEO','ADMIN','PARTNER','CLIENT')),
      status TEXT NOT NULL DEFAULT 'ACTIVE'
        CHECK (status IN ('ACTIVE','SUSPENDED','DEACTIVATED')),
      first_login BOOLEAN NOT NULL DEFAULT true,
      referral_code TEXT UNIQUE,
      referred_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS referrals (
      id BIGSERIAL PRIMARY KEY,
      referrer_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      referred_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      status TEXT NOT NULL DEFAULT 'REGISTERED',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(referrer_id,referred_id)
    );

    CREATE TABLE IF NOT EXISTS password_reset_tokens (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      used_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS packages (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      positioning TEXT,
      description TEXT,
      thumbnail TEXT,
      price NUMERIC(12,2) NOT NULL DEFAULT 0,
      partner_commission NUMERIC(12,2) NOT NULL DEFAULT 0,
      company_share NUMERIC(12,2) NOT NULL DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'ACTIVE',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS package_purchases (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      package_id BIGINT NOT NULL REFERENCES packages(id) ON DELETE RESTRICT,
      amount NUMERIC(12,2) NOT NULL,
      payment_screenshot TEXT,
      transaction_id TEXT,
      payment_date TIMESTAMPTZ,
      status TEXT NOT NULL DEFAULT 'PENDING',
      verified_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
      verified_at TIMESTAMPTZ,
      rejection_reason TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS courses (
      id BIGSERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT,
      url TEXT,
      thumbnail TEXT,
      package_id BIGINT REFERENCES packages(id) ON DELETE SET NULL,
      price NUMERIC(12,2) NOT NULL DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'ACTIVE',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS projects (
      id BIGSERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT,
      budget NUMERIC(12,2) NOT NULL DEFAULT 0,
      client_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
      assigned_partner_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
      status TEXT NOT NULL DEFAULT 'OPEN',
      deadline DATE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS earnings (
      id BIGSERIAL PRIMARY KEY,
      partner_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      project_id BIGINT REFERENCES projects(id) ON DELETE SET NULL,
      package_purchase_id BIGINT REFERENCES package_purchases(id) ON DELETE SET NULL,
      gross_amount NUMERIC(12,2) NOT NULL DEFAULT 0,
      company_share NUMERIC(12,2) NOT NULL DEFAULT 0,
      partner_share NUMERIC(12,2) NOT NULL DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'PENDING',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS withdrawal_requests (
      id BIGSERIAL PRIMARY KEY,
      partner_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      amount NUMERIC(12,2) NOT NULL,
      method TEXT,
      account_details TEXT,
      status TEXT NOT NULL DEFAULT 'PENDING',
      note TEXT,
      approved_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
      approved_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id BIGSERIAL PRIMARY KEY,
      actor_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
      action TEXT NOT NULL,
      target_type TEXT,
      target_id BIGINT,
      details JSONB,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
    CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
    CREATE INDEX IF NOT EXISTS idx_referrals_referrer ON referrals(referrer_id);
    CREATE INDEX IF NOT EXISTS idx_purchases_user ON package_purchases(user_id);
    CREATE INDEX IF NOT EXISTS idx_purchases_status ON package_purchases(status);
    CREATE INDEX IF NOT EXISTS idx_projects_client ON projects(client_id);
    CREATE INDEX IF NOT EXISTS idx_projects_partner ON projects(assigned_partner_id);
    CREATE INDEX IF NOT EXISTS idx_earnings_partner ON earnings(partner_id);
    CREATE INDEX IF NOT EXISTS idx_withdrawals_partner ON withdrawal_requests(partner_id);
  `);

  const packageCount = await q(
    "SELECT COUNT(*)::int AS count FROM packages"
  );

  if (packageCount.rows[0].count === 0) {
    await q(`
      INSERT INTO packages
        (name, positioning, description, price, partner_commission, company_share)
      VALUES
        ('Aarambh','Digital Foundation','Digital basics and foundation skills',499,100,399),
        ('Udaan','Creative + Content Skills','Creative and content skills',999,200,799),
        ('Pragati','Marketing + Client Skills','Marketing and client acquisition skills',1999,400,1599),
        ('Brahmastra','Advanced Digital Skills','Advanced digital skills',3999,800,3199),
        ('Shikhar','Leadership + Business','Leadership and business skills',6999,1400,5599)
    `);
  }
}

const auth = asyncRoute(async (req, res, next) => {
  let token = req.cookies[COOKIE];

  if (!token && req.headers.authorization) {
    const [type, value] =
      req.headers.authorization.split(" ");

    if (type === "Bearer") {
      token = value;
    }
  }

  if (!token) {
    return res.status(401).json({
      message: "Authentication required",
    });
  }

  try {
    const payload = jwt.verify(
      token,
      process.env.postgresql:SkL!2026_9xK7mP2vQ8rL5tN4zW6aC1sD
    );

    const r = await q(
      `SELECT
        id,
        name,
        username,
        email,
        mobile,
        role,
        status,
        first_login,
        referral_code,
        referred_by,
        created_at
       FROM users
       WHERE id=$1`,
      [payload.id]
    );

    if (
      !r.rows[0] ||
      r.rows[0].status !== "ACTIVE"
    ) {
      return res.status(401).json({
        message:
          "Session is no longer active",
      });
    }

    req.user = r.rows[0];

    next();
  } catch {
    return res.status(401).json({
      message:
        "Invalid or expired session",
    });
  }
});

const allow = (...roles) =>
  (req, res, next) => {
    if (roles.includes(req.user.role)) {
      return next();
    }

    return res.status(403).json({
      message: "Access denied",
    });
  };

function makeReferralCode() {
  return `SL-${crypto
    .randomBytes(5)
    .toString("hex")
    .toUpperCase()}`;
}

app.get(
  "/api/health",
  asyncRoute(async (req, res) => {
    await q("SELECT 1");

    res.json({
      ok: true,
      service: "SkillLink API",
      time: new Date().toISOString(),
    });
  })
);

/* =========================
   AUTH
========================= */

app.post(
  "/api/auth/register",
  asyncRoute(async (req, res) => {
    const {
      name,
      mobile,
      email,
      username,
      password,
      role = "PARTNER",
      referralCode,
    } = req.body;

    if (!name || !username || !password) {
      return res.status(400).json({
        message:
          "Name, username and password are required",
      });
    }

    if (String(username).trim().length < 3) {
      return res.status(400).json({
        message:
          "Username must be at least 3 characters",
      });
    }

    if (String(password).length < 8) {
      return res.status(400).json({
        message:
          "Password must be at least 8 characters",
      });
    }

    if (!["PARTNER", "CLIENT"].includes(role)) {
      return res.status(400).json({
        message:
          "Public registration cannot create this role",
      });
    }

    const exists = await q(
      `SELECT id
       FROM users
       WHERE lower(username)=lower($1)
       OR ($2::text IS NOT NULL
           AND lower(email)=lower($2))`,
      [
        String(username).trim(),
        email || null,
      ]
    );

    if (exists.rows.length) {
      return res.status(409).json({
        message:
          "Username or email already exists",
      });
    }

    let referredBy = null;

    if (referralCode) {
      const rr = await q(
        `SELECT id
         FROM users
         WHERE referral_code=$1
         AND role='PARTNER'
         AND status='ACTIVE'`,
        [String(referralCode).trim()]
      );

      if (!rr.rows[0]) {
        return res.status(400).json({
          message:
            "Invalid referral ID",
        });
      }

      referredBy = rr.rows[0].id;
    }

    const hash =
      await bcrypt.hash(password, 12);

    const refCode =
      makeReferralCode();

    const r = await q(
      `INSERT INTO users
       (
         name,
         mobile,
         email,
         username,
         password_hash,
         role,
         referral_code,
         referred_by
       )
       VALUES($1,$2,$3,$4,$5,$6,$7,$8)
       RETURNING
         id,
         name,
         username,
         role,
         status,
         first_login,
         referral_code,
         created_at`,
      [
        String(name).trim(),
        mobile || null,
        email || null,
        String(username).trim(),
        hash,
        role,
        refCode,
        referredBy,
      ]
    );

    if (referredBy) {
      await q(
        `INSERT INTO referrals
         (referrer_id,referred_id,status)
         VALUES($1,$2,'REGISTERED')
         ON CONFLICT DO NOTHING`,
        [
          referredBy,
          r.rows[0].id,
        ]
      );
    }

    await audit(
      r.rows[0].id,
      "REGISTER_USER",
      "USER",
      r.rows[0].id,
      { role }
    );

    res.status(201).json({
      user: r.rows[0],
    });
  })
);
app.post(
  "/api/auth/login",
  loginLimiter,
  asyncRoute(async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        message: "Username and password are required",
      });
    }

    const r = await q(
      `SELECT *
       FROM users
       WHERE lower(username)=lower($1)
       LIMIT 1`,
      [String(username).trim()]
    );

    const user = r.rows[0];

    if (!user) {
      return res.status(401).json({
        message: "Invalid username or password",
      });
    }

    if (user.status !== "ACTIVE") {
      return res.status(403).json({
        message: "Your account is not active",
      });
    }

    const valid = await bcrypt.compare(
      String(password),
      user.password_hash
    );

    if (!valid) {
      return res.status(401).json({
        message: "Invalid username or password",
      });
    }

    const token = issueToken(user);

    setSession(res, token);

    await audit(
      user.id,
      "LOGIN",
      "USER",
      user.id,
      {
        role: user.role,
      }
    );

    res.json({
      message: "Login successful",
      user: safeUser(user),
      role: user.role,
    });
  })
);

app.post(
  "/api/auth/logout",
  asyncRoute(async (req, res) => {
    clearSession(res);

    res.json({
      message: "Logout successful",
    });
  })
);

app.get(
  "/api/auth/me",
  auth,
  asyncRoute(async (req, res) => {
    res.json({
      user: safeUser(req.user),
      role: req.user.role,
    });
  })
);

app.post(
  "/api/auth/change-password",
  auth,
  asyncRoute(async (req, res) => {
    const {
      currentPassword,
      newPassword,
    } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        message:
          "Current password and new password are required",
      });
    }

    if (String(newPassword).length < 8) {
      return res.status(400).json({
        message:
          "New password must be at least 8 characters",
      });
    }

    const r = await q(
      `SELECT password_hash
       FROM users
       WHERE id=$1`,
      [req.user.id]
    );

    if (!r.rows[0]) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    const valid = await bcrypt.compare(
      String(currentPassword),
      r.rows[0].password_hash
    );

    if (!valid) {
      return res.status(400).json({
        message: "Current password is incorrect",
      });
    }

    const hash =
      await bcrypt.hash(newPassword, 12);

    await q(
      `UPDATE users
       SET password_hash=$1,
           first_login=false,
           updated_at=now()
       WHERE id=$2`,
      [hash, req.user.id]
    );

    await audit(
      req.user.id,
      "CHANGE_PASSWORD",
      "USER",
      req.user.id
    );

    res.json({
      message:
        "Password changed successfully",
    });
  })
);

app.post(
  "/api/auth/forgot-password",
  loginLimiter,
  asyncRoute(async (req, res) => {
    const {
      username,
      email,
    } = req.body;

    if (!username && !email) {
      return res.status(400).json({
        message:
          "Username or email is required",
      });
    }

    const r = await q(
      `SELECT id, username, email
       FROM users
       WHERE
         ($1::text IS NOT NULL
          AND lower(username)=lower($1))
         OR
         ($2::text IS NOT NULL
          AND lower(email)=lower($2))
       LIMIT 1`,
      [
        username || null,
        email || null,
      ]
    );

    /*
      Security:
      Do not reveal whether the account exists.
      In production, send the reset token
      through a verified email/SMS service.
    */

    if (!r.rows[0]) {
      return res.json({
        message:
          "If the account exists, reset instructions will be sent",
      });
    }

    const rawToken =
      crypto.randomBytes(32).toString("hex");

    const tokenHash =
      crypto
        .createHash("sha256")
        .update(rawToken)
        .digest("hex");

    await q(
      `UPDATE password_reset_tokens
       SET used_at=now()
       WHERE user_id=$1
       AND used_at IS NULL`,
      [r.rows[0].id]
    );

    await q(
      `INSERT INTO password_reset_tokens
       (user_id,token_hash,expires_at)
       VALUES($1,$2,now()+interval '15 minutes')`,
      [
        r.rows[0].id,
        tokenHash,
      ]
    );

    /*
      IMPORTANT:
      This token is returned only for development/testing.
      Do not expose it in production API responses.
    */

    const response = {
      message:
        "If the account exists, reset instructions will be sent",
    };

    if (process.env.NODE_ENV !== "production") {
      response.resetToken = rawToken;
    }

    await audit(
      r.rows[0].id,
      "PASSWORD_RESET_REQUEST",
      "USER",
      r.rows[0].id
    );

    res.json(response);
  })
);

app.post(
  "/api/auth/reset-password",
  asyncRoute(async (req, res) => {
    const {
      token,
      newPassword,
    } = req.body;

    if (!token || !newPassword) {
      return res.status(400).json({
        message:
          "Token and new password are required",
      });
    }

    if (String(newPassword).length < 8) {
      return res.status(400).json({
        message:
          "Password must be at least 8 characters",
      });
    }

    const tokenHash =
      crypto
        .createHash("sha256")
        .update(String(token))
        .digest("hex");

    const r = await q(
      `SELECT id,user_id
       FROM password_reset_tokens
       WHERE token_hash=$1
       AND used_at IS NULL
       AND expires_at > now()
       ORDER BY id DESC
       LIMIT 1`,
      [tokenHash]
    );

    if (!r.rows[0]) {
      return res.status(400).json({
        message:
          "Invalid or expired reset token",
      });
    }

    const hash =
      await bcrypt.hash(
        String(newPassword),
        12
      );

    await q(
      `UPDATE users
       SET password_hash=$1,
           first_login=false,
           updated_at=now()
       WHERE id=$2`,
      [
        hash,
        r.rows[0].user_id,
      ]
    );

    await q(
      `UPDATE password_reset_tokens
       SET used_at=now()
       WHERE id=$1`,
      [r.rows[0].id]
    );

    clearSession(res);

    await audit(
      r.rows[0].user_id,
      "PASSWORD_RESET",
      "USER",
      r.rows[0].user_id
    );

    res.json({
      message:
        "Password reset successfully",
    });
  })
);

/* =========================
   USER MANAGEMENT
========================= */

app.get(
  "/api/users",
  auth,
  allow("CEO", "ADMIN"),
  asyncRoute(async (req, res) => {
    const {
      role,
      status,
      search,
    } = req.query;

    const conditions = [];
    const params = [];

    if (role) {
      params.push(role);
      conditions.push(
        `role=$${params.length}`
      );
    }

    if (status) {
      params.push(status);
      conditions.push(
        `status=$${params.length}`
      );
    }

    if (search) {
      params.push(`%${String(search).trim()}%`);
      conditions.push(
        `(name ILIKE $${params.length}
          OR username ILIKE $${params.length}
          OR email ILIKE $${params.length}
          OR mobile ILIKE $${params.length})`
      );
    }

    const where =
      conditions.length
        ? `WHERE ${conditions.join(" AND ")}`
        : "";

    const r = await q(
      `SELECT
        id,
        name,
        mobile,
        email,
        username,
        role,
        status,
        first_login,
        referral_code,
        referred_by,
        created_at,
        updated_at
       FROM users
       ${where}
       ORDER BY id DESC`,
      params
    );

    res.json({
      users: r.rows,
    });
  })
);

app.post(
  "/api/users",
  auth,
  allow("CEO", "ADMIN"),
  asyncRoute(async (req, res) => {
    const {
      name,
      mobile,
      email,
      username,
      password,
      role,
      referralCode,
    } = req.body;

    if (
      !name ||
      !username ||
      !password ||
      !role
    ) {
      return res.status(400).json({
        message:
          "Name, username, password and role are required",
      });
    }

    if (
      !["CEO", "ADMIN", "PARTNER", "CLIENT"].includes(
        role
      )
    ) {
      return res.status(400).json({
        message: "Invalid role",
      });
    }

    /*
      Only CEO can create CEO accounts.
      ADMIN cannot create another CEO.
    */
    if (
      role === "CEO" &&
      req.user.role !== "CEO"
    ) {
      return res.status(403).json({
        message:
          "Only CEO can create CEO accounts",
      });
    }

    if (String(password).length < 8) {
      return res.status(400).json({
        message:
          "Password must be at least 8 characters",
      });
    }

    const exists = await q(
      `SELECT id
       FROM users
       WHERE lower(username)=lower($1)
       OR ($2::text IS NOT NULL
           AND lower(email)=lower($2))
       LIMIT 1`,
      [
        String(username).trim(),
        email || null,
      ]
    );

    if (exists.rows.length) {
      return res.status(409).json({
        message:
          "Username or email already exists",
      });
    }

    let referredBy = null;

    if (referralCode) {
      const rr = await q(
        `SELECT id
         FROM users
         WHERE referral_code=$1
         AND status='ACTIVE'
         LIMIT 1`,
        [String(referralCode).trim()]
      );

      if (!rr.rows[0]) {
        return res.status(400).json({
          message:
            "Invalid referral code",
        });
      }

      referredBy = rr.rows[0].id;
    }

    const hash =
      await bcrypt.hash(password, 12);

    const referral =
      makeReferralCode();

    const r = await q(
      `INSERT INTO users
       (
         name,
         mobile,
         email,
         username,
         password_hash,
         role,
         referral_code,
         referred_by
       )
       VALUES($1,$2,$3,$4,$5,$6,$7,$8)
       RETURNING
         id,
         name,
         mobile,
         email,
         username,
         role,
         status,
         first_login,
         referral_code,
         referred_by,
         created_at`,
      [
        String(name).trim(),
        mobile || null,
        email || null,
        String(username).trim(),
        hash,
        role,
        referral,
        referredBy,
      ]
    );

    if (referredBy) {
      await q(
        `INSERT INTO referrals
         (referrer_id,referred_id,status)
         VALUES($1,$2,'REGISTERED')
         ON CONFLICT DO NOTHING`,
        [
          referredBy,
          r.rows[0].id,
        ]
      );
    }

    await audit(
      req.user.id,
      "CREATE_USER",
      "USER",
      r.rows[0].id,
      {
        role,
        username,
      }
    );

    res.status(201).json({
      message:
        "User created successfully",
      user: r.rows[0],
    });
  })
);

app.patch(
  "/api/users/:id/status",
  auth,
  allow("CEO", "ADMIN"),
  asyncRoute(async (req, res) => {
    const userId =
      Number(req.params.id);

    const {
      status,
    } = req.body;

    if (
      !["ACTIVE", "SUSPENDED", "DEACTIVATED"].includes(
        status
      )
    ) {
      return res.status(400).json({
        message:
          "Invalid account status",
      });
    }

    const target = await q(
      `SELECT id,role
       FROM users
       WHERE id=$1`,
      [userId]
    );

    if (!target.rows[0]) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    /*
      ADMIN cannot modify CEO accounts.
    */
    if (
      target.rows[0].role === "CEO" &&
      req.user.role !== "CEO"
    ) {
      return res.status(403).json({
        message:
          "Only CEO can modify CEO account",
      });
    }

    if (
      userId === req.user.id &&
      status !== "ACTIVE"
    ) {
      return res.status(400).json({
        message:
          "You cannot deactivate your own account",
      });
    }

    const r = await q(
      `UPDATE users
       SET status=$1,
           updated_at=now()
       WHERE id=$2
       RETURNING
         id,
         name,
         username,
         email,
         role,
         status,
         updated_at`,
      [
        status,
        userId,
      ]
    );

    await audit(
      req.user.id,
      "UPDATE_USER_STATUS",
      "USER",
      userId,
      {
        status,
      }
    );

    res.json({
      message:
        "User status updated",
      user: r.rows[0],
    });
  })
  /* =========================
   PACKAGES
========================= */

app.get(
  "/api/packages",
  asyncRoute(async (req, res) => {
    const r = await q(
      `SELECT
        id,
        name,
        positioning,
        description,
        thumbnail,
        price,
        partner_commission,
        company_share,
        status,
        created_at,
        updated_at
       FROM packages
       WHERE status='ACTIVE'
       ORDER BY id ASC`
    );

    res.json({
      packages: r.rows,
    });
  })
);

app.post(
  "/api/packages",
  auth,
  allow("CEO", "ADMIN"),
  asyncRoute(async (req, res) => {
    const {
      name,
      positioning,
      description,
      thumbnail,
      price,
      partnerCommission,
      companyShare,
      status = "ACTIVE",
    } = req.body;

    if (!name || price === undefined) {
      return res.status(400).json({
        message:
          "Package name and price are required",
      });
    }

    const packagePrice = Number(price);
    const partnerShare = Number(
      partnerCommission || 0
    );

    const company =
      companyShare === undefined
        ? packagePrice - partnerShare
        : Number(companyShare);

    if (
      !Number.isFinite(packagePrice) ||
      packagePrice < 0
    ) {
      return res.status(400).json({
        message: "Invalid package price",
      });
    }

    if (
      !Number.isFinite(partnerShare) ||
      partnerShare < 0
    ) {
      return res.status(400).json({
        message:
          "Invalid partner commission",
      });
    }

    if (
      !Number.isFinite(company) ||
      company < 0
    ) {
      return res.status(400).json({
        message:
          "Invalid company share",
      });
    }

    const r = await q(
      `INSERT INTO packages
       (
         name,
         positioning,
         description,
         thumbnail,
         price,
         partner_commission,
         company_share,
         status
       )
       VALUES($1,$2,$3,$4,$5,$6,$7,$8)
       RETURNING *`,
      [
        String(name).trim(),
        positioning || null,
        description || null,
        thumbnail || null,
        packagePrice,
        partnerShare,
        company,
        status,
      ]
    );

    await audit(
      req.user.id,
      "CREATE_PACKAGE",
      "PACKAGE",
      r.rows[0].id,
      {
        name,
        price: packagePrice,
      }
    );

    res.status(201).json({
      message:
        "Package created successfully",
      package: r.rows[0],
    });
  })
);

app.patch(
  "/api/packages/:id",
  auth,
  allow("CEO", "ADMIN"),
  asyncRoute(async (req, res) => {
    const id =
      Number(req.params.id);

    if (!Number.isInteger(id)) {
      return res.status(400).json({
        message: "Invalid package ID",
      });
    }

    const current = await q(
      `SELECT *
       FROM packages
       WHERE id=$1`,
      [id]
    );

    if (!current.rows[0]) {
      return res.status(404).json({
        message: "Package not found",
      });
    }

    const old =
      current.rows[0];

    const {
      name,
      positioning,
      description,
      thumbnail,
      price,
      partnerCommission,
      companyShare,
      status,
    } = req.body;

    const nextPrice =
      price === undefined
        ? Number(old.price)
        : Number(price);

    const nextPartner =
      partnerCommission === undefined
        ? Number(old.partner_commission)
        : Number(partnerCommission);

    const nextCompany =
      companyShare === undefined
        ? Number(old.company_share)
        : Number(companyShare);

    if (
      !Number.isFinite(nextPrice) ||
      nextPrice < 0
    ) {
      return res.status(400).json({
        message:
          "Invalid package price",
      });
    }

    if (
      !Number.isFinite(nextPartner) ||
      nextPartner < 0
    ) {
      return res.status(400).json({
        message:
          "Invalid partner commission",
      });
    }

    if (
      !Number.isFinite(nextCompany) ||
      nextCompany < 0
    ) {
      return res.status(400).json({
        message:
          "Invalid company share",
      });
    }

    const r = await q(
      `UPDATE packages
       SET
         name=$1,
         positioning=$2,
         description=$3,
         thumbnail=$4,
         price=$5,
         partner_commission=$6,
         company_share=$7,
         status=$8,
         updated_at=now()
       WHERE id=$9
       RETURNING *`,
      [
        name === undefined
          ? old.name
          : String(name).trim(),

        positioning === undefined
          ? old.positioning
          : positioning,

        description === undefined
          ? old.description
          : description,

        thumbnail === undefined
          ? old.thumbnail
          : thumbnail,

        nextPrice,
        nextPartner,
        nextCompany,

        status === undefined
          ? old.status
          : status,

        id,
      ]
    );

    await audit(
      req.user.id,
      "UPDATE_PACKAGE",
      "PACKAGE",
      id,
      {
        name:
          r.rows[0].name,
      }
    );

    res.json({
      message:
        "Package updated successfully",
      package: r.rows[0],
    });
  })
);

/* =========================
   PACKAGE PURCHASES
========================= */

app.post(
  "/api/packages/purchases",
  auth,
  allow("PARTNER", "CLIENT"),
  asyncRoute(async (req, res) => {
    const {
      packageId,
      amount,
      paymentScreenshot,
      transactionId,
      paymentDate,
    } = req.body;

    const id =
      Number(packageId);

    if (!Number.isInteger(id)) {
      return res.status(400).json({
        message:
          "Valid package ID is required",
      });
    }

    const pkg = await q(
      `SELECT *
       FROM packages
       WHERE id=$1
       AND status='ACTIVE'`,
      [id]
    );

    if (!pkg.rows[0]) {
      return res.status(404).json({
        message:
          "Package not found or inactive",
      });
    }

    const packagePrice =
      Number(pkg.rows[0].price);

    const paidAmount =
      amount === undefined
        ? packagePrice
        : Number(amount);

    if (
      !Number.isFinite(paidAmount) ||
      paidAmount <= 0
    ) {
      return res.status(400).json({
        message:
          "Invalid payment amount",
      });
    }

    if (
      Math.abs(
        paidAmount - packagePrice
      ) > 0.01
    ) {
      return res.status(400).json({
        message:
          "Payment amount does not match package price",
      });
    }

    const duplicate =
      transactionId
        ? await q(
            `SELECT id
             FROM package_purchases
             WHERE transaction_id=$1
             LIMIT 1`,
            [String(transactionId).trim()]
          )
        : { rows: [] };

    if (duplicate.rows.length) {
      return res.status(409).json({
        message:
          "This transaction ID has already been submitted",
      });
    }

    const r = await q(
      `INSERT INTO package_purchases
       (
         user_id,
         package_id,
         amount,
         payment_screenshot,
         transaction_id,
         payment_date,
         status
       )
       VALUES($1,$2,$3,$4,$5,$6,'PENDING')
       RETURNING *`,
      [
        req.user.id,
        id,
        paidAmount,
        paymentScreenshot || null,
        transactionId
          ? String(transactionId).trim()
          : null,
        paymentDate || null,
      ]
    );

    await audit(
      req.user.id,
      "CREATE_PACKAGE_PURCHASE",
      "PACKAGE_PURCHASE",
      r.rows[0].id,
      {
        packageId: id,
        amount: paidAmount,
      }
    );

    res.status(201).json({
      message:
        "Payment submitted for verification",
      purchase: r.rows[0],
    });
  })
);

app.get(
  "/api/packages/purchases",
  auth,
  asyncRoute(async (req, res) => {
    const {
      status,
      userId,
    } = req.query;

    const conditions = [];
    const params = [];

    if (
      req.user.role === "PARTNER" ||
      req.user.role === "CLIENT"
    ) {
      params.push(req.user.id);

      conditions.push(
        `pp.user_id=$${params.length}`
      );
    } else if (userId) {
      params.push(Number(userId));

      conditions.push(
        `pp.user_id=$${params.length}`
      );
    }

    if (status) {
      params.push(status);

      conditions.push(
        `pp.status=$${params.length}`
      );
    }

    const where =
      conditions.length
        ? `WHERE ${conditions.join(" AND ")}`
        : "";

    const r = await q(
      `SELECT
        pp.*,
        p.name AS package_name,
        p.positioning,
        u.name AS user_name,
        u.username AS username
       FROM package_purchases pp
       JOIN packages p
         ON p.id=pp.package_id
       JOIN users u
         ON u.id=pp.user_id
       ${where}
       ORDER BY pp.id DESC`,
      params
    );

    res.json({
      purchases: r.rows,
    });
  })
);

app.patch(
  "/api/packages/purchases/:id",
  auth,
  allow("CEO", "ADMIN"),
  asyncRoute(async (req, res) => {
    const purchaseId =
      Number(req.params.id);

    const {
      status,
      rejectionReason,
    } = req.body;

    const allowedStatuses = [
      "PENDING",
      "VERIFIED",
      "REJECTED",
      "RESUBMISSION_REQUIRED",
    ];

    if (
      !allowedStatuses.includes(status)
    ) {
      return res.status(400).json({
        message:
          "Invalid payment status",
      });
    }

    if (!Number.isInteger(purchaseId)) {
      return res.status(400).json({
        message:
          "Invalid purchase ID",
      });
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const purchaseResult =
        await client.query(
          `SELECT
             pp.*,
             p.name AS package_name,
             p.partner_commission,
             p.company_share,
             u.role AS user_role
           FROM package_purchases pp
           JOIN packages p
             ON p.id=pp.package_id
           JOIN users u
             ON u.id=pp.user_id
           WHERE pp.id=$1
           FOR UPDATE`,
          [purchaseId]
        );

      if (!purchaseResult.rows[0]) {
        await client.query("ROLLBACK");

        return res.status(404).json({
          message:
            "Purchase not found",
        });
      }

      const purchase =
        purchaseResult.rows[0];

      /*
        Prevent duplicate earnings when
        a VERIFIED purchase is edited again.
      */

      if (
        status === "VERIFIED" &&
        purchase.status !== "VERIFIED"
      ) {
        await client.query(
          `INSERT INTO earnings
           (
             partner_id,
             package_purchase_id,
             gross_amount,
             company_share,
             partner_share,
             status
           )
           SELECT
             $1,
             $2,
             $3,
             $4,
             $5,
             'AVAILABLE'
           WHERE NOT EXISTS (
             SELECT 1
             FROM earnings
             WHERE package_purchase_id=$2
           )`,
          [
            purchase.user_id,
            purchaseId,
            Number(purchase.amount),
            Number(
              purchase.company_share
            ),
            Number(
              purchase.partner_commission
            ),
          ]
        );
      }

      const updated =
        await client.query(
          `UPDATE package_purchases
           SET
             status=$1,
             verified_by=$2,
             verified_at=
               CASE
                 WHEN $1='VERIFIED'
                   THEN now()
                 ELSE verified_at
               END,
             rejection_reason=
               CASE
                 WHEN $1 IN ('REJECTED','RESUBMISSION_REQUIRED')
                   THEN $3
                 ELSE NULL
               END,
             updated_at=now()
           WHERE id=$4
           RETURNING *`,
          [
            status,
            req.user.id,
            rejectionReason || null,
            purchaseId,
          ]
        );

      await client.query("COMMIT");

      await audit(
        req.user.id,
        "UPDATE_PACKAGE_PURCHASE",
        "PACKAGE_PURCHASE",
        purchaseId,
        {
          status,
        }
      );

      res.json({
        message:
          "Payment status updated",
        purchase:
          updated.rows[0],
      });
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    } finally {
      client.release();
    }
  })
);

/* =========================
   COURSES
========================= */

app.get(
  "/api/courses",
  asyncRoute(async (req, res) => {
    const {
      packageId,
    } = req.query;

    const params = [];
    let where = "WHERE c.status='ACTIVE'";

    if (packageId) {
      params.push(Number(packageId));

      where +=
        ` AND c.package_id=$${params.length}`;
    }

    const r = await q(
      `SELECT
        c.*,
        p.name AS package_name
       FROM courses c
       LEFT JOIN packages p
         ON p.id=c.package_id
       ${where}
       ORDER BY c.id ASC`,
      params
    );

    res.json({
      courses: r.rows,
    });
  })
);

app.post(
  "/api/courses",
  auth,
  allow("CEO", "ADMIN"),
  asyncRoute(async (req, res) => {
    const {
      title,
      description,
      url,
      thumbnail,
      packageId,
      price = 0,
      status = "ACTIVE",
    } = req.body;

    if (!title) {
      return res.status(400).json({
        message:
          "Course title is required",
      });
    }

    const coursePrice =
      Number(price);

    if (
      !Number.isFinite(coursePrice) ||
      coursePrice < 0
    ) {
      return res.status(400).json({
        message:
          "Invalid course price",
      });
    }

    const r = await q(
      `INSERT INTO courses
       (
         title,
         description,
         url,
         thumbnail,
         package_id,
         price,
         status
       )
       VALUES($1,$2,$3,$4,$5,$6,$7)
       RETURNING *`,
      [
        String(title).trim(),
        description || null,
        url || null,
        thumbnail || null,
        packageId
          ? Number(packageId)
          : null,
        coursePrice,
        status,
      ]
    );

    await audit(
      req.user.id,
      "CREATE_COURSE",
      "COURSE",
      r.rows[0].id,
      {
        title,
      }
    );

    res.status(201).json({
      message:
        "Course created successfully",
      course: r.rows[0],
    });
  })
);

app.patch(
  "/api/courses/:id",
  auth,
  allow("CEO", "ADMIN"),
  asyncRoute(async (req, res) => {
    const id =
      Number(req.params.id);

    if (!Number.isInteger(id)) {
      return res.status(400).json({
        message:
          "Invalid course ID",
      });
    }

    const current = await q(
      `SELECT *
       FROM courses
       WHERE id=$1`,
      [id]
    );

    if (!current.rows[0]) {
      return res.status(404).json({
        message:
          "Course not found",
      });
    }

    const old =
      current.rows[0];

    const {
      title,
      description,
      url,
      thumbnail,
      packageId,
      price,
      status,
    } = req.body;

    const nextPrice =
      price === undefined
        ? Number(old.price)
        : Number(price);

    if (
      !Number.isFinite(nextPrice) ||
      nextPrice < 0
    ) {
      return res.status(400).json({
        message:
          "Invalid course price",
      });
    }

    const r = await q(
      `UPDATE courses
       SET
         title=$1,
         description=$2,
         url=$3,
         thumbnail=$4,
         package_id=$5,
         price=$6,
         status=$7,
         updated_at=now()
       WHERE id=$8
       RETURNING *`,
      [
        title === undefined
          ? old.title
          : String(title).trim(),

        description === undefined
          ? old.description
          : description,

        url === undefined
          ? old.url
          : url,

        thumbnail === undefined
          ? old.thumbnail
          : thumbnail,

        packageId === undefined
          ? old.package_id
          : packageId
          ? Number(packageId)
          : null,

        nextPrice,

        status === undefined
          ? old.status
          : status,

        id,
      ]
    );

    await audit(
      req.user.id,
      "UPDATE_COURSE",
      "COURSE",
      id
    );

    res.json({
      message:
        "Course updated successfully",
      course: r.rows[0],
    });
  })
);
);
/* =========================
   REFERRALS
========================= */

app.get(
  "/api/referrals",
  auth,
  allow("CEO", "ADMIN", "PARTNER"),
  asyncRoute(async (req, res) => {
    const targetUserId =
      req.user.role === "PARTNER"
        ? req.user.id
        : req.query.userId
        ? Number(req.query.userId)
        : null;

    let where = "";
    const params = [];

    if (targetUserId) {
      params.push(targetUserId);
      where = `WHERE r.referrer_id=$1`;
    }

    const result = await q(
      `SELECT
        r.id,
        r.referrer_id,
        r.referred_id,
        r.status,
        r.created_at,
        u.name AS referred_name,
        u.username AS referred_username,
        u.email AS referred_email,
        u.role AS referred_role,
        u.status AS referred_user_status
       FROM referrals r
       JOIN users u
         ON u.id=r.referred_id
       ${where}
       ORDER BY r.id DESC`,
      params
    );

    res.json({
      referrals: result.rows,
    });
  })
);

/* =========================
   PROJECTS
========================= */

app.post(
  "/api/projects",
  auth,
  allow("CEO", "ADMIN", "CLIENT"),
  asyncRoute(async (req, res) => {
    const {
      title,
      description,
      budget = 0,
      deadline,
      assignedPartnerId,
    } = req.body;

    if (!title) {
      return res.status(400).json({
        message:
          "Project title is required",
      });
    }

    const projectBudget =
      Number(budget);

    if (
      !Number.isFinite(projectBudget) ||
      projectBudget < 0
    ) {
      return res.status(400).json({
        message:
          "Invalid project budget",
      });
    }

    let clientId = null;

    if (req.user.role === "CLIENT") {
      clientId = req.user.id;
    } else if (req.body.clientId) {
      clientId = Number(
        req.body.clientId
      );
    }

    if (
      clientId !== null &&
      !Number.isInteger(clientId)
    ) {
      return res.status(400).json({
        message:
          "Invalid client ID",
      });
    }

    let partnerId = null;

    if (assignedPartnerId) {
      partnerId = Number(
        assignedPartnerId
      );

      if (!Number.isInteger(partnerId)) {
        return res.status(400).json({
          message:
            "Invalid partner ID",
        });
      }

      const partner = await q(
        `SELECT id
         FROM users
         WHERE id=$1
         AND role='PARTNER'
         AND status='ACTIVE'`,
        [partnerId]
      );

      if (!partner.rows[0]) {
        return res.status(400).json({
          message:
            "Assigned partner not found",
        });
      }
    }

    const result = await q(
      `INSERT INTO projects
       (
         title,
         description,
         budget,
         client_id,
         assigned_partner_id,
         status,
         deadline
       )
       VALUES($1,$2,$3,$4,$5,$6,$7)
       RETURNING *`,
      [
        String(title).trim(),
        description || null,
        projectBudget,
        clientId,
        partnerId,
        partnerId
          ? "ASSIGNED"
          : "OPEN",
        deadline || null,
      ]
    );

    await audit(
      req.user.id,
      "CREATE_PROJECT",
      "PROJECT",
      result.rows[0].id,
      {
        title,
        budget: projectBudget,
      }
    );

    res.status(201).json({
      message:
        "Project created successfully",
      project: result.rows[0],
    });
  })
);

app.get(
  "/api/projects",
  auth,
  asyncRoute(async (req, res) => {
    const {
      status,
      clientId,
      partnerId,
    } = req.query;

    const conditions = [];
    const params = [];

    if (req.user.role === "CLIENT") {
      params.push(req.user.id);

      conditions.push(
        `p.client_id=$${params.length}`
      );
    }

    if (req.user.role === "PARTNER") {
      params.push(req.user.id);

      conditions.push(
        `p.assigned_partner_id=$${params.length}`
      );
    }

    if (
      req.user.role === "CEO" ||
      req.user.role === "ADMIN"
    ) {
      if (clientId) {
        params.push(Number(clientId));

        conditions.push(
          `p.client_id=$${params.length}`
        );
      }

      if (partnerId) {
        params.push(Number(partnerId));

        conditions.push(
          `p.assigned_partner_id=$${params.length}`
        );
      }
    }

    if (status) {
      params.push(status);

      conditions.push(
        `p.status=$${params.length}`
      );
    }

    const where =
      conditions.length
        ? `WHERE ${conditions.join(" AND ")}`
        : "";

    const result = await q(
      `SELECT
        p.*,
        c.name AS client_name,
        c.username AS client_username,
        partner.name AS partner_name,
        partner.username AS partner_username
       FROM projects p
       LEFT JOIN users c
         ON c.id=p.client_id
       LEFT JOIN users partner
         ON partner.id=p.assigned_partner_id
       ${where}
       ORDER BY p.id DESC`,
      params
    );

    res.json({
      projects: result.rows,
    });
  })
);

app.patch(
  "/api/projects/:id",
  auth,
  allow("CEO", "ADMIN", "CLIENT", "PARTNER"),
  asyncRoute(async (req, res) => {
    const projectId =
      Number(req.params.id);

    if (!Number.isInteger(projectId)) {
      return res.status(400).json({
        message:
          "Invalid project ID",
      });
    }

    const current = await q(
      `SELECT *
       FROM projects
       WHERE id=$1`,
      [projectId]
    );

    if (!current.rows[0]) {
      return res.status(404).json({
        message:
          "Project not found",
      });
    }

    const project =
      current.rows[0];

    /*
      CLIENT can modify only
      their own project.
    */
    if (
      req.user.role === "CLIENT" &&
      Number(project.client_id) !==
        Number(req.user.id)
    ) {
      return res.status(403).json({
        message:
          "You can modify only your own projects",
      });
    }

    /*
      PARTNER can update only
      the status of an assigned project.
    */
    if (
      req.user.role === "PARTNER" &&
      Number(project.assigned_partner_id) !==
        Number(req.user.id)
    ) {
      return res.status(403).json({
        message:
          "You can modify only assigned projects",
      });
    }

    const {
      title,
      description,
      budget,
      deadline,
      status,
      assignedPartnerId,
    } = req.body;

    let nextTitle =
      project.title;

    let nextDescription =
      project.description;

    let nextBudget =
      Number(project.budget);

    let nextDeadline =
      project.deadline;

    let nextStatus =
      project.status;

    let nextPartner =
      project.assigned_partner_id;

    if (
      req.user.role === "CEO" ||
      req.user.role === "ADMIN"
    ) {
      if (title !== undefined) {
        nextTitle =
          String(title).trim();
      }

      if (description !== undefined) {
        nextDescription =
          description;
      }

      if (budget !== undefined) {
        nextBudget =
          Number(budget);
      }

      if (deadline !== undefined) {
        nextDeadline =
          deadline || null;
      }

      if (status !== undefined) {
        nextStatus =
          status;
      }

      if (
        assignedPartnerId !== undefined
      ) {
        nextPartner =
          assignedPartnerId
            ? Number(assignedPartnerId)
            : null;
      }
    } else if (
      req.user.role === "CLIENT"
    ) {
      if (title !== undefined) {
        nextTitle =
          String(title).trim();
      }

      if (description !== undefined) {
        nextDescription =
          description;
      }

      if (budget !== undefined) {
        nextBudget =
          Number(budget);
      }

      if (deadline !== undefined) {
        nextDeadline =
          deadline || null;
      }
    } else if (
      req.user.role === "PARTNER"
    ) {
      if (status !== undefined) {
        nextStatus =
          status;
      }
    }

    if (
      !Number.isFinite(nextBudget) ||
      nextBudget < 0
    ) {
      return res.status(400).json({
        message:
          "Invalid project budget",
      });
    }

    if (
      !nextTitle ||
      nextTitle.length < 2
    ) {
      return res.status(400).json({
        message:
          "Project title is required",
      });
    }

    if (
      nextPartner !== null &&
      nextPartner !== undefined
    ) {
      const partner = await q(
        `SELECT id
         FROM users
         WHERE id=$1
         AND role='PARTNER'
         AND status='ACTIVE'`,
        [nextPartner]
      );

      if (!partner.rows[0]) {
        return res.status(400).json({
          message:
            "Assigned partner not found",
        });
      }
    }

    const result = await q(
      `UPDATE projects
       SET
         title=$1,
         description=$2,
         budget=$3,
         assigned_partner_id=$4,
         status=$5,
         deadline=$6,
         updated_at=now()
       WHERE id=$7
       RETURNING *`,
      [
        nextTitle,
        nextDescription,
        nextBudget,
        nextPartner || null,
        nextStatus,
        nextDeadline,
        projectId,
      ]
    );

    await audit(
      req.user.id,
      "UPDATE_PROJECT",
      "PROJECT",
      projectId,
      {
        status: nextStatus,
      }
    );

    res.json({
      message:
        "Project updated successfully",
      project:
        result.rows[0],
    });
  })
);

/* =========================
   EARNINGS
========================= */

app.get(
  "/api/earnings",
  auth,
  allow("CEO", "ADMIN", "PARTNER"),
  asyncRoute(async (req, res) => {
    const conditions = [];
    const params = [];

    if (req.user.role === "PARTNER") {
      params.push(req.user.id);

      conditions.push(
        `e.partner_id=$${params.length}`
      );
    } else if (req.query.partnerId) {
      params.push(
        Number(req.query.partnerId)
      );

      conditions.push(
        `e.partner_id=$${params.length}`
      );
    }

    if (req.query.status) {
      params.push(req.query.status);

      conditions.push(
        `e.status=$${params.length}`
      );
    }

    const where =
      conditions.length
        ? `WHERE ${conditions.join(" AND ")}`
        : "";

    const result = await q(
      `SELECT
        e.*,
        u.name AS partner_name,
        u.username AS partner_username,
        p.title AS project_title,
        pkg.name AS package_name
       FROM earnings e
       JOIN users u
         ON u.id=e.partner_id
       LEFT JOIN projects p
         ON p.id=e.project_id
       LEFT JOIN package_purchases pp
         ON pp.id=e.package_purchase_id
       LEFT JOIN packages pkg
         ON pkg.id=pp.package_id
       ${where}
       ORDER BY e.id DESC`,
      params
    );

    res.json({
      earnings: result.rows,
    });
  })
);

app.get(
  "/api/earnings/summary",
  auth,
  allow("CEO", "ADMIN", "PARTNER"),
  asyncRoute(async (req, res) => {
    const partnerId =
      req.user.role === "PARTNER"
        ? req.user.id
        : req.query.partnerId
        ? Number(req.query.partnerId)
        : null;

    const params = [];
    let where = "";

    if (partnerId) {
      params.push(partnerId);

      where =
        `WHERE partner_id=$1`;
    }

    const result = await q(
      `SELECT
        COALESCE(
          SUM(partner_share),
          0
        )::numeric AS total_earned,

        COALESCE(
          SUM(
            CASE
              WHEN status='PENDING'
              THEN partner_share
              ELSE 0
            END
          ),
          0
        )::numeric AS pending_earnings,

        COALESCE(
          SUM(
            CASE
              WHEN status='AVAILABLE'
              THEN partner_share
              ELSE 0
            END
          ),
          0
        )::numeric AS available_earnings,

        COALESCE(
          SUM(
            CASE
              WHEN status='WITHDRAWN'
              THEN partner_share
              ELSE 0
            END
          ),
          0
        )::numeric AS withdrawn_earnings
       FROM earnings
       ${where}`,
      params
    );

    res.json({
      summary:
        result.rows[0],
    });
  })
);

/* =========================
   WITHDRAWALS
========================= */

app.post(
  "/api/withdrawals",
  auth,
  allow("PARTNER"),
  asyncRoute(async (req, res) => {
    const {
      amount,
      method,
      accountDetails,
    } = req.body;

    const withdrawalAmount =
      Number(amount);

    if (
      !Number.isFinite(
        withdrawalAmount
      ) ||
      withdrawalAmount <= 0
    ) {
      return res.status(400).json({
        message:
          "Invalid withdrawal amount",
      });
    }

    if (withdrawalAmount < 100) {
      return res.status(400).json({
        message:
          "Minimum withdrawal amount is ₹100",
      });
    }

    const summary =
      await q(
        `SELECT
          COALESCE(
            SUM(
              CASE
                WHEN status='AVAILABLE'
                THEN partner_share
                ELSE 0
              END
            ),
            0
          )::numeric AS available
         FROM earnings
         WHERE partner_id=$1`,
        [req.user.id]
      );

    const available =
      Number(
        summary.rows[0].available
      );

    const pendingResult =
      await q(
        `SELECT
          COALESCE(
            SUM(amount),
            0
          )::numeric AS pending
         FROM withdrawal_requests
         WHERE partner_id=$1
         AND status='PENDING'`,
        [req.user.id]
      );

    const pending =
      Number(
        pendingResult.rows[0].pending
      );

    const withdrawable =
      available - pending;

    if (
      withdrawalAmount >
      withdrawable
    ) {
      return res.status(400).json({
        message:
          "Insufficient available earnings",
      });
    }

    const result = await q(
      `INSERT INTO withdrawal_requests
       (
         partner_id,
         amount,
         method,
         account_details,
         status
       )
       VALUES($1,$2,$3,$4,'PENDING')
       RETURNING *`,
      [
        req.user.id,
        withdrawalAmount,
        method || null,
        accountDetails || null,
      ]
    );

    await audit(
      req.user.id,
      "CREATE_WITHDRAWAL",
      "WITHDRAWAL",
      result.rows[0].id,
      {
        amount:
          withdrawalAmount,
      }
    );

    res.status(201).json({
      message:
        "Withdrawal request submitted",
      withdrawal:
        result.rows[0],
    });
  })
);

app.get(
  "/api/withdrawals",
  auth,
  allow("CEO", "ADMIN", "PARTNER"),
  asyncRoute(async (req, res) => {
    const conditions = [];
    const params = [];

    if (req.user.role === "PARTNER") {
      params.push(req.user.id);

      conditions.push(
        `w.partner_id=$${params.length}`
      );
    } else if (req.query.partnerId) {
      params.push(
        Number(req.query.partnerId)
      );

      conditions.push(
        `w.partner_id=$${params.length}`
      );
    }

    if (req.query.status) {
      params.push(req.query.status);

      conditions.push(
        `w.status=$${params.length}`
      );
    }

    const where =
      conditions.length
        ? `WHERE ${conditions.join(" AND ")}`
        : "";

    const result = await q(
      `SELECT
        w.*,
        u.name AS partner_name,
        u.username AS partner_username,
        a.name AS approved_by_name
       FROM withdrawal_requests w
       JOIN users u
         ON u.id=w.partner_id
       LEFT JOIN users a
         ON a.id=w.approved_by
       ${where}
       ORDER BY w.id DESC`,
      params
    );

    res.json({
      withdrawals:
        result.rows,
    });
  })
);
/* =========================
   WITHDRAWAL MANAGEMENT
========================= */

app.patch(
  "/api/withdrawals/:id",
  auth,
  allow("CEO", "ADMIN"),
  asyncRoute(async (req, res) => {
    const withdrawalId =
      Number(req.params.id);

    const {
      status,
      note,
    } = req.body;

    const allowedStatuses = [
      "PENDING",
      "APPROVED",
      "REJECTED",
      "PAID",
    ];

    if (!Number.isInteger(withdrawalId)) {
      return res.status(400).json({
        message:
          "Invalid withdrawal ID",
      });
    }

    if (
      !allowedStatuses.includes(status)
    ) {
      return res.status(400).json({
        message:
          "Invalid withdrawal status",
      });
    }

    const current = await q(
      `SELECT *
       FROM withdrawal_requests
       WHERE id=$1`,
      [withdrawalId]
    );

    if (!current.rows[0]) {
      return res.status(404).json({
        message:
          "Withdrawal request not found",
      });
    }

    const withdrawal =
      current.rows[0];

    /*
      Do not allow an already PAID request
      to be changed again.
    */
    if (
      withdrawal.status === "PAID" &&
      status !== "PAID"
    ) {
      return res.status(400).json({
        message:
          "A paid withdrawal cannot be changed",
      });
    }

    const result = await q(
      `UPDATE withdrawal_requests
       SET
         status=$1,
         note=$2,
         approved_by=$3,
         approved_at=
           CASE
             WHEN $1 IN ('APPROVED','REJECTED','PAID')
               THEN now()
             ELSE approved_at
           END,
         updated_at=now()
       WHERE id=$4
       RETURNING *`,
      [
        status,
        note || null,
        req.user.id,
        withdrawalId,
      ]
    );

    /*
      When withdrawal is marked PAID,
      move matching AVAILABLE earnings
      into WITHDRAWN status.

      This is done only for the amount
      requested by this withdrawal.
    */
    if (
      status === "PAID" &&
      withdrawal.status !== "PAID"
    ) {
      const client =
        await pool.connect();

      try {
        await client.query(
          "BEGIN"
        );

        let remaining =
          Number(
            withdrawal.amount
          );

        const earnings =
          await client.query(
            `SELECT
               id,
               partner_share
             FROM earnings
             WHERE partner_id=$1
             AND status='AVAILABLE'
             ORDER BY id ASC
             FOR UPDATE`,
            [withdrawal.partner_id]
          );

        for (
          const earning
          of earnings.rows
        ) {
          if (remaining <= 0) {
            break;
          }

          const earningAmount =
            Number(
              earning.partner_share
            );

          if (
            earningAmount <=
            remaining
          ) {
            await client.query(
              `UPDATE earnings
               SET
                 status='WITHDRAWN',
                 updated_at=now()
               WHERE id=$1`,
              [earning.id]
            );

            remaining -=
              earningAmount;
          }
        }

        if (remaining > 0.01) {
          await client.query(
            "ROLLBACK"
          );

          return res.status(400).json({
            message:
              "Available earnings are insufficient to mark this withdrawal as paid",
          });
        }

        await client.query(
          "COMMIT"
        );
      } catch (err) {
        await client.query(
          "ROLLBACK"
        );
        throw err;
      } finally {
        client.release();
      }
    }

    await audit(
      req.user.id,
      "UPDATE_WITHDRAWAL",
      "WITHDRAWAL",
      withdrawalId,
      {
        status,
      }
    );

    res.json({
      message:
        "Withdrawal status updated",
      withdrawal:
        result.rows[0],
    });
  })
);

/* =========================
   DASHBOARD
========================= */

app.get(
  "/api/dashboard",
  auth,
  asyncRoute(async (req, res) => {
    const role =
      req.user.role;

    if (role === "PARTNER") {
      const [
        referrals,
        earnings,
        withdrawals,
        projects,
        purchases,
      ] = await Promise.all([
        q(
          `SELECT COUNT(*)::int AS count
           FROM referrals
           WHERE referrer_id=$1`,
          [req.user.id]
        ),

        q(
          `SELECT
             COALESCE(
               SUM(partner_share),
               0
             )::numeric AS total_earned,

             COALESCE(
               SUM(
                 CASE
                   WHEN status='AVAILABLE'
                   THEN partner_share
                   ELSE 0
                 END
               ),
               0
             )::numeric AS available_earnings,

             COALESCE(
               SUM(
                 CASE
                   WHEN status='PENDING'
                   THEN partner_share
                   ELSE 0
                 END
               ),
               0
             )::numeric AS pending_earnings,

             COALESCE(
               SUM(
                 CASE
                   WHEN status='WITHDRAWN'
                   THEN partner_share
                   ELSE 0
                 END
               ),
               0
             )::numeric AS withdrawn_earnings
           FROM earnings
           WHERE partner_id=$1`,
          [req.user.id]
        ),

        q(
          `SELECT
             COUNT(*)::int AS total,
             COUNT(*) FILTER (
               WHERE status='PENDING'
             )::int AS pending,
             COUNT(*) FILTER (
               WHERE status='APPROVED'
             )::int AS approved,
             COUNT(*) FILTER (
               WHERE status='PAID'
             )::int AS paid
           FROM withdrawal_requests
           WHERE partner_id=$1`,
          [req.user.id]
        ),

        q(
          `SELECT COUNT(*)::int AS count
           FROM projects
           WHERE assigned_partner_id=$1`,
          [req.user.id]
        ),

        q(
          `SELECT COUNT(*)::int AS count
           FROM package_purchases
           WHERE user_id=$1`,
          [req.user.id]
        ),
      ]);

      return res.json({
        role,
        dashboard: {
          referrals:
            referrals.rows[0],
          earnings:
            earnings.rows[0],
          withdrawals:
            withdrawals.rows[0],
          projects:
            projects.rows[0],
          purchases:
            purchases.rows[0],
        },
      });
    }

    if (role === "CLIENT") {
      const [
        projects,
        purchases,
      ] = await Promise.all([
        q(
          `SELECT
             COUNT(*)::int AS total,
             COUNT(*) FILTER (
               WHERE status='OPEN'
             )::int AS open,
             COUNT(*) FILTER (
               WHERE status='ASSIGNED'
             )::int AS assigned,
             COUNT(*) FILTER (
               WHERE status='COMPLETED'
             )::int AS completed
           FROM projects
           WHERE client_id=$1`,
          [req.user.id]
        ),

        q(
          `SELECT
             COUNT(*)::int AS total,
             COUNT(*) FILTER (
               WHERE status='PENDING'
             )::int AS pending,
             COUNT(*) FILTER (
               WHERE status='VERIFIED'
             )::int AS verified,
             COUNT(*) FILTER (
               WHERE status='REJECTED'
             )::int AS rejected
           FROM package_purchases
           WHERE user_id=$1`,
          [req.user.id]
        ),
      ]);

      return res.json({
        role,
        dashboard: {
          projects:
            projects.rows[0],
          purchases:
            purchases.rows[0],
        },
      });
    }

    /*
      CEO and ADMIN dashboard
    */
    const [
      users,
      partners,
      clients,
      projects,
      purchases,
      withdrawals,
      earnings,
    ] = await Promise.all([
      q(
        `SELECT COUNT(*)::int AS count
         FROM users`
      ),

      q(
        `SELECT COUNT(*)::int AS count
         FROM users
         WHERE role='PARTNER'
         AND status='ACTIVE'`
      ),

      q(
        `SELECT COUNT(*)::int AS count
         FROM users
         WHERE role='CLIENT'
         AND status='ACTIVE'`
      ),

      q(
        `SELECT
           COUNT(*)::int AS total,
           COUNT(*) FILTER (
             WHERE status='OPEN'
           )::int AS open,
           COUNT(*) FILTER (
             WHERE status='ASSIGNED'
           )::int AS assigned,
           COUNT(*) FILTER (
             WHERE status='COMPLETED'
           )::int AS completed
         FROM projects`
      ),

      q(
        `SELECT
           COUNT(*)::int AS total,
           COUNT(*) FILTER (
             WHERE status='PENDING'
           )::int AS pending,
           COUNT(*) FILTER (
             WHERE status='VERIFIED'
           )::int AS verified,
           COALESCE(
             SUM(
               CASE
                 WHEN status='VERIFIED'
                 THEN amount
                 ELSE 0
               END
             ),
             0
           )::numeric AS verified_revenue
         FROM package_purchases`
      ),

      q(
        `SELECT
           COUNT(*)::int AS total,
           COUNT(*) FILTER (
             WHERE status='PENDING'
           )::int AS pending,
           COUNT(*) FILTER (
             WHERE status='APPROVED'
           )::int AS approved,
           COUNT(*) FILTER (
             WHERE status='PAID'
           )::int AS paid,
           COALESCE(
             SUM(
               CASE
                 WHEN status='PENDING'
                 THEN amount
                 ELSE 0
               END
             ),
             0
           )::numeric AS pending_amount
         FROM withdrawal_requests`
      ),

      q(
        `SELECT
           COALESCE(
             SUM(gross_amount),
             0
           )::numeric AS gross_amount,

           COALESCE(
             SUM(company_share),
             0
           )::numeric AS company_share,

           COALESCE(
             SUM(partner_share),
             0
           )::numeric AS partner_share
         FROM earnings`
      ),
    ]);

    res.json({
      role,
      dashboard: {
        users:
          users.rows[0],
        partners:
          partners.rows[0],
        clients:
          clients.rows[0],
        projects:
          projects.rows[0],
        purchases:
          purchases.rows[0],
        withdrawals:
          withdrawals.rows[0],
        earnings:
          earnings.rows[0],
      },
    });
  })
);

/* =========================
   AUDIT LOGS
========================= */

app.get(
  "/api/audit-logs",
  auth,
  allow("CEO", "ADMIN"),
  asyncRoute(async (req, res) => {
    const {
      limit = 100,
    } = req.query;

    const safeLimit = Math.min(
      Math.max(
        Number(limit) || 100,
        1
      ),
      500
    );

    const result = await q(
      `SELECT
        a.id,
        a.actor_id,
        a.action,
        a.target_type,
        a.target_id,
        a.details,
        a.created_at,
        u.name AS actor_name,
        u.username AS actor_username
       FROM audit_logs a
       LEFT JOIN users u
         ON u.id=a.actor_id
       ORDER BY a.id DESC
       LIMIT $1`,
      [safeLimit]
    );

    res.json({
      logs:
        result.rows,
    });
  })
);

/* =========================
   ROOT
========================= */

app.get(
  "/",
  (req, res) => {
    res.json({
      service: "SkillLink API",
      status: "running",
      version: "1.0.0",
    });
  }
);
/* =========================
   ERROR HANDLING
========================= */

app.use(
  (req, res) => {
    res.status(404).json({
      message:
        "API route not found",
      path: req.originalUrl,
    });
  }
);

app.use(
  (err, req, res, next) => {
    console.error(
      "SERVER_ERROR:",
      err
    );

    if (
      err &&
      err.message ===
        "CORS origin not allowed"
    ) {
      return res.status(403).json({
        message:
          "CORS origin not allowed",
      });
    }

    if (
      err &&
      err.code === "23505"
    ) {
      return res.status(409).json({
        message:
          "Duplicate value already exists",
      });
    }

    if (
      err &&
      err.code === "23503"
    ) {
      return res.status(400).json({
        message:
          "Referenced record does not exist",
      });
    }

    if (
      err &&
      err.code === "22P02"
    ) {
      return res.status(400).json({
        message:
          "Invalid data format",
      });
    }

    res.status(500).json({
      message:
        "Internal server error",
      ...(process.env.NODE_ENV !==
        "production"
        ? {
            error:
              err.message,
          }
        : {}),
    });
  }
);

/* =========================
   SERVER START
========================= */

async function start() {
  try {
    console.log(
      "Connecting to PostgreSQL..."
    );

    await q("SELECT 1");

    console.log(
      "PostgreSQL connected successfully"
    );

    console.log(
      "Initializing database..."
    );

    await initDatabase();

    console.log(
      "Database initialization completed"
    );

    app.listen(
      PORT,
      "0.0.0.0",
      () => {
        console.log(
          `SkillLink API running on port ${PORT}`
        );
      }
    );
  } catch (err) {
    console.error(
      "SERVER_START_ERROR:",
      err
    );

    process.exit(1);
  }
}

start();