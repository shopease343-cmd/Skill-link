
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS roles (
  id BIGSERIAL PRIMARY KEY,
  code VARCHAR(20) UNIQUE NOT NULL CHECK (code IN ('CEO','ADMIN','PARTNER','CLIENT')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO roles(code) VALUES ('CEO'),('ADMIN'),('PARTNER'),('CLIENT') ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS permissions (
  id BIGSERIAL PRIMARY KEY,
  code VARCHAR(80) UNIQUE NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO permissions(code) VALUES
('manage_partners'),('manage_clients'),('manage_projects'),('manage_courses'),('manage_leads'),
('manage_referrals'),('manage_levels'),('view_payments'),('manage_notifications'),
('view_reports'),('view_audit_logs'),('manage_masterclasses'),('manage_packages'),
('manage_qr'),('approve_withdrawals'),('approve_refunds'),('manage_users')
ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  role_id BIGINT NOT NULL REFERENCES roles(id),
  username VARCHAR(80) UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  email VARCHAR(255) UNIQUE,
  mobile VARCHAR(30),
  status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','SUSPENDED','DEACTIVATED','PENDING')),
  force_password_change BOOLEAN NOT NULL DEFAULT false,
  referral_code VARCHAR(40) UNIQUE,
  referred_by_user_id BIGINT REFERENCES users(id),
  last_login_at TIMESTAMPTZ,
  failed_login_count INT NOT NULL DEFAULT 0,
  locked_until TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_users_role_status ON users(role_id,status);
CREATE INDEX IF NOT EXISTS idx_users_referrer ON users(referred_by_user_id);

CREATE TABLE IF NOT EXISTS profiles (
  user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  full_name VARCHAR(160),
  profile_picture_url TEXT,
  upi_id VARCHAR(160),
  address TEXT,
  language VARCHAR(20) DEFAULT 'en',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS user_permissions (
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  permission_id BIGINT NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
  granted_by BIGINT REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY(user_id,permission_id)
);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT UNIQUE NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS packages (
  id BIGSERIAL PRIMARY KEY,
  name VARCHAR(100) UNIQUE NOT NULL,
  description TEXT,
  positioning VARCHAR(200),
  price NUMERIC(12,2) NOT NULL CHECK(price>=0),
  partner_commission NUMERIC(12,2) NOT NULL DEFAULT 0 CHECK(partner_commission>=0),
  company_share NUMERIC(12,2) NOT NULL DEFAULT 0 CHECK(company_share>=0),
  thumbnail_url TEXT,
  status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE','INACTIVE','DRAFT')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO packages(name,positioning,price,partner_commission,company_share) VALUES
('Aarambh','Digital Foundation',499,100,399),
('Udaan','Creative + Content Skills',999,250,749),
('Pragati','Marketing + Client Skills',1999,550,1449),
('Brahmastra','Advanced Digital Skills',3999,1100,2899),
('Shikhar','Leadership + Business',6999,3000,3999)
ON CONFLICT(name) DO NOTHING;

CREATE TABLE IF NOT EXISTS package_purchases (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id),
  package_id BIGINT NOT NULL REFERENCES packages(id),
  amount NUMERIC(12,2) NOT NULL,
  payment_status VARCHAR(30) NOT NULL DEFAULT 'PENDING' CHECK(payment_status IN ('PENDING','VERIFIED','REJECTED','RESUBMISSION_REQUIRED')),
  purchased_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  verified_at TIMESTAMPTZ,
  verified_by BIGINT REFERENCES users(id),
  refund_eligible_at TIMESTAMPTZ,
  UNIQUE(user_id,package_id,purchased_at)
);

CREATE TABLE IF NOT EXISTS payment_proofs (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id),
  package_purchase_id BIGINT REFERENCES package_purchases(id),
  masterclass_id BIGINT,
  service_type VARCHAR(30) NOT NULL CHECK(service_type IN ('PACKAGE','MASTERCLASS','PROJECT','OTHER')),
  amount NUMERIC(12,2) NOT NULL CHECK(amount>=0),
  transaction_id VARCHAR(160),
  proof_url TEXT,
  paid_on DATE,
  status VARCHAR(30) NOT NULL DEFAULT 'PENDING' CHECK(status IN ('PENDING','VERIFIED','REJECTED','RESUBMISSION_REQUIRED')),
  verified_by BIGINT REFERENCES users(id),
  verified_at TIMESTAMPTZ,
  remarks TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_payment_proofs_status ON payment_proofs(status);

CREATE TABLE IF NOT EXISTS courses (
  id BIGSERIAL PRIMARY KEY,
  package_id BIGINT REFERENCES packages(id),
  title VARCHAR(200) NOT NULL,
  description TEXT,
  thumbnail_url TEXT,
  category VARCHAR(120),
  status VARCHAR(20) NOT NULL DEFAULT 'DRAFT' CHECK(status IN ('DRAFT','PREVIEW','PUBLISHED','ARCHIVED')),
  certificate_eligible BOOLEAN NOT NULL DEFAULT false,
  created_by BIGINT REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS course_modules (
  id BIGSERIAL PRIMARY KEY,
  course_id BIGINT NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
  title VARCHAR(200) NOT NULL,
  position INT NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS course_chapters (
  id BIGSERIAL PRIMARY KEY,
  module_id BIGINT NOT NULL REFERENCES course_modules(id) ON DELETE CASCADE,
  title VARCHAR(200) NOT NULL,
  position INT NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS course_content (
  id BIGSERIAL PRIMARY KEY,
  chapter_id BIGINT NOT NULL REFERENCES course_chapters(id) ON DELETE CASCADE,
  content_type VARCHAR(20) NOT NULL CHECK(content_type IN ('VIDEO','NOTE','PDF','EMBED')),
  title VARCHAR(200),
  video_url TEXT,
  file_url TEXT,
  position INT NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS course_progress (
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  course_id BIGINT NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
  progress_percent NUMERIC(5,2) NOT NULL DEFAULT 0 CHECK(progress_percent BETWEEN 0 AND 100),
  completed_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY(user_id,course_id)
);
CREATE TABLE IF NOT EXISTS quizzes (
  id BIGSERIAL PRIMARY KEY,
  course_id BIGINT NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
  title VARCHAR(200) NOT NULL,
  passing_score NUMERIC(5,2) NOT NULL DEFAULT 70
);
CREATE TABLE IF NOT EXISTS quiz_questions (
  id BIGSERIAL PRIMARY KEY,
  quiz_id BIGINT NOT NULL REFERENCES quizzes(id) ON DELETE CASCADE,
  question TEXT NOT NULL,
  options JSONB NOT NULL,
  correct_option INT NOT NULL
);
CREATE TABLE IF NOT EXISTS quiz_attempts (
  id BIGSERIAL PRIMARY KEY,
  quiz_id BIGINT NOT NULL REFERENCES quizzes(id),
  user_id BIGINT NOT NULL REFERENCES users(id),
  score NUMERIC(5,2) NOT NULL,
  passed BOOLEAN NOT NULL,
  attempted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS skill_mastery (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id),
  skill_name VARCHAR(160) NOT NULL,
  mastery_percent NUMERIC(5,2) NOT NULL DEFAULT 0 CHECK(mastery_percent BETWEEN 0 AND 100),
  achieved_at TIMESTAMPTZ,
  UNIQUE(user_id,skill_name)
);

CREATE TABLE IF NOT EXISTS levels (
  id BIGSERIAL PRIMARY KEY,
  level_no INT UNIQUE NOT NULL CHECK(level_no BETWEEN 1 AND 9),
  name VARCHAR(100) NOT NULL,
  score_required INT NOT NULL,
  referral_required INT NOT NULL DEFAULT 0,
  skill_mastery_required INT NOT NULL DEFAULT 0,
  reward_description TEXT,
  enabled BOOLEAN NOT NULL DEFAULT true
);
INSERT INTO levels(level_no,name,score_required,referral_required,skill_mastery_required,reward_description) VALUES
(1,'Starter Partner',100,0,1,'CEO-configured reward'),
(2,'Rising Partner',250,15,1,'CEO-configured reward'),
(3,'Skilled Partner',400,20,1,'CEO-configured reward'),
(4,'Advanced Partner',500,25,2,'CEO-configured reward'),
(5,'Pro Partner',650,30,2,'CEO-configured reward'),
(6,'Expert Partner',800,40,3,'CEO-configured reward'),
(7,'Elite Partner',1000,50,4,'CEO-configured reward'),
(8,'Master Partner',1500,60,5,'CEO-configured reward'),
(9,'Legend Partner',2000,75,6,'CEO-configured reward')
ON CONFLICT(level_no) DO NOTHING;

CREATE TABLE IF NOT EXISTS rewards (
  id BIGSERIAL PRIMARY KEY,
  level_id BIGINT REFERENCES levels(id),
  title VARCHAR(200) NOT NULL,
  description TEXT,
  eligibility TEXT,
  status VARCHAR(20) DEFAULT 'ACTIVE',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS reward_claims (
  id BIGSERIAL PRIMARY KEY,
  reward_id BIGINT NOT NULL REFERENCES rewards(id),
  user_id BIGINT NOT NULL REFERENCES users(id),
  status VARCHAR(20) DEFAULT 'ELIGIBLE',
  claimed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS scores (
  user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  total_score INT NOT NULL DEFAULT 0,
  current_level INT NOT NULL DEFAULT 1,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS score_transactions (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id),
  source_type VARCHAR(40) NOT NULL,
  source_id BIGINT,
  points INT NOT NULL,
  description TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(user_id,source_type,source_id)
);

CREATE TABLE IF NOT EXISTS referrals (
  id BIGSERIAL PRIMARY KEY,
  referrer_id BIGINT NOT NULL REFERENCES users(id),
  referred_user_id BIGINT NOT NULL UNIQUE REFERENCES users(id),
  code VARCHAR(40) NOT NULL,
  registration_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  activation_at TIMESTAMPTZ,
  valid BOOLEAN NOT NULL DEFAULT false,
  status VARCHAR(30) NOT NULL DEFAULT 'REGISTERED'
);
CREATE TABLE IF NOT EXISTS referral_events (
  id BIGSERIAL PRIMARY KEY,
  referral_id BIGINT NOT NULL REFERENCES referrals(id) ON DELETE CASCADE,
  event_type VARCHAR(50) NOT NULL,
  metadata JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS masterclasses (
  id BIGSERIAL PRIMARY KEY,
  title VARCHAR(200) NOT NULL,
  description TEXT,
  price NUMERIC(12,2) NOT NULL DEFAULT 99,
  scheduled_at TIMESTAMPTZ,
  meeting_url TEXT,
  status VARCHAR(20) NOT NULL DEFAULT 'DRAFT' CHECK(status IN ('DRAFT','PUBLISHED','UNPUBLISHED','CANCELLED')),
  created_by BIGINT REFERENCES users(id),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS masterclass_registrations (
  id BIGSERIAL PRIMARY KEY,
  masterclass_id BIGINT NOT NULL REFERENCES masterclasses(id),
  user_id BIGINT NOT NULL REFERENCES users(id),
  payment_proof_id BIGINT REFERENCES payment_proofs(id),
  access_unlocked BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(masterclass_id,user_id)
);

CREATE TABLE IF NOT EXISTS projects (
  id BIGSERIAL PRIMARY KEY,
  title VARCHAR(220) NOT NULL,
  description TEXT,
  required_skills JSONB,
  budget NUMERIC(12,2) NOT NULL DEFAULT 0,
  deadline DATE,
  priority VARCHAR(20) DEFAULT 'NORMAL',
  client_id BIGINT REFERENCES users(id),
  created_by BIGINT REFERENCES users(id),
  status VARCHAR(30) NOT NULL DEFAULT 'NEW',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_projects_status ON projects(status);
CREATE TABLE IF NOT EXISTS project_assignments (
  id BIGSERIAL PRIMARY KEY,
  project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  partner_id BIGINT NOT NULL REFERENCES users(id),
  assigned_by BIGINT REFERENCES users(id),
  status VARCHAR(30) NOT NULL DEFAULT 'ASSIGNED',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(project_id,partner_id)
);
CREATE TABLE IF NOT EXISTS project_revisions (
  id BIGSERIAL PRIMARY KEY,
  project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  requested_by BIGINT REFERENCES users(id),
  reason TEXT,
  revision_no INT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS project_disputes (
  id BIGSERIAL PRIMARY KEY,
  project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  opened_by BIGINT REFERENCES users(id),
  reason VARCHAR(200),
  description TEXT,
  status VARCHAR(30) NOT NULL DEFAULT 'OPEN',
  ceo_decision TEXT,
  resolved_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS project_messages (
  id BIGSERIAL PRIMARY KEY,
  project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  sender_id BIGINT NOT NULL REFERENCES users(id),
  body TEXT NOT NULL,
  attachment_url TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_project_messages_project ON project_messages(project_id,created_at);
CREATE TABLE IF NOT EXISTS project_earnings (
  id BIGSERIAL PRIMARY KEY,
  project_id BIGINT NOT NULL REFERENCES projects(id),
  partner_id BIGINT NOT NULL REFERENCES users(id),
  gross_amount NUMERIC(12,2) NOT NULL,
  company_share NUMERIC(12,2) NOT NULL,
  partner_share NUMERIC(12,2) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(project_id,partner_id)
);

CREATE TABLE IF NOT EXISTS leads (
  id BIGSERIAL PRIMARY KEY,
  name VARCHAR(160) NOT NULL,
  mobile VARCHAR(30),
  source VARCHAR(100),
  assigned_partner_id BIGINT REFERENCES users(id),
  assigned_admin_id BIGINT REFERENCES users(id),
  status VARCHAR(30) NOT NULL DEFAULT 'NEW',
  notes TEXT,
  conversion_amount NUMERIC(12,2),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS earnings_ledger (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id),
  source_type VARCHAR(30) NOT NULL CHECK(source_type IN ('PROJECT','PACKAGE_REFERRAL','OTHER')),
  source_id BIGINT NOT NULL,
  gross_amount NUMERIC(12,2) NOT NULL CHECK(gross_amount>=0),
  company_share NUMERIC(12,2) NOT NULL DEFAULT 0,
  partner_share NUMERIC(12,2) NOT NULL DEFAULT 0,
  pending_amount NUMERIC(12,2) NOT NULL DEFAULT 0,
  available_amount NUMERIC(12,2) NOT NULL DEFAULT 0,
  withdrawn_amount NUMERIC(12,2) NOT NULL DEFAULT 0,
  status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(user_id,source_type,source_id)
);
CREATE INDEX IF NOT EXISTS idx_ledger_user_status ON earnings_ledger(user_id,status);

CREATE TABLE IF NOT EXISTS withdrawals (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id),
  amount NUMERIC(12,2) NOT NULL CHECK(amount>=100),
  payment_method VARCHAR(40) NOT NULL,
  payment_details TEXT NOT NULL,
  request_date TIMESTAMPTZ NOT NULL DEFAULT now(),
  status VARCHAR(20) NOT NULL DEFAULT 'PENDING' CHECK(status IN ('PENDING','UNDER_REVIEW','APPROVED','REJECTED','PAID','FAILED')),
  payment_reference VARCHAR(160),
  remarks TEXT,
  reviewed_by BIGINT REFERENCES users(id),
  reviewed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_withdrawals_status ON withdrawals(status);

CREATE TABLE IF NOT EXISTS refund_requests (
  id BIGSERIAL PRIMARY KEY,
  package_purchase_id BIGINT NOT NULL REFERENCES package_purchases(id),
  user_id BIGINT NOT NULL REFERENCES users(id),
  period_ends_at TIMESTAMPTZ NOT NULL,
  skilllink_earnings NUMERIC(12,2) NOT NULL DEFAULT 0,
  eligible BOOLEAN NOT NULL DEFAULT false,
  status VARCHAR(30) NOT NULL DEFAULT 'PENDING',
  ceo_decision TEXT,
  decided_by BIGINT REFERENCES users(id),
  decided_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS company_settings (
  id BIGSERIAL PRIMARY KEY,
  setting_key VARCHAR(100) UNIQUE NOT NULL,
  setting_value JSONB NOT NULL,
  updated_by BIGINT REFERENCES users(id),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS notifications (
  id BIGSERIAL PRIMARY KEY,
  title VARCHAR(200) NOT NULL,
  description TEXT NOT NULL,
  created_by BIGINT REFERENCES users(id),
  target_role VARCHAR(20),
  target_user_id BIGINT REFERENCES users(id),
  page_link TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS notification_reads (
  notification_id BIGINT NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  read_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY(notification_id,user_id)
);

CREATE TABLE IF NOT EXISTS certificates (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id),
  course_id BIGINT NOT NULL REFERENCES courses(id),
  certificate_id VARCHAR(80) UNIQUE NOT NULL,
  verification_code VARCHAR(100) UNIQUE NOT NULL,
  issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  details JSONB
);
CREATE TABLE IF NOT EXISTS certificate_verifications (
  id BIGSERIAL PRIMARY KEY,
  certificate_id BIGINT NOT NULL REFERENCES certificates(id),
  verified_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  ip_hash VARCHAR(128)
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGSERIAL PRIMARY KEY,
  actor_user_id BIGINT REFERENCES users(id),
  action VARCHAR(100) NOT NULL,
  target_type VARCHAR(80),
  target_id BIGINT,
  before_value JSONB,
  after_value JSONB,
  ip_hash VARCHAR(128),
  user_agent TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at DESC);

CREATE OR REPLACE FUNCTION block_audit_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'Audit logs are immutable';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_no_update ON audit_logs;
DROP TRIGGER IF EXISTS audit_no_delete ON audit_logs;
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_logs FOR EACH ROW EXECUTE FUNCTION block_audit_mutation();
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_logs FOR EACH ROW EXECUTE FUNCTION block_audit_mutation();

CREATE TABLE IF NOT EXISTS uploads (
  id BIGSERIAL PRIMARY KEY,
  owner_user_id BIGINT REFERENCES users(id),
  purpose VARCHAR(40) NOT NULL,
  original_name TEXT NOT NULL,
  stored_name TEXT NOT NULL,
  mime_type VARCHAR(120) NOT NULL,
  size_bytes BIGINT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sessions (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash VARCHAR(128) UNIQUE NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN NEW.updated_at=now(); RETURN NEW; END;
$$ LANGUAGE plpgsql;

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['users','profiles','packages','courses','masterclasses','projects','leads'] LOOP
    EXECUTE format('DROP TRIGGER IF EXISTS %I_updated_at ON %I',t,t);
    EXECUTE format('CREATE TRIGGER %I_updated_at BEFORE UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION set_updated_at()',t,t);
  END LOOP;
END $$;
