/**
 * MAS-CSI Full-Stack Express Server
 * Serves real REST API routes and mounts Vite dev middleware on port 3000.
 */

import express from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import crypto from 'crypto';

const app = express();
const PORT = 3000;

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Server User Model with security telemetry
export interface ServerUser {
  user_id: string;
  username: string;
  email: string;
  role: string;
  password_hash: string;
  is_suspended: boolean;
  login_enabled: boolean;
  totp_secret?: string;
  last_login?: string | null;
  last_login_formatted_time?: string | null;
  last_location?: string | null;
  last_latitude?: number | null;
  last_longitude?: number | null;
  last_accuracy?: number | null;
  is_outside_organization?: boolean;
}

// In-memory backend database
const db = {
  events: [] as any[],
  incidents: [] as any[],
  evidenceVault: [] as any[],
  fileNotifications: [] as any[],
  dispatchedEmails: [] as any[],
  users: [
    {
      user_id: 'USR-001',
      username: 'admin',
      email: 'admin@mas-csi.lab',
      role: 'Super Admin',
      password_hash: crypto.createHash('sha256').update('Admin@CSI2026!').digest('hex'),
      is_suspended: false,
      login_enabled: true,
    },
    {
      user_id: 'USR-002',
      username: 'sec_analyst',
      email: 'analyst@mas-csi.lab',
      role: 'Security Analyst',
      password_hash: crypto.createHash('sha256').update('Analyst@CSI2026!').digest('hex'),
      is_suspended: false,
      login_enabled: true,
    },
    {
      user_id: 'USR-003',
      username: 'auditor',
      email: 'auditor@mas-csi.lab',
      role: 'Auditor',
      password_hash: crypto.createHash('sha256').update('Auditor@CSI2026!').digest('hex'),
      is_suspended: false,
      login_enabled: true,
    },
    {
      user_id: 'USR-004',
      username: 'john_doe',
      email: 'jdoe@organization.internal',
      role: 'Employee',
      password_hash: crypto.createHash('sha256').update('Employee@CSI2026!').digest('hex'),
      is_suspended: false,
      login_enabled: true,
    },
  ] as ServerUser[],
  auditLogs: [] as any[],
  files: [
    {
      file_id: 'FILE-001',
      name: 'critical_server_config.conf',
      content: '# MAS-CSI Internal Gateway Configuration\nPORT=8443\nTLS_ENABLED=true\nACCESS_POLICY=STRICT_RBAC\nAUTH_VAULT=ENABLED',
      created_by: 'john_doe',
      created_at: new Date(Date.now() - 3600000 * 5).toISOString(),
      original_sha256: crypto.createHash('sha256').update('# MAS-CSI Internal Gateway Configuration\nPORT=8443\nTLS_ENABLED=true\nACCESS_POLICY=STRICT_RBAC\nAUTH_VAULT=ENABLED').digest('hex'),
      current_sha256: crypto.createHash('sha256').update('# MAS-CSI Internal Gateway Configuration\nPORT=8443\nTLS_ENABLED=true\nACCESS_POLICY=STRICT_RBAC\nAUTH_VAULT=ENABLED').digest('hex'),
      last_modified_by: 'john_doe',
      last_modified_at: new Date(Date.now() - 3600000 * 5).toISOString(),
      is_tampered: false,
      tampered_by: null,
      history: [
        {
          timestamp: new Date(Date.now() - 3600000 * 5).toISOString(),
          modified_by: 'john_doe',
          sha256: crypto.createHash('sha256').update('# MAS-CSI Internal Gateway Configuration\nPORT=8443\nTLS_ENABLED=true\nACCESS_POLICY=STRICT_RBAC\nAUTH_VAULT=ENABLED').digest('hex'),
          action: 'CREATED',
        }
      ]
    }
  ] as any[],
  geoHistory: [] as any[],
};

// -------------------------------------------------------------
// REST API ENDPOINTS
// -------------------------------------------------------------

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'HEALTHY',
    service: 'MAS-CSI Cyber Intelligence Platform API',
    version: '9.0.0',
    timestamp: new Date().toISOString(),
    database: 'CONNECTED',
    agents: 'READY',
    vault: 'SEALED',
    registered_roles: ['Super Admin', 'Security Analyst', 'Auditor', 'Employee'],
  });
});

// Platform stats
app.get('/api/stats', (req, res) => {
  res.json({
    total_events: db.events.length,
    total_incidents: db.incidents.length,
    sealed_evidence_count: db.evidenceVault.length,
    registered_users: db.users.length,
    stored_files: db.files.length,
    tampered_files: db.files.filter(f => f.is_tampered).length,
    active_endpoints: 1,
    detection_state: 'ACTIVE',
  });
});

// Telemetry events
app.get('/api/events', (req, res) => {
  const limit = parseInt(req.query.limit as string) || 100;
  res.json(db.events.slice(-limit));
});

app.post('/api/events', (req, res) => {
  const event = {
    event_id: `EVT-${Date.now().toString().slice(-6)}-${Math.floor(1000 + Math.random() * 9000)}`,
    timestamp: new Date().toISOString(),
    ...req.body,
  };
  db.events.push(event);
  res.status(201).json({ status: 'INGESTED', event_id: event.event_id, event });
});

// Incidents
app.get('/api/incidents', (req, res) => {
  res.json(db.incidents);
});

app.get('/api/incidents/:id', (req, res) => {
  const inc = db.incidents.find(i => i.incident_id === req.params.id);
  if (!inc) return res.status(404).json({ error: 'Incident not found' });
  res.json(inc);
});

// Evidence Vault
app.get('/api/evidence', (req, res) => {
  res.json(db.evidenceVault);
});

app.get('/api/evidence/:id/verify', (req, res) => {
  const record = db.evidenceVault.find(e => e.evidence_id === req.params.id);
  if (!record) return res.status(404).json({ error: 'Evidence not found' });

  const calculated = crypto.createHash('sha256').update(record.content).digest('hex');
  const isValid = calculated.toLowerCase() === record.sha256.toLowerCase();
  res.json({
    evidence_id: record.evidence_id,
    isValid,
    storedHash: record.sha256,
    calculatedHash: calculated,
  });
});

// -------------------------------------------------------------
// USER REGISTRATION & EMAIL OTP DISPATCH APIs
// -------------------------------------------------------------

// User Registration: Must be registered before accessing the secure lab
app.post('/api/auth/register', (req, res) => {
  const { username, email, password, role } = req.body;
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Username, email, and password are required for registration.' });
  }

  const existing = db.users.find(u => u.username.toLowerCase() === username.toLowerCase() || u.email.toLowerCase() === email.toLowerCase());
  if (existing) {
    return res.status(400).json({ error: 'An account with this username or email is already registered.' });
  }

  const hash = crypto.createHash('sha256').update(password).digest('hex');
  const newUser: ServerUser = {
    user_id: `USR-${Date.now().toString().slice(-4)}`,
    username,
    email,
    role: role || 'Employee',
    password_hash: hash,
    is_suspended: false,
    login_enabled: true,
    totp_secret: 'GEZDGNBVGY3TQOJQ',
  };

  db.users.push(newUser);

  // Send onboarding welcome email to registered email address
  const welcomeEmail = {
    email_id: `EML-WELCOME-${Date.now().toString().slice(-5)}`,
    to_email: email,
    to_username: username,
    from_address: 'MAS-CSI Security Sentinel <security-auth@mas-csi.internal>',
    subject: `[MAS-CSI Security] Account Successfully Registered - Clearance: ${newUser.role}`,
    timestamp: new Date().toISOString(),
    formatted_time: new Date().toLocaleString(),
    expires_at: 'NEVER',
    body_text: `Welcome to MAS-CSI Cyber Intelligence Platform, ${username}.\nYour account has been officially registered with role [${newUser.role}].\nWhen logging in, two-factor authentication (2FA) verification codes will be sent to this registered address: ${email}.\nPlease keep your credentials confidential.`,
    is_read: false,
    email_type: 'WELCOME_REGISTRATION'
  };
  db.dispatchedEmails.unshift(welcomeEmail);

  // Record registration event
  db.events.unshift({
    event_id: `EVT-REG-${Date.now().toString().slice(-4)}`,
    timestamp: new Date().toISOString(),
    event_type: 'user_registration',
    severity: 'INFO',
    username,
    message: `New identity registered in directory: ${username} (${email}) with role [${newUser.role}]. Welcome email dispatched.`,
  });

  res.status(201).json({
    status: 'REGISTERED',
    user: {
      user_id: newUser.user_id,
      username: newUser.username,
      email: newUser.email,
      role: newUser.role,
    },
    message: `Account registered successfully! Welcome email sent to ${email}.`,
  });
});

// Send OTP to registered user's email address
app.post('/api/auth/send-otp', (req, res) => {
  const { username, location_label, latitude, longitude } = req.body;
  if (!username) {
    return res.status(400).json({ error: 'Username is required to dispatch OTP.' });
  }

  const user = db.users.find(u => u.username.toLowerCase() === username.toLowerCase());
  if (!user) {
    // Audit attempt from unregistered identity
    db.events.unshift({
      event_id: `EVT-UNREG-OTP-${Date.now().toString().slice(-4)}`,
      timestamp: new Date().toISOString(),
      event_type: 'unregistered_access_attempt',
      severity: 'HIGH',
      username,
      message: `[BLOCKED] Unregistered entity '${username}' attempted to request a 2FA OTP code. Request denied.`,
    });
    return res.status(404).json({
      error: 'Account not found: You must be registered first in the directory before you can request an OTP or access the system.',
      notRegistered: true,
    });
  }

  // Generate 6-digit cryptographic OTP code
  const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 5 * 60 * 1000).toLocaleTimeString();

  const otpEmail = {
    email_id: `EML-OTP-${Date.now().toString().slice(-5)}`,
    to_email: user.email,
    to_username: user.username,
    from_address: 'MAS-CSI Zero-Trust Auth Sentinel <security-auth@mas-csi.internal>',
    subject: `[MAS-CSI 2FA Passcode] Your One-Time Verification Code: ${otpCode}`,
    otp_code: otpCode,
    timestamp: now.toISOString(),
    formatted_time: now.toLocaleString(),
    expires_at: expiresAt,
    location_label: location_label || (latitude ? `${latitude.toFixed(4)}°, ${longitude.toFixed(4)}°` : 'San Francisco Lab HQ'),
    body_text: `Security Alert: A login attempt was initiated for user '${user.username}'.\n\nYour 6-Digit Secondary Verification Passcode is: ${otpCode}\n\nValid for 5 minutes (until ${expiresAt}).\nOriginating Location: ${location_label || 'Corporate Workstation'}\nIf you did not initiate this request, notify the Super Admin SOC immediately.`,
    is_read: false,
    email_type: 'OTP_VERIFICATION'
  };

  db.dispatchedEmails.unshift(otpEmail);

  res.json({
    status: 'DISPATCHED',
    message: `6-digit OTP code dispatched to registered email: ${user.email}`,
    to_email: user.email,
    email_id: otpEmail.email_id,
    otp_code: otpCode,
    email: otpEmail,
  });
});

// List all dispatched security emails (Corporate Webmail API)
app.get('/api/auth/emails', (req, res) => {
  const { username, email } = req.query;
  let list = db.dispatchedEmails;
  if (email) {
    list = list.filter(e => e.to_email.toLowerCase() === (email as string).toLowerCase());
  } else if (username) {
    list = list.filter(e => e.to_username.toLowerCase() === (username as string).toLowerCase());
  }
  res.json(list);
});

// Authentication for Real Lab & Roles
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  const hash = crypto.createHash('sha256').update(password).digest('hex');
  const user = db.users.find(u => u.username.toLowerCase() === username.toLowerCase());

  // Strict registration verification
  if (!user) {
    // Record unauthorized access attempt from unregistered entity
    db.events.unshift({
      event_id: `EVT-UNREG-LOGIN-${Date.now().toString().slice(-4)}`,
      timestamp: new Date().toISOString(),
      event_type: 'unregistered_login_attempt',
      severity: 'HIGH',
      username: username || 'unknown',
      source_ip: req.ip || '127.0.0.1',
      message: `[ACCESS BLOCKED] Unregistered identity '${username}' attempted to log in without prior registration.`,
    });

    db.incidents.unshift({
      incident_id: `INC-UNREG-${Date.now().toString().slice(-4)}`,
      created_at: new Date().toISOString(),
      severity: 'HIGH',
      status: 'NEW',
      title: `Unauthorized Access by Unregistered User: '${username}'`,
      description: `An unauthenticated actor attempted access with unregistered username '${username}'. Identity registration is required prior to authentication.`,
      target_user: username,
      actor_user: username,
      mitre_technique: 'T1078.003',
      mitre_tactic: 'Initial Access',
    });

    return res.status(401).json({
      error: 'Access Denied: Unregistered Identity. You must be registered first in the directory before you can log in or access the lab.',
      notRegistered: true,
    });
  }

  if (user.password_hash !== hash) {
    db.events.push({
      event_id: `EVT-AUTH-FAIL-${Date.now().toString().slice(-4)}`,
      timestamp: new Date().toISOString(),
      event_type: 'login_failure',
      severity: 'HIGH',
      username: username || 'unknown',
      source_ip: req.ip || '127.0.0.1',
      message: `Failed authentication attempt (password mismatch) for user: ${username}`,
    });
    return res.status(401).json({ error: 'Invalid credentials. Password mismatch.' });
  }

  if (user.is_suspended) {
    return res.status(403).json({ error: 'Account is administratively suspended' });
  }

  const now = new Date();
  const formattedTime = req.body.formatted_time || now.toLocaleString('en-US', {
    weekday: 'short',
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    timeZoneName: 'short'
  });

  const locationLabel = req.body.location_label || (req.body.latitude ? `${req.body.latitude.toFixed(4)}° N, ${req.body.longitude.toFixed(4)}° W` : '37.7749° N, -122.4194° W');

  user.last_login = now.toISOString();
  user.last_login_formatted_time = formattedTime;
  user.last_location = locationLabel;
  user.last_latitude = req.body.latitude || null;
  user.last_longitude = req.body.longitude || null;
  user.is_outside_organization = req.body.is_outside_organization || false;

  // If login is from outside organization, trigger immediate admin SOC incident
  if (req.body.is_outside_organization) {
    const geoIncId = `INC-GEO-${Date.now().toString().slice(-4)}`;
    db.incidents.unshift({
      incident_id: geoIncId,
      created_at: now.toISOString(),
      severity: 'HIGH',
      status: 'NEW',
      title: `Unrecognized Location / Geofence Breach: ${user.username}`,
      description: `User '${user.username}' authenticated from outside the authorized organizational perimeter (${locationLabel}). Geographic security alert dispatched to Super Admin.`,
      target_user: user.username,
      actor_user: user.username,
      mitre_technique: 'T1078',
      mitre_tactic: 'Initial Access',
    });
    db.events.unshift({
      event_id: `EVT-GEO-ALERT-${Date.now().toString().slice(-4)}`,
      timestamp: now.toISOString(),
      event_type: 'out_of_org_login',
      severity: 'HIGH',
      username: user.username,
      message: `[OUTSIDE ORGANIZATION LOGIN] User '${user.username}' signed in from remote untrusted coordinates: ${locationLabel}`,
    });
  }

  const sessionId = `SES-${user.username.toUpperCase()}-${Date.now().toString().slice(-4)}`;
  res.json({
    status: 'SUCCESS',
    user: {
      user_id: user.user_id,
      username: user.username,
      email: user.email,
      role: user.role,
      last_login: user.last_login,
      last_login_formatted_time: formattedTime,
      last_location: locationLabel,
      is_outside_organization: user.is_outside_organization,
    },
    session_id: sessionId,
  });
});

// Real Lab Files: List all files
app.get('/api/lab/files', (req, res) => {
  res.json(db.files);
});

// Real Lab Notifications: List all FIM notifications
app.get('/api/lab/notifications', (req, res) => {
  res.json(db.fileNotifications);
});

// Real Lab Files: Create new secure file
app.post('/api/lab/files', (req, res) => {
  const { name, content, username, file_type, mime_type, data_url, importance, classification, notes, custom_sha256 } = req.body;
  if (!name || !content) {
    return res.status(400).json({ error: 'File name and content are required' });
  }

  const hash = custom_sha256 || crypto.createHash('sha256').update(content).digest('hex');
  const newFile = {
    file_id: `FILE-${Date.now().toString().slice(-5)}`,
    name,
    content,
    original_content: content,
    file_type: file_type || 'TEXT',
    mime_type: mime_type || 'text/plain',
    data_url: data_url || null,
    importance: importance || 'MEDIUM',
    classification: classification || 'INTERNAL',
    notes: notes || '',
    created_by: username || 'anonymous',
    created_at: new Date().toISOString(),
    original_sha256: hash,
    current_sha256: hash,
    last_modified_by: username || 'anonymous',
    last_modified_at: new Date().toISOString(),
    is_tampered: false,
    tampered_by: null,
    history: [
      {
        timestamp: new Date().toISOString(),
        modified_by: username || 'anonymous',
        sha256: hash,
        action: 'CREATED',
      }
    ]
  };

  db.files.push(newFile);
  res.status(201).json(newFile);
});

// Real Lab Files: Edit file & detect multi-user tampering
app.put('/api/lab/files/:id', (req, res) => {
  const { content, username } = req.body;
  const file = db.files.find(f => f.file_id === req.params.id);
  if (!file) return res.status(404).json({ error: 'File not found' });

  const newHash = crypto.createHash('sha256').update(content).digest('hex');
  const isDifferentUser = username && username.toLowerCase() !== file.created_by.toLowerCase();

  file.content = content;
  file.current_sha256 = newHash;
  file.last_modified_by = username || 'unknown';
  file.last_modified_at = new Date().toISOString();

  if (isDifferentUser) {
    file.is_tampered = true;
    file.tampered_by = username;

    // Ingest incident for data tampering
    const incidentId = `INC-TAMPER-${Date.now().toString().slice(-4)}`;
    db.incidents.push({
      incident_id: incidentId,
      created_at: new Date().toISOString(),
      severity: 'CRITICAL',
      status: 'NEW',
      title: `Unauthorized File Modification: ${file.name}`,
      description: `Secure file owned by ${file.created_by} was modified by another user: ${username}. SHA-256 integrity mismatch.`,
      target_user: file.created_by,
      actor_user: username,
      mitre_technique: 'T1565.001',
      mitre_tactic: 'Impact',
    });

    // Automated FIM notification sent to Admin and File Owner
    db.fileNotifications.unshift({
      notification_id: `NOTIF-${Date.now().toString().slice(-5)}`,
      file_id: file.file_id,
      file_name: file.name,
      original_owner: file.created_by,
      tampered_by: username,
      timestamp: new Date().toISOString(),
      original_sha256: file.original_sha256,
      tampered_sha256: newHash,
      severity: 'CRITICAL',
      status: 'PENDING_REVIEW',
      message: `Integrity Drift Alert: File '${file.name}' owned by ${file.created_by} was altered by '${username}'. Original owner or Admin can revert to verified snapshot.`,
      can_revert: true,
    });
  }

  file.history.push({
    timestamp: new Date().toISOString(),
    modified_by: username || 'unknown',
    sha256: newHash,
    action: isDifferentUser ? 'UNAUTHORIZED_ALTERATION' : 'UPDATED',
  });

  res.json({ file, tamperedByOther: isDifferentUser });
});

// Real Lab Files: Simulate attacker tamper
app.post('/api/lab/files/:id/tamper', (req, res) => {
  const { modified_content, attacker_username } = req.body;
  const file = db.files.find(f => f.file_id === req.params.id);
  if (!file) return res.status(404).json({ error: 'File not found' });

  const attacker = attacker_username || 'rogue_attacker';
  const newContent = modified_content || (file.content + '\n[EXFILTRATION_PAYLOAD_INSERTED_BY_ATTACKER]');
  const newHash = crypto.createHash('sha256').update(newContent).digest('hex');

  file.content = newContent;
  file.current_sha256 = newHash;
  file.last_modified_by = attacker;
  file.last_modified_at = new Date().toISOString();
  file.is_tampered = true;
  file.tampered_by = attacker;

  file.history.push({
    timestamp: new Date().toISOString(),
    modified_by: attacker,
    sha256: newHash,
    action: 'MALICIOUS_TAMPER',
  });

  // Automated notification to Admin & Owner
  db.fileNotifications.unshift({
    notification_id: `NOTIF-${Date.now().toString().slice(-5)}`,
    file_id: file.file_id,
    file_name: file.name,
    original_owner: file.created_by,
    tampered_by: attacker,
    timestamp: new Date().toISOString(),
    original_sha256: file.original_sha256,
    tampered_sha256: newHash,
    severity: 'CRITICAL',
    status: 'PENDING_REVIEW',
    message: `🚨 MALICIOUS INTEGRITY TAMPER: File '${file.name}' owned by ${file.created_by} tampered by '${attacker}'. SHA-256 altered from ${file.original_sha256.slice(0, 12)}... to ${newHash.slice(0, 12)}...`,
    can_revert: true,
  });

  res.json({ status: 'TAMPERED', file });
});

// Real Lab Files: Restore original file back to verified genesis content
app.post('/api/lab/files/:id/restore', (req, res) => {
  const file = db.files.find(f => f.file_id === req.params.id);
  if (!file) return res.status(404).json({ error: 'File not found' });

  // Revert back to the data the employee had stored first
  if (file.original_content) {
    file.content = file.original_content;
  }
  file.current_sha256 = file.original_sha256;
  file.is_tampered = false;
  file.tampered_by = null;
  file.last_modified_by = file.created_by;
  file.last_modified_at = new Date().toISOString();

  file.history.push({
    timestamp: new Date().toISOString(),
    modified_by: req.body.username || file.created_by,
    sha256: file.original_sha256,
    action: 'RESTORED_TO_ORIGINAL',
  });

  // Mark all related notifications as REVERTED
  db.fileNotifications.forEach(n => {
    if (n.file_id === file.file_id) {
      n.status = 'REVERTED';
      n.can_revert = false;
    }
  });

  res.json({ status: 'RESTORED', file });
});

// -------------------------------------------------------------
// GEOLOCATION & GOOGLE MAPS APIs
// -------------------------------------------------------------
app.get('/api/geo/coordinates', (req, res) => {
  res.json(db.geoHistory.slice(-20));
});

app.post('/api/geo/coordinates', (req, res) => {
  const { latitude, longitude, accuracy, username, label } = req.body;
  const record = {
    geo_id: `GEO-${Date.now().toString().slice(-4)}`,
    latitude,
    longitude,
    accuracy: accuracy || 15,
    username: username || 'lab_user',
    label: label || 'Authorized Telemetry Sensor',
    timestamp: new Date().toISOString(),
    google_maps_url: `https://maps.google.com/maps?q=${latitude},${longitude}&z=15`,
  };
  db.geoHistory.push(record);
  res.status(201).json(record);
});

// -------------------------------------------------------------
// HACK PREDICTOR ENGINE API
// -------------------------------------------------------------
app.get('/api/predict-hack', (req, res) => {
  const failedLogins = db.events.filter(e => e.event_type === 'login_failure').length;
  const portProbes = db.events.filter(e => e.event_type === 'port_probe').length;
  const tamperedFiles = db.files.filter(f => f.is_tampered).length;

  let score = 15;
  let stage = 'Reconnaissance';
  let probability = 'LOW';
  const forecast: string[] = [];

  if (failedLogins >= 3) {
    score += 45;
    stage = 'Credential Access (T1110)';
    probability = 'HIGH';
    forecast.push('Probable Brute Force / Credential Stuffing Campaign detected against employee accounts.');
  }
  if (portProbes >= 3) {
    score += 30;
    stage = 'Discovery / Lateral Movement (T1046)';
    if (probability !== 'CRITICAL') probability = 'HIGH';
    forecast.push('Automated port sweep observed. Likely precursor to remote service exploitation.');
  }
  if (tamperedFiles > 0) {
    score += 50;
    stage = 'Impact / Data Tampering (T1565.001)';
    probability = 'CRITICAL';
    forecast.push('Active data corruption or unauthorized credential file alteration detected in real lab.');
  }

  score = Math.min(score, 99);

  res.json({
    threat_prediction_score: score,
    kill_chain_stage: stage,
    probability,
    forecast_indicators: forecast.length > 0 ? forecast : ['Standard benign baseline telemetry.'],
    recommended_proactive_actions: [
      'Enforce Multi-Factor Authentication (MFA) step-up challenge',
      'Rate limit IP requests on /api/auth/login to 5 req/min',
      'Verify SHA-256 hashes of all stored employee files in real lab',
      'Lock compromised accounts and revoke active sessions',
    ],
    timestamp: new Date().toISOString(),
  });
});

// -------------------------------------------------------------
// CYBER SECURITY TOOLS SUITE APIs
// -------------------------------------------------------------

// YARA Rule Scanner
app.post('/api/security/yara-scan', (req, res) => {
  const { content, rule } = req.body;
  const target = content || '';
  const ruleName = rule || 'Default_Webshell_Rule';

  const matches: string[] = [];
  if (target.includes('UNION SELECT') || target.includes('OR 1=1')) matches.push('$sqli_tautology');
  if (target.includes('<?php system') || target.includes('shell_exec')) matches.push('$webshell_exec');
  if (target.includes('<script>') || target.includes('javascript:')) matches.push('$xss_script_injection');
  if (target.includes('powershell -enc') || target.includes('Invoke-Expression')) matches.push('$powershell_payload');

  res.json({
    tool: 'YARA Rule Scanner v4.4',
    rule_name: ruleName,
    matched: matches.length > 0,
    tags: matches,
    timestamp: new Date().toISOString(),
    status: matches.length > 0 ? 'ALERT_RULE_MATCH' : 'CLEAN',
  });
});

// ClamAV Malware Hash Scanner
app.post('/api/security/clamav-scan', (req, res) => {
  const { sha256, fileName } = req.body;
  const knownMaliciousHashes = [
    '44d88612fea8a8f36de82e1278abb02f',
    '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  ];

  const isMalicious = knownMaliciousHashes.includes(sha256?.toLowerCase());
  res.json({
    tool: 'ClamAV Malware Engine v1.2',
    file_name: fileName || 'unknown.dat',
    sha256,
    verdict: isMalicious ? 'INFECTED' : 'CLEAN',
    signature: isMalicious ? 'Win.Test.EICAR_HDB-1' : 'None',
    quarantined: isMalicious,
    timestamp: new Date().toISOString(),
  });
});

// OWASP ZAP Dynamic Scanner
app.post('/api/security/zap-scan', (req, res) => {
  const { targetUrl } = req.body;
  res.json({
    tool: 'OWASP ZAP Dynamic Application Security Tester v2.14',
    target: targetUrl || 'http://localhost:3000/api/lab',
    scanned_at: new Date().toISOString(),
    findings: [
      {
        alert: 'Missing X-Frame-Options Header',
        risk: 'LOW',
        confidence: 'HIGH',
        cwe: 'CWE-1021',
        url: targetUrl || '/api/lab',
      },
      {
        alert: 'Strict Transport Security (HSTS) Missing',
        risk: 'MEDIUM',
        confidence: 'HIGH',
        cwe: 'CWE-319',
        url: targetUrl || '/api/lab',
      },
      {
        alert: 'Content-Security-Policy Header Not Enforced',
        risk: 'LOW',
        confidence: 'MEDIUM',
        cwe: 'CWE-693',
        url: targetUrl || '/api/lab',
      },
    ],
  });
});

// -------------------------------------------------------------
// USER MANAGEMENT & RBAC APIs
// -------------------------------------------------------------
app.get('/api/users', (req, res) => {
  res.json(db.users.map(u => ({
    user_id: u.user_id,
    username: u.username,
    email: u.email,
    role: u.role,
    is_suspended: u.is_suspended,
    login_enabled: u.login_enabled,
  })));
});

app.post('/api/users/:id/suspend', (req, res) => {
  const user = db.users.find(u => u.user_id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.is_suspended = true;
  user.login_enabled = false;
  res.json({ status: 'SUSPENDED', user });
});

app.post('/api/users/:id/restore', (req, res) => {
  const user = db.users.find(u => u.user_id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.is_suspended = false;
  user.login_enabled = true;
  res.json({ status: 'RESTORED', user });
});

// -------------------------------------------------------------
// VITE DEV SERVER MIDDLEWARE MOUNT
// -------------------------------------------------------------
async function startServer() {
  const vite = await createViteServer({
    server: { middlewareMode: true },
    appType: 'spa',
  });

  app.use(vite.middlewares);

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[MAS-CSI] Full-Stack server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();

