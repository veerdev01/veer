require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const https = require('https');

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

// ─── CONFIG ────────────────────────────────────────────────────────────────
const MONGO_URI    = process.env.MONGO_URI    || 'mongodb://localhost:27017/bothost';
const JWT_SECRET   = process.env.JWT_SECRET   || 'bothost_super_secret_key_change_in_prod';
const ADMIN_USER   = process.env.ADMIN_USER   || 'admin';
const ADMIN_PASS   = process.env.ADMIN_PASS   || 'Admin@123';
const PORT         = process.env.PORT         || 3000;
const TG_BOT_TOKEN = process.env.TG_BOT_TOKEN || '';
const TG_CHAT_ID   = process.env.TG_CHAT_ID   || '';

// ─── TELEGRAM ───────────────────────────────────────────────────────────────
function sendTelegram(text) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ chat_id: TG_CHAT_ID, text, parse_mode: 'HTML' });
    const options = {
      hostname: 'api.telegram.org',
      path: `/bot${TG_BOT_TOKEN}/sendMessage`,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
    };
    const req = https.request(options, res => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(JSON.parse(data)));
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// ─── SCHEMAS ─────────────────────────────────────────────────────────────────
const userSchema = new mongoose.Schema({
  name:      { type: String, required: true, trim: true },
  email:     { type: String, required: true, unique: true, lowercase: true },
  password:  { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const orderSchema = new mongoose.Schema({
  orderId:     { type: String, unique: true },
  userId:      { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  customer:    String,
  email:       String,
  whatsapp:    String,
  plan:        String,
  cpu:         String,
  ram:         String,
  storage:     String,
  os:          String,
  price:       Number,
  duration:    String,
  utr:         { type: String, required: true },
  status:      { type: String, enum: ['pending','verified','approved','rejected'], default: 'pending' },
  // VPS Credentials — only visible to user after approved
  vpsIp:       { type: String, default: '' },
  vpsUsername: { type: String, default: 'root' },
  vpsPassword: { type: String, default: '' },
  vpsPort:     { type: String, default: '22' },
  vpsNote:     { type: String, default: '' },
  createdAt:   { type: Date, default: Date.now }
});

const settingsSchema = new mongoose.Schema({
  key:   { type: String, unique: true },
  value: mongoose.Schema.Types.Mixed
});

const User     = mongoose.model('User',     userSchema);
const Order    = mongoose.model('Order',    orderSchema);
const Settings = mongoose.model('Settings', settingsSchema);

// ─── HELPERS ─────────────────────────────────────────────────────────────────
function generateOrderId() {
  return `NX-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).substring(2,6).toUpperCase()}`;
}

function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid token' }); }
}

function adminAuth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const p = jwt.verify(token, JWT_SECRET);
    if (p.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
    req.admin = p; next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
}

async function getSetting(key, fallback = null) {
  const doc = await Settings.findOne({ key });
  return doc ? doc.value : fallback;
}
async function setSetting(key, value) {
  await Settings.findOneAndUpdate({ key }, { value }, { upsert: true });
}
function isValidUTR(utr) {
  return /^\d{10,24}$/.test(utr.trim());
}

// ─── BHARATPE UTR VERIFICATION ───────────────────────────────────────────────
async function verifyBharatPeUTR(utr, amount) {
  try {
    const merchantId = await getSetting('bharatpeMerchantId', '');
    const token      = await getSetting('bharatpeToken', '');
    if (!merchantId || !token) return { verified: false, reason: 'BharatPe not configured' };

    const body = JSON.stringify({ txnId: utr.trim() });
    const options = {
      hostname: 'payments-testenvironment.bharatpe.com',
      path: `/merchant-middleware/api/v1/payment/verify`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'merchant_id': merchantId,
        'token': token,
        'Content-Length': Buffer.byteLength(body)
      }
    };

    return new Promise((resolve) => {
      const req = https.request(options, res => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            const json = JSON.parse(data);
            // BharatPe returns success if transaction found and amount matches
            if (json.status === 'SUCCESS' || json.data?.status === 'SUCCESS') {
              const txnAmount = json.data?.amount || json.amount || 0;
              if (Number(txnAmount) >= Number(amount)) {
                resolve({ verified: true });
              } else {
                resolve({ verified: false, reason: `Amount mismatch: Expected ₹${amount}, Got ₹${txnAmount}` });
              }
            } else {
              resolve({ verified: false, reason: json.message || 'UTR not found in BharatPe' });
            }
          } catch {
            resolve({ verified: false, reason: 'BharatPe response parse error' });
          }
        });
      });
      req.on('error', () => resolve({ verified: false, reason: 'BharatPe API unreachable' }));
      req.write(body);
      req.end();
    });
  } catch {
    return { verified: false, reason: 'Verification error' };
  }
}

// ─── AUTH ────────────────────────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    if (await User.findOne({ email })) return res.status(409).json({ error: 'Email already registered' });
    const user = await User.create({ name, email, password: await bcrypt.hash(password, 10) });
    const token = jwt.sign({ id: user._id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, name: user.name, email: user.email } });
  } catch { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(401).json({ error: 'Invalid email or password' });
    const token = jwt.sign({ id: user._id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, name: user.name, email: user.email } });
  } catch { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    const token = jwt.sign({ role: 'admin', username }, JWT_SECRET, { expiresIn: '8h' });
    return res.json({ token });
  }
  res.status(401).json({ error: 'Invalid admin credentials' });
});

// ─── ORDERS ──────────────────────────────────────────────────────────────────
app.post('/api/orders', auth, async (req, res) => {
  try {
    const { plan, cpu, ram, storage, os, price, duration, whatsapp, utr } = req.body;
    if (!utr) return res.status(400).json({ error: 'UTR is required' });
    if (!isValidUTR(utr)) return res.status(400).json({ error: 'Invalid UTR. Enter a valid 10-24 digit transaction ID.' });
    if (await Order.findOne({ utr: utr.trim() })) return res.status(409).json({ error: 'This UTR has already been used.' });

    // ── BharatPe UTR Verification ──
    const bpResult = await verifyBharatPeUTR(utr, price);
    const orderStatus = bpResult.verified ? 'verified' : 'pending';
    const autoVerified = bpResult.verified;

    const orderId = generateOrderId();
    const order = await Order.create({
      orderId, userId: req.user.id, customer: req.user.name, email: req.user.email,
      whatsapp, plan, cpu, ram, storage, os, price, duration, utr: utr.trim(), status: orderStatus
    });

    // Send Telegram notification
    const time = new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' });
    sendTelegram(`
🆕 <b>NEW ORDER RECEIVED!</b>

🔖 <b>Order ID:</b> <code>${orderId}</code>
👤 <b>Customer:</b> ${req.user.name}
📧 <b>Email:</b> ${req.user.email}
📱 <b>WhatsApp:</b> ${whatsapp || 'Not provided'}

📦 <b>Plan:</b> ${plan}
🖥️ <b>Specs:</b> ${cpu} | ${ram} | ${storage}
💿 <b>OS:</b> ${os || 'Not specified'}
⏱️ <b>Duration:</b> ${duration}

💰 <b>Amount:</b> ₹${Number(price).toLocaleString('en-IN')}
🔢 <b>UTR:</b> <code>${utr}</code>
${autoVerified ? '✅ <b>UTR Auto-Verified via BharatPe</b>' : '⚠️ <b>UTR Pending Manual Verification</b>' + (bpResult.reason ? `\nReason: ${bpResult.reason}` : '')}

🕐 ${time}

👉 Go to Admin Panel → Set VPS Credentials to approve.
    `.trim()).catch(e => console.error('Telegram error:', e.message));

    res.json({ 
      success: true, 
      orderId: order.orderId, 
      status: order.status,
      verified: autoVerified,
      message: autoVerified ? 'Payment verified automatically!' : 'Order placed, payment under review.'
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// User sees their orders — credentials only visible if approved
app.get('/api/orders/mine', auth, async (req, res) => {
  const orders = await Order.find({ userId: req.user.id }).sort({ createdAt: -1 });
  const safe = orders.map(o => {
    const obj = o.toObject();
    if (o.status !== 'approved') {
      obj.vpsIp = ''; obj.vpsUsername = ''; obj.vpsPassword = ''; obj.vpsPort = ''; obj.vpsNote = '';
    }
    return obj;
  });
  res.json(safe);
});

// ─── SETTINGS ────────────────────────────────────────────────────────────────
app.get('/api/settings/public', async (req, res) => {
  res.json({
    upiId: await getSetting('upiId', 'yourname@bharatpe'),
    qrUrl: await getSetting('qrUrl', ''),
    wa:    await getSetting('wa',    '919876543210'),
    tg:    await getSetting('tg',    '@BotHostSupport'),
    plans: await getSetting('plans', defaultPlans())
  });
});

// ─── ADMIN ───────────────────────────────────────────────────────────────────
app.get('/api/admin/stats', adminAuth, async (req, res) => {
  const [total, pending, verified, approved, users, revenue] = await Promise.all([
    Order.countDocuments(),
    Order.countDocuments({ status: 'pending' }),
    Order.countDocuments({ status: 'verified' }),
    Order.countDocuments({ status: 'approved' }),
    User.countDocuments(),
    Order.aggregate([{ $match: { status: { $in: ['approved','verified'] } } }, { $group: { _id: null, total: { $sum: '$price' } } }])
  ]);
  res.json({ total, pending, verified, approved, users, revenue: revenue[0]?.total || 0 });
});

app.get('/api/admin/orders', adminAuth, async (req, res) => {
  res.json(await Order.find().sort({ createdAt: -1 }));
});

app.patch('/api/admin/orders/:id/approve', adminAuth, async (req, res) => {
  const order = await Order.findByIdAndUpdate(req.params.id, { status: 'approved' }, { new: true });
  if (!order) return res.status(404).json({ error: 'Order not found' });
  res.json({ success: true, order });
});

app.patch('/api/admin/orders/:id/reject', adminAuth, async (req, res) => {
  const order = await Order.findByIdAndUpdate(req.params.id, { status: 'rejected' }, { new: true });
  if (!order) return res.status(404).json({ error: 'Order not found' });
  res.json({ success: true, order });
});

// ── Set VPS Credentials → auto-approve + notify on Telegram ─────────────────
app.patch('/api/admin/orders/:id/credentials', adminAuth, async (req, res) => {
  try {
    const { vpsIp, vpsUsername, vpsPassword, vpsPort, vpsNote } = req.body;
    if (!vpsIp || !vpsPassword) return res.status(400).json({ error: 'IP and Password are required' });

    const order = await Order.findByIdAndUpdate(req.params.id, {
      vpsIp: vpsIp.trim(),
      vpsUsername: (vpsUsername || 'root').trim(),
      vpsPassword: vpsPassword.trim(),
      vpsPort: (vpsPort || '22').trim(),
      vpsNote: (vpsNote || '').trim(),
      status: 'approved'
    }, { new: true });

    if (!order) return res.status(404).json({ error: 'Order not found' });

    // Notify yourself on Telegram
    sendTelegram(`
✅ <b>VPS CREDENTIALS SENT</b>

🔖 <b>Order:</b> <code>${order.orderId}</code>
👤 <b>Customer:</b> ${order.customer}
📧 <b>Email:</b> ${order.email}

🖥️ <b>IP:</b> <code>${vpsIp}</code>
👤 <b>Username:</b> <code>${vpsUsername || 'root'}</code>
🔑 <b>Password:</b> <code>${vpsPassword}</code>
🔌 <b>Port:</b> ${vpsPort || '22'}
${vpsNote ? `📝 <b>Note:</b> ${vpsNote}` : ''}

✅ Customer can now login to website and see their VPS credentials.
    `.trim()).catch(e => console.error('Telegram error:', e.message));

    res.json({ success: true, order });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/admin/users', adminAuth, async (req, res) => {
  res.json(await User.find().sort({ createdAt: -1 }).select('-password'));
});

app.get('/api/admin/settings', adminAuth, async (req, res) => {
  res.json({
    upiId:             await getSetting('upiId', ''),
    qrUrl:             await getSetting('qrUrl', ''),
    wa:                await getSetting('wa',    ''),
    tg:                await getSetting('tg',    ''),
    bharatpeMerchantId: await getSetting('bharatpeMerchantId', ''),
    bharatpeToken:     await getSetting('bharatpeToken', ''),
    plans:             await getSetting('plans', defaultPlans())
  });
});

app.post('/api/admin/settings', adminAuth, async (req, res) => {
  const { upiId, qrUrl, wa, tg, bharatpeMerchantId, bharatpeToken } = req.body;
  if (upiId              !== undefined) await setSetting('upiId',              upiId);
  if (qrUrl              !== undefined) await setSetting('qrUrl',              qrUrl);
  if (wa                 !== undefined) await setSetting('wa',                 wa);
  if (tg                 !== undefined) await setSetting('tg',                 tg);
  if (bharatpeMerchantId !== undefined) await setSetting('bharatpeMerchantId', bharatpeMerchantId);
  if (bharatpeToken      !== undefined) await setSetting('bharatpeToken',      bharatpeToken);
  res.json({ success: true });
});

app.post('/api/admin/plans', adminAuth, async (req, res) => {
  if (!Array.isArray(req.body.plans)) return res.status(400).json({ error: 'plans must be array' });
  await setSetting('plans', req.body.plans);
  res.json({ success: true });
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ─── DEFAULT PLANS ───────────────────────────────────────────────────────────
function defaultPlans() {
  return [
    { name:'Starter',    cpu:'1 vCPU', ram:'1 GB',  storage:'20 GB SSD',  price:199,  orig:399,  badge:'',        featured:false },
    { name:'Basic',      cpu:'2 vCPU', ram:'2 GB',  storage:'40 GB SSD',  price:399,  orig:699,  badge:'',        featured:false },
    { name:'Pro',        cpu:'4 vCPU', ram:'4 GB',  storage:'80 GB SSD',  price:799,  orig:1299, badge:'Popular', featured:true  },
    { name:'Business',   cpu:'6 vCPU', ram:'8 GB',  storage:'160 GB SSD', price:1499, orig:2299, badge:'',        featured:false },
    { name:'Enterprise', cpu:'8 vCPU', ram:'16 GB', storage:'320 GB SSD', price:2499, orig:3999, badge:'',        featured:false },
    { name:'Custom',     cpu:'Custom', ram:'Custom', storage:'Custom',     price:0,    orig:0,    badge:'',        featured:false }
  ];
}

// ─── START ───────────────────────────────────────────────────────────────────
mongoose.connect(MONGO_URI)
  .then(() => {
    console.log('✅ MongoDB connected');
    app.listen(PORT, () => {
      console.log(`🚀 BotHost running on port ${PORT}`);
      sendTelegram('🚀 <b>BotHost Server Started!</b>\nTelegram bot is connected and ready to receive orders.')
        .then(() => console.log('✅ Telegram OK'))
        .catch(e => console.error('❌ Telegram:', e.message));
    });
  })
  .catch(err => { console.error('❌ MongoDB failed:', err.message); process.exit(1); });
