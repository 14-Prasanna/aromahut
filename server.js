require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const cors = require('cors');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const sanitizeHtml = require('sanitize-html');
const jwt = require('jsonwebtoken');
const cron = require('node-cron');
const { Server } = require('socket.io');
const http = require('http');
const PDFDocument = require('pdfkit');
const path = require('path');

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: 'https://www.aromahut.in',
    methods: ['GET', 'POST'],
  },
});

// Middleware
app.use(express.json());
app.use(cors({
  origin: 'https://www.aromahut.in',
}));
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
}));

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, {
  serverSelectionTimeoutMS: 5000,
})
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => {
    console.error('❌ MongoDB Connection Error:', err.message);
    process.exit(1);
  });

// Schemas
const orderSchema = new mongoose.Schema({
  buyerName: { type: String, required: true },
  buyerEmail: { type: String, required: true },
  buyerPhone: { type: String, required: true },
  buyerAddress: { type: String, required: true },
  buyerTown: { type: String, default: '' },
  buyerPostalCode: { type: String, default: '' },
  items: [{
    productName: { type: String, required: true },
    productPrice: { type: Number, required: true, min: 0 },
    productQuantity: { type: Number, required: true, min: 1 },
    productWeight: { type: String },
  }],
  razorpayOrderId: { type: String, required: true, unique: true },
  razorpayPaymentId: { type: String, required: true, unique: true },
  createdAt: { type: Date, default: Date.now },
  status: { type: String, enum: ['Pending', 'Completed'], default: 'Pending' },
  packetSuccess: { type: Boolean, default: false },
  packedToUser: { type: Boolean, default: false },
  sentToParcel: { type: Boolean, default: false },
  isParcelReady: { type: Boolean, default: false },
  subtotal: { type: Number, required: true },
  gstRate: { type: Number, default: 0.05 }, // 5% GST
  gstAmount: { type: Number, required: true },
  shippingFee: { type: Number, default: 1.00 },
  totalAmount: { type: Number, required: true },
});
const Order = mongoose.model('Order', orderSchema);

const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  imageUrl: { type: String, required: true },
  packetsToPack: { type: Number, required: true, min: 0 },
  weight: { type: String, required: true },
  updatedAt: { type: Date, default: Date.now },
});
const Product = mongoose.model('Product', productSchema);

const feedbackSchema = new mongoose.Schema({
  orderId: { type: String, required: true },
  paymentId: { type: String, required: true },
  rating: { type: Number, min: 1, max: 5 },
  comment: { type: String, trim: true, maxlength: 500 },
  createdAt: { type: Date, default: Date.now },
});
const Feedback = mongoose.model('Feedback', feedbackSchema);

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// Utility Functions
const authenticateAdmin = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized: No token provided' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (!decoded.isAdmin) {
      return res.status(403).json({ error: 'Forbidden: Admin access required' });
    }
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Unauthorized: Invalid token' });
  }
};

// WebSocket Connection
io.on('connection', (socket) => {
  console.log('✅ Client connected:', socket.id);
  socket.on('disconnect', () => {
    console.log('❌ Client disconnected:', socket.id);
  });
});

// Routes
app.post('/admin/login', (req, res) => {
  const { username, password } = req.body;
  if (username === process.env.ADMIN_USERNAME && password === process.env.ADMIN_PASSWORD) {
    const token = jwt.sign({ isAdmin: true }, process.env.JWT_SECRET, { expiresIn: '1h' });
    return res.json({ status: 'success', token });
  }
  res.status(401).json({ error: 'Invalid credentials' });
});

app.post('/create-order', async (req, res) => {
  const { amount, items, shippingFee } = req.body;
  
  // Validate input
  if (!amount || isNaN(amount) || amount < 100) {
    return res.status(400).json({ error: 'Invalid amount: Must be a number ≥ ₹1 (100 paise)' });
  }
  if (!items || !Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'Invalid items: Must be a non-empty array' });
  }

  // Calculate amounts with GST
  const subtotal = items.reduce((sum, item) => sum + (item.price * item.quantity), 0);
  const gstRate = 0.05; // 5% GST
  const gstAmount = subtotal * gstRate;
  const totalAmount = subtotal + gstAmount + (shippingFee || 0);
  const amountInPaise = Math.round(totalAmount * 100);

  // Validate calculated amount matches provided amount
  if (amountInPaise !== amount) {
    return res.status(400).json({ 
      error: `Amount mismatch: Expected ${amountInPaise} paise, received ${amount} paise`,
      details: {
        subtotal,
        gstAmount,
        shippingFee,
        totalAmount
      }
    });
  }

  // Create Razorpay order
  const options = {
    amount: amountInPaise,
    currency: 'INR',
    receipt: `receipt_order_${Date.now()}`,
  };

  try {
    const order = await razorpay.orders.create(options);
    res.json(order);
  } catch (err) {
    console.error('Razorpay Order Error:', err);
    res.status(500).json({ 
      error: 'Failed to create order', 
      details: err.description || err.message 
    });
  }
});

app.post('/verify-payment', async (req, res) => {
  const {
    razorpay_order_id,
    razorpay_payment_id,
    razorpay_signature,
    buyerName,
    buyerEmail,
    buyerPhone,
    buyerAddress,
    items,
    shippingFee = 1.00
  } = req.body;

  // Validate required fields
  if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature ||
      !buyerName || !buyerEmail || !buyerPhone || !buyerAddress || !items || !Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ status: 'failed', error: 'Missing required fields' });
  }

  // Sanitize inputs
  const sanitizedBuyerName = sanitizeHtml(buyerName);
  const sanitizedBuyerEmail = sanitizeHtml(buyerEmail);
  const sanitizedBuyerPhone = sanitizeHtml(buyerPhone);
  const sanitizedBuyerAddress = sanitizeHtml(buyerAddress);

  // Validate email and phone
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(sanitizedBuyerEmail)) {
    return res.status(400).json({ status: 'failed', error: 'Invalid email address' });
  }
  if (!/^\d{10}$/.test(sanitizedBuyerPhone)) {
    return res.status(400).json({ status: 'failed', error: 'Invalid phone number: Must be 10 digits' });
  }

  // Verify payment signature
  const hmac = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET);
  hmac.update(razorpay_order_id + '|' + razorpay_payment_id);
  const generatedSignature = hmac.digest('hex');

  if (generatedSignature !== razorpay_signature) {
    console.error('Payment verification failed: Invalid signature');
    return res.status(400).json({ status: 'failed', message: 'Payment verification failed' });
  }

  try {
    // Calculate order amounts
    const addressParts = sanitizedBuyerAddress.split(', ');
    const subtotal = items.reduce((sum, item) => sum + (item.price * item.quantity), 0);
    const gstRate = 0.05; // 5% GST
    const gstAmount = subtotal * gstRate;
    const totalAmount = subtotal + gstAmount + parseFloat(shippingFee);

    // Create order document
    const orderData = {
      buyerName: sanitizedBuyerName,
      buyerEmail: sanitizedBuyerEmail,
      buyerPhone: sanitizedBuyerPhone,
      buyerAddress: addressParts[0] || sanitizedBuyerAddress,
      buyerTown: addressParts[1] || '',
      buyerPostalCode: addressParts[2] || '',
      items: items.map(item => ({
        productName: sanitizeHtml(item.name),
        productPrice: parseFloat(item.price),
        productQuantity: parseInt(item.quantity, 10),
        productWeight: sanitizeHtml(item.weight || ''),
      })),
      razorpayOrderId: razorpay_order_id,
      razorpayPaymentId: razorpay_payment_id,
      subtotal,
      gstRate,
      gstAmount,
      shippingFee: parseFloat(shippingFee),
      totalAmount
    };

    const order = new Order(orderData);
    await order.save();
    
    // Send confirmation email
    await sendOrderEmail(order);
    
    return res.json({ 
      status: 'success', 
      message: 'Payment verified and order saved',
      orderDetails: {
        orderId: razorpay_order_id,
        paymentId: razorpay_payment_id,
        subtotal,
        gstAmount,
        shippingFee,
        totalAmount
      }
    });
  } catch (error) {
    console.error('Error processing payment:', error.message, error.stack);
    return res.status(500).json({ 
      status: 'failed', 
      error: 'Server error', 
      details: error.message 
    });
  }
});

// Email Function
async function sendOrderEmail(order) {
  try {
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD,
      },
    });

    const itemsHtml = order.items.map(item => `
      <tr>
        <td style="padding: 8px; border: 1px solid #ddd;">${sanitizeHtml(item.productName)}</td>
        <td style="padding: 8px; border: 1px solid #ddd;">${item.productWeight || '-'}</td>
        <td style="padding: 8px; border: 1px solid #ddd;">${item.productQuantity}</td>
        <td style="padding: 8px; border: 1px solid #ddd;">₹${item.productPrice.toFixed(2)}</td>
      </tr>
    `).join('');

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: order.buyerEmail,
      subject: 'Thank You for Your Purchase from AromaHut!',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #ddd;">
          <h2 style="color: #ff6b00;">Order Confirmation</h2>
          <p>Dear ${sanitizeHtml(order.buyerName)},</p>
          <p>Thank you for shopping with AromaHut! Your order has been successfully placed.</p>
          
          <h3>Order Details</h3>
          <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px;">
            <thead>
              <tr style="background-color: #f9f9f9;">
                <th style="padding: 8px; border: 1px solid #ddd;">Product</th>
                <th style="padding: 8px; border: 1px solid #ddd;">Weight</th>
                <th style="padding: 8px; border: 1px solid #ddd;">Quantity</th>
                <th style="padding: 8px; border: 1px solid #ddd;">Price</th>
              </tr>
            </thead>
            <tbody>
              ${itemsHtml}
            </tbody>
          </table>
          
          <div style="text-align: right; margin-bottom: 20px;">
            <p><strong>Subtotal:</strong> ₹${order.subtotal.toFixed(2)}</p>
            <p><strong>GST (${(order.gstRate * 100)}%):</strong> ₹${order.gstAmount.toFixed(2)}</p>
            <p><strong>Shipping:</strong> ₹${order.shippingFee.toFixed(2)}</p>
            <p style="font-weight: bold; font-size: 1.1em;">
              <strong>Total:</strong> ₹${order.totalAmount.toFixed(2)}
            </p>
          </div>
          
          <h3>Shipping To</h3>
          <p>${sanitizeHtml(order.buyerName)}</p>
          <p>${sanitizeHtml([order.buyerAddress, order.buyerTown, order.buyerPostalCode].filter(Boolean).join(', '))}</p>
          
          <p>We'll notify you once your order has shipped. For any questions, contact us at ${process.env.EMAIL_USER}.</p>
          <p>Best regards,<br>AromaHut Team</p>
        </div>
      `,
    };

    await transporter.sendMail(mailOptions);
    console.log(`✅ Confirmation email sent to ${order.buyerEmail}`);
  } catch (error) {
    console.error('❌ Email sending error:', error.message);
    throw error;
  }
}

// Admin Routes
app.get('/admin/orders', authenticateAdmin, async (req, res) => {
  try {
    const { status, startDate, endDate } = req.query;
    const query = {};
    
    if (status && ['Pending', 'Completed'].includes(status)) {
      query.status = status;
    }
    if (startDate) {
      query.createdAt = { $gte: new Date(startDate) };
    }
    if (endDate) {
      query.createdAt = {
        ...query.createdAt,
        $lte: new Date(new Date(endDate).setHours(23, 59, 59, 999)),
      };
    }

    const orders = await Order.find(query)
      .sort({ createdAt: -1 })
      .lean();

    res.status(200).json({ 
      status: 'success', 
      data: orders.map(order => ({
        ...order,
        formattedTotal: `₹${order.totalAmount.toFixed(2)}`,
        formattedDate: new Date(order.createdAt).toLocaleString()
      }))
    });
  } catch (error) {
    console.error('Error fetching orders:', error.message);
    res.status(500).json({ 
      error: 'Failed to fetch orders', 
      details: error.message 
    });
  }
});

// PDF Invoice Generation
app.get('/download-invoice/:orderId', authenticateAdmin, async (req, res) => {
  try {
    const order = await Order.findOne({ razorpayOrderId: req.params.orderId });
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }

    const doc = new PDFDocument({ size: 'A4', margin: 50 });
    const filename = `invoice_${order.razorpayOrderId}.pdf`;

    res.setHeader('Content-disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-type', 'application/pdf');
    doc.pipe(res);

    // Logo
    doc.image(path.join(__dirname, 'public', 'img', 'aromahutTitleIcon.png'), 50, 50, { width: 80 });

    // Header
    doc.fontSize(16).fillColor('#003366').text('AromaHut', { align: 'center' });
    doc.fontSize(10).fillColor('black');
    doc.text('No. 45, Spice Lane, Salem - 636007, Tamil Nadu, India', { align: 'center' });
    doc.text('GSTIN: 33ABCDE1234F125 | Phone: +91-98765-43210', { align: 'center' });
    doc.moveDown(1);

    // Invoice Title
    doc.fontSize(14).fillColor('#003366').text('TAX INVOICE', { align: 'center' });
    doc.fontSize(10).fillColor('black');
    doc.text(`Invoice No: INV-${order.razorpayOrderId.slice(0, 8)}`, { align: 'left' });
    doc.text(`Date: ${new Date(order.createdAt).toLocaleDateString('en-IN')}`, { align: 'left' });
    doc.moveDown(1);

    // Buyer Information
    doc.fontSize(12).fillColor('black').text('Bill To:', { align: 'left' });
    doc.fontSize(10);
    doc.text(order.buyerName, { align: 'left' });
    doc.text([order.buyerAddress, order.buyerTown, order.buyerPostalCode].filter(Boolean).join(', '), { align: 'left' });
    doc.text(`Phone: ${order.buyerPhone}`, { align: 'left' });
    doc.text(`Email: ${order.buyerEmail}`, { align: 'left' });
    doc.moveDown(1);

    // Items Table
    doc.fontSize(12).text('Items:', { align: 'left' });
    doc.fontSize(10);

    // Table Header
    const tableTop = doc.y + 10;
    const tableX = 50;
    doc.font('Helvetica-Bold');
    doc.text('Description', tableX, tableTop, { width: 200 });
    doc.text('HSN/SAC', tableX + 200, tableTop, { width: 80, align: 'center' });
    doc.text('Qty', tableX + 280, tableTop, { width: 50, align: 'center' });
    doc.text('Rate (₹)', tableX + 330, tableTop, { width: 80, align: 'right' });
    doc.text('GST (5%)', tableX + 410, tableTop, { width: 80, align: 'right' });
    doc.text('Amount (₹)', tableX + 490, tableTop, { width: 80, align: 'right' });
    doc.moveDown(0.5);
    doc.lineWidth(1).moveTo(tableX, doc.y).lineTo(tableX + 570, doc.y).stroke();

    // Table Rows
    doc.font('Helvetica');
    order.items.forEach((item, index) => {
      const rowY = doc.y + 10;
      const itemTotal = item.productPrice * item.productQuantity;
      const itemGst = itemTotal * 0.05;
      
      doc.text(item.productName, tableX, rowY, { width: 200 });
      doc.text('9983', tableX + 200, rowY, { width: 80, align: 'center' }); // Generic HSN code for spices
      doc.text(item.productQuantity.toString(), tableX + 280, rowY, { width: 50, align: 'center' });
      doc.text(item.productPrice.toFixed(2), tableX + 330, rowY, { width: 80, align: 'right' });
      doc.text(itemGst.toFixed(2), tableX + 410, rowY, { width: 80, align: 'right' });
      doc.text(itemTotal.toFixed(2), tableX + 490, rowY, { width: 80, align: 'right' });
      doc.moveDown(0.5);
      doc.lineWidth(0.5).moveTo(tableX, doc.y).lineTo(tableX + 570, doc.y).stroke();
    });

    // Totals
    const subtotalY = doc.y + 10;
    doc.text('Subtotal', tableX + 410, subtotalY, { width: 80, align: 'right' });
    doc.text(order.subtotal.toFixed(2), tableX + 490, subtotalY, { width: 80, align: 'right' });
    doc.moveDown(0.5);
    
    doc.text('GST (5%)', tableX + 410, doc.y, { width: 80, align: 'right' });
    doc.text(order.gstAmount.toFixed(2), tableX + 490, doc.y, { width: 80, align: 'right' });
    doc.moveDown(0.5);
    
    doc.text('Shipping', tableX + 410, doc.y, { width: 80, align: 'right' });
    doc.text(order.shippingFee.toFixed(2), tableX + 490, doc.y, { width: 80, align: 'right' });
    doc.moveDown(0.5);
    
    doc.lineWidth(1).moveTo(tableX, doc.y).lineTo(tableX + 570, doc.y).stroke();
    doc.font('Helvetica-Bold');
    doc.text('Total', tableX + 410, doc.y + 10, { width: 80, align: 'right' });
    doc.text(order.totalAmount.toFixed(2), tableX + 490, doc.y + 10, { width: 80, align: 'right' });

    // Footer
    doc.moveDown(2);
    doc.fontSize(10).text('Thank you for your business!', { align: 'center' });
    doc.text('For any inquiries, please contact us at aromahut24@gmail.com', { align: 'center' });
    doc.text('This is a computer generated invoice and does not require a signature', { align: 'center' });

    doc.end();
  } catch (error) {
    console.error('Error generating invoice:', error.message);
    res.status(500).json({ 
      error: 'Failed to generate invoice', 
      details: error.message 
    });
  }
});

// Error Handling
app.use((err, req, res, next) => {
  console.error('Unhandled Error:', err.message, err.stack);
  res.status(500).json({ 
    error: 'Internal server error', 
    details: err.message 
  });
});

// Start Server
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
