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
const fs = require('fs');

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

mongoose.connect(process.env.MONGO_URI, {
  serverSelectionTimeoutMS: 5000,
})
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => {
    console.error('❌ MongoDB Connection Error:', err.message);
    process.exit(1);
  });

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

io.on('connection', (socket) => {
  console.log('✅ Client connected:', socket.id);
  socket.on('disconnect', () => {
    console.log('❌ Client disconnected:', socket.id);
  });
});

app.post('/admin/login', (req, res) => {
  const { username, password } = req.body;
  if (username === 'admin' && password === 'password') {
    const token = jwt.sign({ isAdmin: true }, process.env.JWT_SECRET, { expiresIn: '1h' });
    return res.json({ status: 'success', token });
  }
  res.status(401).json({ error: 'Invalid credentials' });
});

app.get('/admin/orders', async (req, res) => {
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
    const orders = await Order.find(query).sort({ createdAt: -1 }).lean();
    res.status(200).json({ status: 'success', data: orders });
  } catch (error) {
    console.error('Error fetching orders:', error.message);
    res.status(500).json({ error: 'Failed to fetch orders', details: error.message });
  }
});

app.post('/admin/order-status', async (req, res) => {
  const { orderId, step, completed } = req.body;
  if (!orderId || !step || typeof completed !== 'boolean') {
    return res.status(400).json({ error: 'Missing required fields: orderId, step, completed' });
  }
  const validSteps = ['packet_success', 'packed_to_user', 'sent_to_parcel'];
  if (!validSteps.includes(step)) {
    return res.status(400).json({ error: 'Invalid step value' });
  }
  try {
    const order = await Order.findOne({ razorpayOrderId: orderId });
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }
    const stepFieldMap = {
      packet_success: 'packetSuccess',
      packed_to_user: 'packedToUser',
      sent_to_parcel: 'sentToParcel',
    };
    order[stepFieldMap[step]] = completed;
    if (order.packetSuccess && order.packedToUser && order.sentToParcel) {
      order.status = 'Completed';
    } else {
      order.status = 'Pending';
    }
    await order.save();
    io.emit('orderUpdated', {
      orderId: order.razorpayOrderId,
      status: order.status,
      packetSuccess: order.packetSuccess,
      packedToUser: order.packedToUser,
      sentToParcel: order.sentToParcel,
    });
    res.status(200).json({ status: 'success', message: 'Order status updated' });
  } catch (error) {
    console.error('Error updating order status:', error.message);
    res.status(500).json({ error: 'Failed to update order status', details: error.message });
  }
});

app.get('/admin/order/:id', async (req, res) => {
  try {
    const order = await Order.findOne({ razorpayOrderId: req.params.id }).lean();
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }
    const response = {
      id: order.razorpayOrderId,
      buyer: {
        name: order.buyerName,
        email: order.buyerEmail,
        phone: order.buyerPhone,
        address: [order.buyerAddress, order.buyerTown, order.buyerPostalCode].filter(Boolean).join(', '),
      },
      items: order.items,
      createdAt: order.createdAt,
      status: order.status,
      steps: {
        packetSuccess: order.packetSuccess,
        packedToUser: order.packedToUser,
        sentToParcel: order.sentToParcel,
      },
      isParcelReady: order.isParcelReady,
    };
    res.status(200).json({ status: 'success', data: response });
  } catch (error) {
    console.error('Error fetching order:', error.message);
    res.status(500).json({ error: 'Failed to fetch order', details: error.message });
  }
});

app.get('/admin/products', async (req, res) => {
  try {
    const { page = 1 } = req.query;
    const limit = 10;
    const skip = (parseInt(page) - 1) * limit;
    const products = await Product.find()
      .sort({ updatedAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();
    const total = await Product.countDocuments();
    res.status(200).json({
      status: 'success',
      data: products,
      pagination: {
        page: parseInt(page),
        totalPages: Math.ceil(total / limit),
        totalItems: total,
      },
    });
  } catch (error) {
    console.error('Error fetching products:', error.message);
    res.status(500).json({ error: 'Failed to fetch products', details: error.message });
  }
});

app.post('/admin/start-packing', async (req, res) => {
  const { productId } = req.body;
  if (!productId) {
    return res.status(400).json({ error: 'Missing productId' });
  }
  try {
    const product = await Product.findById(productId);
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }
    product.packetsToPack = 0;
    product.updatedAt = new Date();
    await product.save();
    res.status(200).json({ status: 'success', message: 'Packing started, packetsToPack reset to 0' });
  } catch (error) {
    console.error('Error starting packing:', error.message);
    res.status(500).json({ error: 'Failed to start packing', details: error.message });
  }
});

app.get('/admin/customers', async (req, res) => {
  try {
    const orders = await Order.find({ isParcelReady: false })
      .sort({ createdAt: -1 })
      .lean();
    const customers = orders.map(order => ({
      orderId: order.razorpayOrderId,
      customerName: order.buyerName,
      email: order.buyerEmail,
      buyerPhone: order.buyerPhone,
      dateTime: order.createdAt,
      status: order.status,
      products: order.items.map(item => ({
        id: item._id.toString(),
        name: item.productName,
        quantity: item.productQuantity,
      })),
    }));
    res.status(200).json({ status: 'success', data: customers });
  } catch (error) {
    console.error('Error fetching customers:', error.message);
    res.status(500).json({ error: 'Failed to fetch customers', details: error.message });
  }
});

app.post('/admin/parcel-ready', async (req, res) => {
  const { orderId } = req.body;
  if (!orderId) {
    return res.status(400).json({ error: 'Missing orderId' });
  }
  try {
    const order = await Order.findOne({ razorpayOrderId: orderId });
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }
    order.isParcelReady = true;
    order.status = 'Completed';
    await order.save();
    io.emit('parcelReady', { orderId: order.razorpayOrderId });
    res.status(200).json({ status: 'success', message: 'Parcel marked as ready' });
  } catch (error) {
    console.error('Error marking parcel ready:', error.message);
    res.status(500).json({ error: 'Failed to mark parcel ready', details: error.message });
  }
});

// Update packetsToPack every 10 minutes
cron.schedule('*/10 * * * *', async () => {
  try {
    const products = await Product.find();
    const orders = await Order.find({ status: 'Pending' });
    for (const product of products) {
      const totalPackets = orders.reduce((sum, order) => {
        const productItems = order.items.filter(item => 
          item.productName === product.name && item.productWeight === product.weight
        );
        return sum + productItems.reduce((acc, item) => acc + item.productQuantity, 0);
      }, 0);
      if (product.packetsToPack !== totalPackets) {
        product.packetsToPack = totalPackets;
        product.updatedAt = new Date();
        await product.save();
      }
    }
    console.log('✅ packetsToPack updated for all products');
  } catch (error) {
    console.error('Error in cron job:', error.message);
  }
});

app.get('/test-email', async (req, res) => {
  try {
    await sendOrderEmail({
      buyerEmail: 'aromahut24@gmail.com',
      buyerName: 'Test User',
      buyerAddress: '123 Test Street, Test City, 123456',
      items: [{ productName: 'Test Product', productPrice: 100, productQuantity: 1 }],
    });
    res.status(200).json({ message: 'Test email sent successfully!' });
  } catch (error) {
    console.error('Test Email Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to send test email', details: error.message });
  }
});

app.post('/create-order', async (req, res) => {
  const { amount, items, shippingFee, gst } = req.body;
  if (!amount || isNaN(amount) || amount < 100) {
    return res.status(400).json({ error: 'Invalid amount: Must be a number ≥ ₹1 (100 paise)' });
  }
  if (!items || !Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'Invalid items: Must be a non-empty array' });
  }
  if (!shippingFee || isNaN(shippingFee) || shippingFee < 0) {
    return res.status(400).json({ error: 'Invalid shippingFee: Must be a number ≥ 0' });
  }
  if (!gst || isNaN(gst) || gst < 0) {
    return res.status(400).json({ error: 'Invalid GST: Must be a number ≥ 0' });
  }

  let subtotal = 0;
  for (const item of items) {
    if (!item.name || !item.quantity || isNaN(item.price) || item.quantity < 1 || item.price < 0) {
      return res.status(400).json({ error: 'Invalid item: Must include name, quantity (≥1), and price (≥0)' });
    }
    subtotal += item.price * item.quantity;
  }

  // Calculate total including shippingFee and GST
  const calculatedTotal = subtotal + shippingFee + gst;
  const calculatedAmount = Math.round(calculatedTotal * 100);

  if (calculatedAmount !== amount) {
    return res.status(400).json({ error: `Amount mismatch: Expected ${calculatedAmount} paise, received ${amount} paise` });
  }

  const options = {
    amount: amount,
    currency: 'INR',
    receipt: `receipt_order_${Date.now()}`,
  };

  try {
    const order = await razorpay.orders.create(options);
    res.json(order);
  } catch (err) {
    console.error('Razorpay Order Error:', err);
    res.status(500).json({ error: 'Failed to create order', details: err.description || err.message });
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
  } = req.body;
  if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature ||
      !buyerName || !buyerEmail || !buyerPhone || !buyerAddress || !items || !Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ status: 'failed', error: 'Missing required fields' });
  }
  const sanitizedBuyerName = sanitizeHtml(buyerName);
  const sanitizedBuyerEmail = sanitizeHtml(buyerEmail);
  const sanitizedBuyerPhone = sanitizeHtml(buyerPhone);
  const sanitizedBuyerAddress = sanitizeHtml(buyerAddress);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(sanitizedBuyerEmail)) {
    return res.status(400).json({ status: 'failed', error: 'Invalid email address' });
  }
  if (!/^\d{10}$/.test(sanitizedBuyerPhone)) {
    return res.status(400).json({ status: 'failed', error: 'Invalid phone number: Must be 10 digits' });
  }
  const hmac = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET);
  hmac.update(razorpay_order_id + '|' + razorpay_payment_id);
  const generatedSignature = hmac.digest('hex');
  if (generatedSignature !== razorpay_signature) {
    console.error('Payment verification failed: Invalid signature');
    return res.status(400).json({ status: 'failed', message: 'Payment verification failed' });
  }
  try {
    const addressParts = sanitizedBuyerAddress.split(', ');
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
    };
    const order = new Order(orderData);
    await order.save();
    await sendOrderEmail(order);
    return res.json({ status: 'success', message: 'Payment verified, order saved, and email sent!' });
  } catch (error) {
    console.error('Error processing payment:', error.message, error.stack);
    return res.status(500).json({ status: 'failed', error: 'Server error', details: error.message });
  }
});

app.post('/submit-feedback', async (req, res) => {
  const { orderId, paymentId, rating, comment } = req.body;
  try {
    if (!orderId || !paymentId) {
      return res.status(400).json({ error: 'Order ID and Payment ID are required' });
    }
    if (!rating && !comment) {
      return res.status(400).json({ error: 'Rating or comment is required' });
    }
    if (comment && comment.length < 3) {
      return res.status(400).json({ error: 'Comment must be at least 3 characters long' });
    }
    const feedback = new Feedback({
      orderId,
      paymentId,
      rating: rating ? parseInt(rating, 10) : undefined,
      comment: comment ? sanitizeHtml(comment) : undefined,
    });
    await feedback.save();
    res.status(200).json({ message: 'Feedback submitted successfully' });
  } catch (error) {
    console.error('Error saving feedback:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to save feedback', details: error.message });
  }
});

app.get('/get-order', async (req, res) => {
  const { orderId, paymentId } = req.query;
  try {
    if (!orderId || !paymentId) {
      return res.status(400).json({ error: 'Order ID and Payment ID are required' });
    }
    const order = await Order.findOne({
      razorpayOrderId: orderId,
      razorpayPaymentId: paymentId,
    });
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }
    const totalAmount = order.items.reduce((sum, item) => sum + item.productPrice * item.productQuantity, 0) + 1.00;
    const response = {
      id: order.razorpayOrderId,
      paymentId: order.razorpayPaymentId,
      amount: Math.round(totalAmount * 100),
      buyer: {
        name: order.buyerName,
        email: order.buyerEmail,
        phone: order.buyerPhone,
        address: [order.buyerAddress, order.buyerTown, order.buyerPostalCode].filter(Boolean).join(', '),
      },
      items: order.items.map(item => ({
        name: item.productName,
        weight: item.productWeight || '',
        quantity: item.productQuantity,
        price: item.productPrice,
      })),
    };
    res.status(200).json(response);
  } catch (error) {
    console.error('Error fetching order:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to fetch order', details: error.message });
  }
});

async function sendOrderEmail(order) {
  try {
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: 'aromahut24@gmail.com',
        pass: 'zrbh uuok rhqe gyoi',
      },
    });
    const totalAmount = order.items.reduce((sum, item) => sum + item.productPrice * item.productQuantity, 0) + 1.00;
    const itemsHtml = order.items.map(item => `
      <tr>
        <td style="padding: 8px; border: 1px solid #ddd;">${sanitizeHtml(item.productName)}</td>
        <td style="padding: 8px; border: 1px solid #ddd;">${item.productWeight || '-'}</td>
        <td style="padding: 8px; border: 1px solid #ddd;">${item.productQuantity}</td>
        <td style="padding: 8px; border: 1px solid #ddd;">₹${item.productPrice.toFixed(2)}</td>
      </tr>
    `).join('');
    const mailOptions = {
      from: 'aromahut24@gmail.com',
      to: order.buyerEmail,
      subject: 'Thank You for Your Purchase from AromaHut!',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #ddd;">
          <h2 style="color: #ff6b00;">Order Confirmation</h2>
          <p>Dear ${sanitizeHtml(order.buyerName.charAt(0).toUpperCase() + order.buyerName.slice(1))}</p>
          <p>Thank you for shopping with AromaHut! Your order has been successfully placed.</p>
          <h3>Order Details</h3>
          <table style="width: 100%; border-collapse: collapse;">
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
          <p style="margin-top: 20px;"><strong>Total (including ₹1.00 shipping):</strong> ₹${totalAmount.toFixed(2)}</p>
          <h3>Shipping To</h3>
          <p>${sanitizeHtml(order.buyerName.toUpperCase())}</p>
          <p>${sanitizeHtml([order.buyerAddress, order.buyerTown, order.buyerPostalCode].filter(Boolean).join(', ').toUpperCase())}</p>
          <p>We’ll notify you once your order has shipped. For any questions, contact us at aromahut24@gmail.com.</p>
          <p>Best regards,<br>AromaHut Team</p>
        </div>
      `,
    };
    await transporter.sendMail(mailOptions);
  } catch (error) {
    console.error('Email Sending Error:', error.message, error.stack);
    throw error;
  }
}

// New endpoint to download PDF invoice
app.get('/download-invoice/:orderId', authenticateAdmin, async (req, res) => {
  try {
    const order = await Order.findOne({ razorpayOrderId: req.params.orderId });
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }

    const doc = new PDFDocument({ size: 'A4', margin: 50 });
    const filename = `invoice_${order.razorpayOrderId}.pdf`;

    // Set response headers for PDF download
    res.setHeader('Content-disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-type', 'application/pdf');

    // Pipe PDF to response
    doc.pipe(res);

    // Add logo to top-left corner
    const logoPath = path.join(__dirname, 'public', 'img', 'aromahutTitleIcon.png');
    doc.image(logoPath, 50, 50, { width: 80 });

    // Fonts and styling
    doc.font('Helvetica');

    // Seller Information
    doc.fontSize(16).fillColor('#003366').text('Spice World Enterprises', { align: 'center' });
    doc.fontSize(10).fillColor('black');
    doc.text('No. 45, Spice Lane, Salem - 636007, Tamil Nadu, India', { align: 'center' });
    doc.text('GSTIN: 33ABCDE1234F125 | Phone: +91-98765-43210 | Email: sales@spiceworld.com', { align: 'center' });
    doc.moveDown(1);

    // Invoice Title and Details
    doc.fontSize(14).fillColor('#003366').text('INVOICE', { align: 'center' });
    doc.fontSize(10).fillColor('black');
    doc.text(`Invoice No: INV-${order.razorpayOrderId.slice(0, 8)}`, { align: 'left' });
    doc.text(`Date: ${new Date(order.createdAt).toLocaleDateString('en-IN')}`, { align: 'left' });
    doc.moveDown(1);

    // Buyer Information
    doc.fontSize(12).fillColor('black').text('Bill To:', { align: 'left' });
    doc.fontSize(10);
    doc.text(order.buyerName, { align: 'left' });
    doc.text([order.buyerAddress, order.buyerTown, order.buyerPostalCode].filter(Boolean).join(', '), { align: 'left' });
    doc.text(`GSTIN: 33WXYZZ5678K129 | Phone: ${order.buyerPhone}`, { align: 'left' });
    doc.text(`Email: ${order.buyerEmail}`, { align: 'left' });
    doc.moveDown(1);

    // Items Table
    doc.fontSize(12).text('Items:', { align: 'left' });
    doc.fontSize(10);

    // Table header
    const tableTop = doc.y + 10;
    const tableX = 50;
    doc.font('Helvetica-Bold');
    doc.text('Description', tableX, tableTop, { width: 200 });
    doc.text('Weight', tableX + 200, tableTop, { width: 100, align: 'center' });
    doc.text('Quantity', tableX + 300, tableTop, { width: 80, align: 'center' });
    doc.text('Unit Price', tableX + 380, tableTop, { width: 80, align: 'right' });
    doc.text('Total', tableX + 460, tableTop, { width: 80, align: 'right' });
    doc.moveDown(0.5);
    doc.lineWidth(1).moveTo(tableX, doc.y).lineTo(tableX + 540, doc.y).stroke();

    // Table rows
    doc.font('Helvetica');
    let totalAmount = 0;
    order.items.forEach((item, index) => {
      const rowY = doc.y + 10;
      doc.text(item.productName, tableX, rowY, { width: 200 });
      doc.text(item.productWeight || '-', tableX + 200, rowY, { width: 100, align: 'center' });
      doc.text(item.productQuantity.toString(), tableX + 300, rowY, { width: 80, align: 'center' });
      doc.text(`₹${item.productPrice.toFixed(2)}`, tableX + 380, rowY, { width: 80, align: 'right' });
      const itemTotal = item.productPrice * item.productQuantity;
      doc.text(`₹${itemTotal.toFixed(2)}`, tableX + 460, rowY, { width: 80, align: 'right' });
      totalAmount += itemTotal;
      doc.moveDown(0.5);
      doc.lineWidth(0.5).moveTo(tableX, doc.y).lineTo(tableX + 540, doc.y).stroke();
    });

    // Totals
    const subtotalY = doc.y + 10;
    totalAmount += 1.00; // Adding shipping
    doc.text('Subtotal', tableX + 380, subtotalY, { width: 80, align: 'right' });
    doc.text(`₹${(totalAmount - 1).toFixed(2)}`, tableX + 460, subtotalY, { width: 80, align: 'right' });
    doc.moveDown(0.5);
    doc.text('Shipping', tableX + 380, doc.y, { width: 80, align: 'right' });
    doc.text('₹1.00', tableX + 460, doc.y, { width: 80, align: 'right' });
    doc.moveDown(0.5);
    doc.lineWidth(1).moveTo(tableX, doc.y).lineTo(tableX + 540, doc.y).stroke();
    doc.font('Helvetica-Bold');
    doc.text('Total', tableX + 380, doc.y + 10, { width: 80, align: 'right' });
    doc.text(`₹${totalAmount.toFixed(2)}`, tableX + 460, doc.y + 10, { width: 80, align: 'right' });

    // Footer
    doc.moveDown(2);
    doc.fontSize(10).text('Thank you for your business!', { align: 'center' });
    doc.text('For any inquiries, please contact us at sales@spiceworld.com.', { align: 'center' });

    // Finalize PDF
    doc.end();
  } catch (error) {
    console.error('Error generating invoice:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to generate invoice', details: error.message });
  }
});

app.use((err, req, res, next) => {
  console.error('Unhandled Error:', err.message, err.stack);
  res.status(500).json({ error: 'Internal server error', details: err.message });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
