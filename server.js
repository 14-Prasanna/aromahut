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

// Database Connection
mongoose.connect(process.env.MONGO_URI, {
  serverSelectionTimeoutMS: 5000,
})
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => {
    console.error('❌ MongoDB Connection Error:', err.message);
    process.exit(1);
  });

// Schemas and Models
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

// Razorpay Configuration
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// Authentication Middleware
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

// Socket.io Connection
io.on('connection', (socket) => {
  console.log('✅ Client connected:', socket.id);
  socket.on('disconnect', () => {
    console.log('❌ Client disconnected:', socket.id);
  });
});

// Utility Functions
async function sendOrderEmail(order) {
  try {
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const totalAmount = order.items.reduce((sum, item) => sum + item.productPrice * item.productQuantity, 0) + 1.00;
    
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: order.buyerEmail,
      subject: 'Your AromaHut Order Confirmation',
      html: buildOrderEmailHtml(order, totalAmount),
    };

    await transporter.sendMail(mailOptions);
  } catch (error) {
    console.error('Email Sending Error:', error);
    throw error;
  }
}

function buildOrderEmailHtml(order, totalAmount) {
  const itemsHtml = order.items.map(item => `
    <tr>
      <td style="padding: 8px; border: 1px solid #ddd;">${sanitizeHtml(item.productName)}</td>
      <td style="padding: 8px; border: 1px solid #ddd;">${item.productWeight || '-'}</td>
      <td style="padding: 8px; border: 1px solid #ddd;">${item.productQuantity}</td>
      <td style="padding: 8px; border: 1px solid #ddd;">₹${item.productPrice.toFixed(2)}</td>
    </tr>
  `).join('');

  return `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #ddd; border-radius: 5px;">
      <h2 style="color: #4a6baf; text-align: center;">Order Confirmation</h2>
      <p>Dear ${sanitizeHtml(order.buyerName)},</p>
      <p>Thank you for your order from AromaHut! We're preparing your items and will notify you when they ship.</p>
      
      <h3 style="color: #4a6baf; margin-top: 20px;">Order Details</h3>
      <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px;">
        <thead>
          <tr style="background-color: #f8f9fa;">
            <th style="padding: 8px; border: 1px solid #ddd; text-align: left;">Product</th>
            <th style="padding: 8px; border: 1px solid #ddd; text-align: left;">Weight</th>
            <th style="padding: 8px; border: 1px solid #ddd; text-align: left;">Quantity</th>
            <th style="padding: 8px; border: 1px solid #ddd; text-align: left;">Price</th>
          </tr>
        </thead>
        <tbody>
          ${itemsHtml}
        </tbody>
      </table>
      
      <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px;">
        <p style="margin: 0; font-weight: bold;">Order Total: ₹${totalAmount.toFixed(2)}</p>
      </div>
      
      <h3 style="color: #4a6baf;">Shipping Information</h3>
      <p>${sanitizeHtml(order.buyerName)}<br>
      ${sanitizeHtml([order.buyerAddress, order.buyerTown, order.buyerPostalCode].filter(Boolean).join(', '))}</p>
      
      <p style="margin-top: 30px;">We appreciate your business! If you have any questions, please contact us at ${process.env.EMAIL_USER}.</p>
      
      <p style="margin-top: 20px; font-size: 0.9em; color: #6c757d;">Order ID: ${order.razorpayOrderId}<br>
      Payment ID: ${order.razorpayPaymentId}</p>
    </div>
  `;
}

async function generateProfessionalInvoice(order, res) {
  const doc = new PDFDocument({ size: 'A4', margin: 40 });
  const filename = `AromaHut_Invoice_${order.razorpayOrderId}.pdf`;
  
  res.setHeader('Content-disposition', `attachment; filename="${filename}"`);
  res.setHeader('Content-type', 'application/pdf');
  doc.pipe(res);

  // Constants
  const pageWidth = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const margin = doc.page.margins.left;
  const tableWidth = pageWidth;

  // 1. Header
  doc.fillColor('#4a6baf')
     .fontSize(20)
     .text('AromaHut', margin, 30, { align: 'left' })
     .fontSize(10)
     .fillColor('#666666')
     .text('Premium Spices & Herbs', margin, 55)
     .moveDown();

  // Invoice Info
  doc.fontSize(14)
     .fillColor('#4a6baf')
     .text('TAX INVOICE', margin + 350, 30, { align: 'right' })
     .fontSize(10)
     .fillColor('#333333')
     .text(`Invoice #: ${order.razorpayOrderId}`, margin + 350, 50, { align: 'right' })
     .text(`Date: ${new Date(order.createdAt).toLocaleDateString('en-IN')}`, margin + 350, 65, { align: 'right' })
     .moveDown();

  // 2. Seller and Buyer Info
  doc.fontSize(10)
     .fillColor('#333333')
     .text('From:', margin, 100)
     .text('AromaHut (Spice World Enterprises)', margin, 115)
     .text('45, Spice Lane, Salem - 636007', margin, 130)
     .text('Tamil Nadu, India', margin, 145)
     .text('GSTIN: 33ABCDE1234F1Z5', margin, 160)
     .text('Phone: +91 98765 43210', margin, 175)
     .text(`Email: ${process.env.EMAIL_USER}`, margin, 190);

  doc.text('Bill To:', margin + 300, 100)
     .text(order.buyerName.toUpperCase(), margin + 300, 115)
     .text(order.buyerAddress, margin + 300, 130);
  
  if (order.buyerTown || order.buyerPostalCode) {
    doc.text([order.buyerTown, order.buyerPostalCode].filter(Boolean).join(', '), margin + 300, 145);
  }
  doc.text(`Phone: ${order.buyerPhone}`, margin + 300, 160)
     .text(`Email: ${order.buyerEmail}`, margin + 300, 175);

  // Line separator
  doc.moveTo(margin, 220)
     .lineTo(margin + pageWidth, 220)
     .strokeColor('#cccccc')
     .stroke();

  // 3. Items Table
  const tableTop = 240;
  const itemCodeX = margin;
  const descriptionX = margin + 50;
  const quantityX = margin + 300;
  const priceX = margin + 350;
  const amountX = margin + 420;

  // Table Header
  doc.fontSize(10)
     .font('Helvetica-Bold')
     .fillColor('#ffffff')
     .rect(margin, tableTop - 10, pageWidth, 20)
     .fill('#4a6baf')
     .text('No.', itemCodeX, tableTop)
     .text('Description', descriptionX, tableTop)
     .text('Qty', quantityX, tableTop, { width: 50, align: 'right' })
     .text('Price', priceX, tableTop, { width: 70, align: 'right' })
     .text('Amount', amountX, tableTop, { width: 80, align: 'right' })
     .moveTo(margin, tableTop + 20)
     .lineTo(margin + pageWidth, tableTop + 20)
     .stroke();

  // Table Rows
  let y = tableTop + 30;
  let itemCount = 1;
  let subtotal = 0;

  order.items.forEach(item => {
    const itemTotal = item.productPrice * item.productQuantity;
    subtotal += itemTotal;

    doc.fontSize(10)
       .font('Helvetica')
       .fillColor('#333333')
       .text(itemCount.toString(), itemCodeX, y)
       .text(item.productName, descriptionX, y)
       .text(item.productQuantity.toString(), quantityX, y, { width: 50, align: 'right' })
       .text(`₹${item.productPrice.toFixed(2)}`, priceX, y, { width: 70, align: 'right' })
       .text(`₹${itemTotal.toFixed(2)}`, amountX, y, { width: 80, align: 'right' });

    itemCount++;
    y += 25;
  });

  // Shipping Line
  doc.fontSize(10)
     .text('Shipping', descriptionX, y)
     .text('1', quantityX, y, { width: 50, align: 'right' })
     .text('₹1.00', priceX, y, { width: 70, align: 'right' })
     .text('₹1.00', amountX, y, { width: 80, align: 'right' });

  subtotal += 1.00; // Add shipping
  y += 30;

  // Total Amount
  doc.fontSize(12)
     .font('Helvetica-Bold')
     .text('Total:', amountX - 50, y, { width: 50, align: 'right' })
     .text(`₹${subtotal.toFixed(2)}`, amountX, y, { width: 80, align: 'right' });

  // 4. Payment Information
  y += 40;
  doc.fontSize(10)
     .text('Payment Information:', margin, y)
     .text(`Payment ID: ${order.razorpayPaymentId}`, margin, y + 20)
     .text('Payment Method: Online Payment (Razorpay)', margin, y + 35)
     .text('Payment Status: Paid', margin, y + 50);

  // 5. Footer
  y += 80;
  doc.fontSize(8)
     .text('Terms & Conditions:', margin, y)
     .text('- Payment is due immediately as this is a paid invoice', margin, y + 15)
     .text('- Please retain this invoice for your records', margin, y + 30)
     .text('- All sales are final', margin, y + 45)
     .text('- Thank you for your business!', margin, y + 60);

  // Company Info at Bottom
  doc.fontSize(8)
     .text('AromaHut - Premium Spices and Herbs', margin, doc.page.height - 40)
     .text('www.aromahut.in | Email: contact@aromahut.in', margin, doc.page.height - 25);

  doc.end();
}

// Routes
app.post('/admin/login', (req, res) => {
  const { username, password } = req.body;
  if (username === process.env.ADMIN_USER && password === process.env.ADMIN_PASS) {
    const token = jwt.sign({ isAdmin: true }, process.env.JWT_SECRET, { expiresIn: '1h' });
    return res.json({ status: 'success', token });
  }
  res.status(401).json({ error: 'Invalid credentials' });
});

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
    const orders = await Order.find(query).sort({ createdAt: -1 }).lean();
    res.status(200).json({ status: 'success', data: orders });
  } catch (error) {
    console.error('Error fetching orders:', error);
    res.status(500).json({ error: 'Failed to fetch orders', details: error.message });
  }
});

app.post('/admin/order-status', authenticateAdmin, async (req, res) => {
  const { orderId, step, completed } = req.body;
  if (!orderId || !step || typeof completed !== 'boolean') {
    return res.status(400).json({ error: 'Missing required fields' });
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
    console.error('Error updating order status:', error);
    res.status(500).json({ error: 'Failed to update order status', details: error.message });
  }
});

app.get('/admin/order/:id', authenticateAdmin, async (req, res) => {
  try {
    const order = await Order.findOne({ razorpayOrderId: req.params.id }).lean();
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }
    res.status(200).json({ status: 'success', data: order });
  } catch (error) {
    console.error('Error fetching order:', error);
    res.status(500).json({ error: 'Failed to fetch order', details: error.message });
  }
});

app.get('/admin/products', authenticateAdmin, async (req, res) => {
  try {
    const products = await Product.find().sort({ updatedAt: -1 }).lean();
    res.status(200).json({ status: 'success', data: products });
  } catch (error) {
    console.error('Error fetching products:', error);
    res.status(500).json({ error: 'Failed to fetch products', details: error.message });
  }
});

app.get('/download-invoice/:orderId', authenticateAdmin, async (req, res) => {
  try {
    const order = await Order.findOne({ razorpayOrderId: req.params.orderId });
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }
    await generateProfessionalInvoice(order, res);
  } catch (error) {
    console.error('Error generating invoice:', error);
    res.status(500).json({ error: 'Failed to generate invoice', details: error.message });
  }
});

app.post('/create-order', async (req, res) => {
  const { amount, items } = req.body;
  if (!amount || isNaN(amount) || amount < 100) {
    return res.status(400).json({ error: 'Invalid amount: Must be a number ≥ ₹1 (100 paise)' });
  }
  if (!items || !Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'Invalid items: Must be a non-empty array' });
  }
  
  let calculatedAmount = 0;
  for (const item of items) {
    if (!item.name || !item.quantity || isNaN(item.price) || item.quantity < 1 || item.price < 0) {
      return res.status(400).json({ error: 'Invalid item: Must include name, quantity (≥1), and price (≥0)' });
    }
    calculatedAmount += item.price * item.quantity;
  }
  
  calculatedAmount += 1.00;
  calculatedAmount = Math.round(calculatedAmount * 100);
  
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
    console.error('Error processing payment:', error);
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
    console.error('Error saving feedback:', error);
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
    console.error('Error fetching order:', error);
    res.status(500).json({ error: 'Failed to fetch order', details: error.message });
  }
});

// Error Handling Middleware
app.use((err, req, res, next) => {
  console.error('Unhandled Error:', err);
  res.status(500).json({ error: 'Internal server error', details: err.message });
});

// Server Startup
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
