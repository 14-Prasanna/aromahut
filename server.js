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
  shippingFee: { type: Number, required: true, default: 0 },
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

// Utility Functions
function calculateShippingFee(items) {
  const totalWeight = items.reduce((sum, item) => {
    // Convert weight to kg if needed (assuming weights are in grams)
    const weight = item.productWeight ? parseFloat(item.productWeight) / 1000 : 0;
    return sum + (weight * item.productQuantity);
  }, 0);

  // Calculate shipping fee: Rs.2 for each 1.1kg range
  return Math.ceil((totalWeight + 0.1) / 1.1) * 2;
}

async function sendOrderEmail(order) {
  try {
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const subtotal = order.items.reduce((sum, item) => sum + item.productPrice * item.productQuantity, 0);
    const totalAmount = subtotal + order.shippingFee;
    
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: order.buyerEmail,
      subject: 'Your AromaHut Order Confirmation',
      html: buildOrderEmailHtml(order, subtotal, order.shippingFee, totalAmount),
    };

    await transporter.sendMail(mailOptions);
  } catch (error) {
    console.error('Email Sending Error:', error);
    throw error;
  }
}

function buildOrderEmailHtml(order, subtotal, shippingFee, totalAmount) {
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
        <tfoot>
          <tr>
            <td colspan="3" style="padding: 8px; border: 1px solid #ddd; text-align: right;">Subtotal:</td>
            <td style="padding: 8px; border: 1px solid #ddd;">₹${subtotal.toFixed(2)}</td>
          </tr>
          <tr>
            <td colspan="3" style="padding: 8px; border: 1px solid #ddd; text-align: right;">Shipping:</td>
            <td style="padding: 8px; border: 1px solid #ddd;">₹${shippingFee.toFixed(2)}</td>
          </tr>
          <tr style="font-weight: bold;">
            <td colspan="3" style="padding: 8px; border: 1px solid #ddd; text-align: right;">Total:</td>
            <td style="padding: 8px; border: 1px solid #ddd;">₹${totalAmount.toFixed(2)}</td>
          </tr>
        </tfoot>
      </table>
      
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

  // Add AromaHut logo
  const logoPath = path.join(__dirname, 'logo.png');
  if (fs.existsSync(logoPath)) {
    doc.image(logoPath, margin + 400, 30, { width: 120, align: 'right' });
  }

  // Header with company details
  doc.fillColor('#4a6baf')
     .fontSize(20)
     .text('AROMAHUT', margin, 30, { align: 'left' })
     .fontSize(10)
     .fillColor('#666666')
     .text('Premium Spices & Herbs', margin, 55)
     .text('45, Spice Lane, Salem - 636007', margin, 70)
     .text('Tamil Nadu, India', margin, 85)
     .text(`GSTIN: ${process.env.GSTIN || '33ABCDE1234F1Z5'}`, margin, 100)
     .moveDown();

  // Invoice Info
  doc.fontSize(14)
     .fillColor('#4a6baf')
     .text('TAX INVOICE', margin + 350, 30, { align: 'right' })
     .fontSize(10)
     .fillColor('#333333')
     .text(`Invoice #: ${order.razorpayOrderId}`, margin + 350, 50, { align: 'right' })
     .text(`Date: ${new Date(order.createdAt).toLocaleDateString('en-IN', {
       day: '2-digit',
       month: 'short',
       year: 'numeric'
     })}`, margin + 350, 65, { align: 'right' })
     .moveDown();

  // Buyer Info
  doc.fontSize(10)
     .fillColor('#333333')
     .text('Bill To:', margin, 140)
     .font('Helvetica-Bold')
     .text(order.buyerName.toUpperCase(), margin, 155)
     .font('Helvetica')
     .text(order.buyerAddress, margin, 170);
  
  if (order.buyerTown || order.buyerPostalCode) {
    doc.text([order.buyerTown, order.buyerPostalCode].filter(Boolean).join(', '), margin, 185);
  }
  doc.text(`Phone: ${order.buyerPhone}`, margin, 200)
     .text(`Email: ${order.buyerEmail}`, margin, 215);

  // Line separator
  doc.moveTo(margin, 240)
     .lineTo(margin + pageWidth, 240)
     .strokeColor('#4a6baf')
     .lineWidth(1)
     .stroke();

  // Items Table
  const tableTop = 260;
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
     .text('Unit Price', priceX, tableTop, { width: 70, align: 'right' })
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

    // Add weight if available
    if (item.productWeight) {
      doc.fontSize(8)
         .fillColor('#666666')
         .text(`(${item.productWeight})`, descriptionX, y + 15);
    }

    itemCount++;
    y += 30;
  });

  // Shipping Line
  doc.fontSize(10)
     .text('Shipping Charges', descriptionX, y)
     .text('1', quantityX, y, { width: 50, align: 'right' })
     .text(`₹${order.shippingFee.toFixed(2)}`, priceX, y, { width: 70, align: 'right' })
     .text(`₹${order.shippingFee.toFixed(2)}`, amountX, y, { width: 80, align: 'right' });

  const totalBeforeTax = subtotal + order.shippingFee;
  y += 40;

  // Total Amount
  doc.fontSize(12)
     .font('Helvetica-Bold')
     .text('Subtotal:', amountX - 50, y, { width: 50, align: 'right' })
     .text(`₹${totalBeforeTax.toFixed(2)}`, amountX, y, { width: 80, align: 'right' });

  // GST Calculation (assuming 5% GST)
  const gstRate = 0.05;
  const gstAmount = totalBeforeTax * gstRate;
  const grandTotal = totalBeforeTax + gstAmount;
  
  y += 20;
  doc.fontSize(10)
     .text(`GST (${gstRate * 100}%):`, amountX - 50, y, { width: 50, align: 'right' })
     .text(`₹${gstAmount.toFixed(2)}`, amountX, y, { width: 80, align: 'right' });

  y += 20;
  doc.fontSize(12)
     .font('Helvetica-Bold')
     .text('Grand Total:', amountX - 50, y, { width: 50, align: 'right' })
     .text(`₹${grandTotal.toFixed(2)}`, amountX, y, { width: 80, align: 'right' });

  // Payment Information
  y += 40;
  doc.fontSize(10)
     .fillColor('#4a6baf')
     .text('Payment Information:', margin, y)
     .fillColor('#333333')
     .text(`Payment ID: ${order.razorpayPaymentId}`, margin, y + 20)
     .text('Payment Method: Online Payment (Razorpay)', margin, y + 35)
     .text('Payment Status: Paid', margin, y + 50);

  // Footer with terms and conditions
  y += 80;
  doc.fontSize(8)
     .fillColor('#4a6baf')
     .text('Terms & Conditions:', margin, y)
     .fillColor('#333333')
     .text('- Payment is due immediately as this is a paid invoice', margin, y + 15)
     .text('- Please retain this invoice for your records', margin, y + 30)
     .text('- All sales are final', margin, y + 45)
     .text('- Thank you for your business!', margin, y + 60);

  // Company Info at Bottom
  doc.fontSize(8)
     .fillColor('#4a6baf')
     .text('AromaHut - Premium Spices and Herbs', margin, doc.page.height - 40)
     .fillColor('#666666')
     .text('www.aromahut.in | Email: contact@aromahut.in | Phone: +91 98765 43210', margin, doc.page.height - 25);

  // Add border around the entire page
  doc.rect(margin - 20, margin - 20, pageWidth + 40, doc.page.height - 80)
     .strokeColor('#4a6baf')
     .lineWidth(0.5)
     .stroke();

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

// ... [Keep all other existing routes the same, just update the verify-payment route below]

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
    shippingFee
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
    const calculatedShippingFee = calculateShippingFee(items);
    
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
      shippingFee: calculatedShippingFee
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

// ... [Keep all other existing routes and the server startup code the same]

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
