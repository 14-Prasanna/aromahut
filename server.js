require('dotenv').config();

const express = require('express');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const cors = require('cors');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const sanitizeHtml = require('sanitize-html');

const app = express();

// Middleware
app.use(express.json());
app.use(cors({ origin: process.env.FRONTEND_URL || '*' }));
app.use(rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests
}));

// Validate environment variables
const requiredEnvVars = ['MONGO_URI', 'RAZORPAY_KEY_ID', 'RAZORPAY_KEY_SECRET', 'EMAIL_USER', 'EMAIL_PASS'];
const missingEnvVars = requiredEnvVars.filter(varName => !process.env[varName]);
if (missingEnvVars.length) {
  console.error(`❌ Missing environment variables: ${missingEnvVars.join(', ')}`);
  process.exit(1);
}

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, {
  serverSelectionTimeoutMS: 5000,
})
  .then(() => {})
  .catch(err => {
    console.error('❌ MongoDB Connection Error:', err.message);
    process.exit(1);
  });

// Order Schema
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
});
const Order = mongoose.model('Order', orderSchema);

// Feedback Schema
const feedbackSchema = new mongoose.Schema({
  orderId: { type: String, required: true },
  paymentId: { type: String, required: true },
  rating: { type: Number, min: 1, max: 5 },
  comment: { type: String, trim: true, maxlength: 500 },
  createdAt: { type: Date, default: Date.now },
});
const Feedback = mongoose.model('Feedback', feedbackSchema);

// Razorpay Initialization
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// Test Email Endpoint
app.get('/test-email', async (req, res) => {
  try {
    await sendOrderEmail({
      buyerEmail: process.env.EMAIL_USER,
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

// Create Order Endpoint
app.post('/create-order', async (req, res) => {
  const { amount, items } = req.body;

  // Validate request
  if (!amount || isNaN(amount) || amount < 100) {
    return res.status(400).json({ error: 'Invalid amount: Must be a number ≥ ₹1 (100 paise)' });
  }
  if (!items || !Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'Invalid items: Must be a non-empty array' });
  }

  // Validate items
  let calculatedAmount = 0;
  for (const item of items) {
    if (!item.name || !item.quantity || isNaN(item.price) || item.quantity < 1 || item.price < 0) {
      return res.status(400).json({ error: 'Invalid item: Must include name, quantity (≥1), and price (≥0)' });
    }
    calculatedAmount += item.price * item.quantity;
  }
  calculatedAmount += 1.00; // Add shipping cost
  calculatedAmount = Math.round(calculatedAmount * 100); // Convert to paise

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

// Verify Payment and Save Order Endpoint
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

  // Verify Razorpay signature
  const hmac = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET);
  hmac.update(razorpay_order_id + '|' + razorpay_payment_id);
  const generatedSignature = hmac.digest('hex');

  if (generatedSignature !== razorpay_signature) {
    console.error('Payment verification failed: Invalid signature');
    return res.status(400).json({ status: 'failed', message: 'Payment verification failed' });
  }

  try {
    // Parse address
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

    // Validate items
    for (const item of orderData.items) {
      if (!item.productName || isNaN(item.productPrice) || isNaN(item.productQuantity) ||
          item.productPrice < 0 || item.productQuantity < 1) {
        return res.status(400).json({ status: 'failed', error: 'Invalid item data' });
      }
    }

    const order = new Order(orderData);
    await order.save();

    // Send confirmation email
    await sendOrderEmail(order);

    return res.json({ status: 'success', message: 'Payment verified, order saved, and email sent!' });
  } catch (error) {
    console.error('Error processing payment:', error.message, error.stack);
    return res.status(500).json({ status: 'failed', error: 'Server error', details: error.message });
  }
});

// Submit Feedback Endpoint
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

// Get Order Details Endpoint
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

    const totalAmount = order.items.reduce((sum, item) => sum + item.productPrice * item.productQuantity, 0) + 1.00; // Include shipping

    const response = {
      id: order.razorpayOrderId,
      paymentId: order.razorpayPaymentId,
      amount: Math.round(totalAmount * 100), // Convert to paise
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

// Send Order Confirmation Email
async function sendOrderEmail(order) {
  try {
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const totalAmount = order.items.reduce((sum, item) => sum + item.productPrice * item.productQuantity, 0) + 1.00; // Include shipping

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
          <p>We’ll notify you once your order has shipped. For any questions, contact us at ${process.env.EMAIL_USER}.</p>
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

// Error Handling Middleware
app.use((err, req, res, next) => {
  console.error('Unhandled Error:', err.message, err.stack);
  res.status(500).json({ error: 'Internal server error', details: err.message });
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});