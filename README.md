# 🛍️ Aromahut – Premium Aroma Products Webstore

**Aromahut** is a multi-page, fully responsive e-commerce website built for selling aroma products such as candles, essential oils, and incense. It integrates invoice generation, email notifications, and secure payment via Razorpay. The backend is powered by Node.js and hosted on Render, while the frontend is deployed on a `.in` domain.

---

## 🌟 Key Features

- 🛒 **Multi-Page E-commerce Flow** – `index.html`, `cart.html`, `checkout.html`, `about.html`, etc.
- 🧾 **PDF Invoice Download** – Auto-generated invoice using Node + HTML-to-PDF libraries
- 📧 **Email Notifications** – Order summary sent via **Nodemailer**
- 💳 **Razorpay Integration** – Seamless, secure payments on checkout
- 💻 **Responsive UI** – Built with **Bootstrap** for consistent mobile & desktop experience
- 🌐 **Live on Custom Domain** – Hosted with `.in` domain and Render backend

---

## 🧠 Tech Stack

| Layer        | Tech                          |
|--------------|-------------------------------|
| Frontend     | HTML, CSS, Bootstrap, JS      |
| Backend      | Node.js, Express.js           |
| Styling      | SCSS, Bootstrap               |
| Payment      | Razorpay API                  |
| Emails       | Nodemailer                    |
| Deployment   | Frontend on Netlify / GitHub Pages / Custom `.in` domain <br> Backend on Render |
| Invoice Gen. | PDFKit or html-pdf (Node lib) |

---

## 📂 Folder Structure

```bash
aromahut/
├── css/               # Stylesheets
├── img/               # Product & UI images
├── js/                # Frontend scripts
├── lib/               # Razorpay or invoice libraries
├── node_modules/      # Node dependencies
├── scss/              # SCSS source files
├── .env               # API keys (ignored in Git)
├── .gitignore
├── 404.html           # Custom error page
├── about.html
├── cart.html
├── checkout.html
├── greetings.html
├── index.html
├── CNAME              # Custom domain config
├── server.js          # Express backend with Razorpay, Nodemailer
├── package.json
└── README.md
```

🚀** Run Locally**
Frontend:
# Open in browser (no build needed)
    1. index.html

Backend:
# Install dependencies
    1. npm install
# Start server
    2. node server.js

**🎯 Project Purpose **
This project showcases:

My ability to build real-world, full-stack applications

Integration of payment APIs, PDF generation, and email logic

Clean frontend design and performance-optimized HTML

# 🙋‍♂️ Developed By 
---
# Prasanna Venkatesh K
# Mohan Raj S
---
# Frontend Web Developer | Passionate about clean code & real-world use cases
https://prasannavenkateshportfolio14.netlify.app/
https://mohanxz.github.io/
