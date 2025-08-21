/*
================================================================================
|                                                                              |
|                     Inventory Management System - Backend                      |
|                                                                              |
================================================================================
|
| This file contains the complete backend code for the MERN stack inventory
| management system. It's a single-file representation for clarity, but in a
| real project, you would split this into multiple files and folders (e.g.,
| /models, /routes, /controllers, /services, /middleware).
|
| To Run This Code:
| 1. Make sure you have Node.js and MongoDB installed.
| 2. Save this code as `server.js`.
| 3. In the same directory, run `npm init -y`.
| 4. Install dependencies:
|    npm install express mongoose bcryptjs jsonwebtoken cors dotenv pdfkit socket.io
| 5. Create a `.env` file with the variables mentioned in the setup guide
|    (MONGO_URI, JWT_SECRET, PORT).
| 6. Run `node server.js`.
|
*/

//----------------------------------------------------------------------------//
//                                 1. SETUP                                   //
//----------------------------------------------------------------------------//

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const http = require('http');
const { Server } = require("socket.io");
const PDFDocument = require('pdfkit');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: "*", // In production, restrict this to your frontend's URL
        methods: ["GET", "POST"]
    }
});

// Middleware
app.use(cors());
app.use(express.json());

// Environment Variables
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/inventory_db';
const JWT_SECRET = process.env.JWT_SECRET || 'a_very_secret_key';


//----------------------------------------------------------------------------//
//                              2. DATABASE                                   //
//----------------------------------------------------------------------------//

// Add this line for debugging to see if the URI is loaded
console.log('Attempting to connect to MongoDB...');

mongoose.connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => console.log('MongoDB Connected...'))
.catch(err => {
    // This will print a much more helpful error message
    console.error('MongoDB Connection Error! Please ensure MongoDB is running and your .env file is configured correctly.');
    console.error('Error Details:', err.message);
    process.exit(1); // Exit the process with an error code
});

//----------------------------------------------------------------------------//
//                               3. SCHEMAS                                   //
//----------------------------------------------------------------------------//

// User Schema (For RBAC)
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['admin', 'manager', 'operator'], default: 'operator' }
}, { timestamps: true });

// Product Schema (with embedded variants)
const ProductSchema = new mongoose.Schema({
    productName: { type: String, required: true },
    description: { type: String },
    category: { type: String, required: true, index: true },
    supplier: { type: mongoose.Schema.Types.ObjectId, ref: 'Supplier' },
    barcode: { type: String, unique: true, sparse: true },
    gstRate: { type: Number, required: true },
    hsnCode: { type: String, required: true },
    variants: [{
        sku: { type: String, required: true, unique: true },
        attributes: { type: Object, required: true }, // e.g., { color: 'Black', size: 'L' }
        price: { type: mongoose.Types.Decimal128, required: true },
        stock: {
            quantity: { type: Number, required: true, default: 0 },
            location: { type: String, required: true },
            reorderPoint: { type: Number, required: true, default: 10 },
            lastUpdated: { type: Date, default: Date.now }
        }
    }]
}, { timestamps: true });

// Customer Schema
const CustomerSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, unique: true, sparse: true },
    phone: { type: String },
    whatsappNumber: { type: String, required: true },
    billingAddress: { type: String },
    shippingAddress: { type: String }
}, { timestamps: true });

// Invoice Schema
const InvoiceSchema = new mongoose.Schema({
    invoiceNumber: { type: String, required: true, unique: true },
    customer: { type: mongoose.Schema.Types.ObjectId, ref: 'Customer', required: true },
    lineItems: [{
        product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
        variantSku: { type: String },
        productName: { type: String },
        quantity: { type: Number },
        price: { type: mongoose.Types.Decimal128 },
        gstRate: { type: Number },
        hsnCode: { type: String }
    }],
    totalAmount: { type: mongoose.Types.Decimal128 },
    gstDetails: {
        cgst: { type: mongoose.Types.Decimal128 },
        sgst: { type: mongoose.Types.Decimal128 },
        igst: { type: mongoose.Types.Decimal128 }
    },
    paymentStatus: { type: String, enum: ['paid', 'unpaid'], default: 'unpaid' },
    pdfUrl: { type: String }, // Link to PDF stored in S3
    whatsappStatus: { type: String, enum: ['pending', 'sent', 'delivered', 'read', 'failed'], default: 'pending' },
    messageSid: { type: String } // To track message status from BSP
}, { timestamps: true });

// Audit log for inventory changes
const InventoryTransactionSchema = new mongoose.Schema({
    product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
    variantSku: { type: String, required: true },
    type: { type: String, enum: ['SALE', 'RETURN', 'ADJUSTMENT', 'RECEIPT'], required: true },
    quantityChange: { type: Number, required: true },
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // User who performed the action
    notes: { type: String }
}, { timestamps: true });


const User = mongoose.model('User', UserSchema);
const Product = mongoose.model('Product', ProductSchema);
const Customer = mongoose.model('Customer', CustomerSchema);
const Invoice = mongoose.model('Invoice', InvoiceSchema);
const InventoryTransaction = mongoose.model('InventoryTransaction', InventoryTransactionSchema);


//----------------------------------------------------------------------------//
//                       4. MIDDLEWARE (AUTH & RBAC)                          //
//----------------------------------------------------------------------------//

const auth = (req, res, next) => {
    const token = req.header('x-auth-token');
    if (!token) return res.status(401).json({ msg: 'No token, authorization denied' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded.user;
        next();
    } catch (err) {
        res.status(401).json({ msg: 'Token is not valid' });
    }
};

const ROLES = {
    admin: ['products:create', 'products:read', 'products:update', 'products:delete', 'users:manage', 'invoices:read_all'],
    manager: ['products:create', 'products:read', 'products:update', 'invoices:read_all'],
    operator: ['products:read', 'invoices:create', 'invoices:read_own']
};

const authorize = (requiredPermissions) => (req, res, next) => {
    const userRole = req.user.role;
    const userPermissions = ROLES[userRole];

    const hasPermission = requiredPermissions.every(p => userPermissions.includes(p));

    if (!hasPermission) {
        return res.status(403).json({ msg: 'Forbidden: You do not have the required permissions.' });
    }
    next();
};


//----------------------------------------------------------------------------//
//                         5. MOCK SERVICES                                   //
//----------------------------------------------------------------------------//

// Mock S3 Service
const s3Service = {
    upload: async (pdfBuffer, fileName) => {
        console.log(`[Mock S3] Uploading ${fileName}...`);
        // In a real app, this would use the AWS SDK to upload the buffer to S3
        const mockUrl = `https://mock-s3-bucket.s3.amazonaws.com/invoices/${fileName}`;
        console.log(`[Mock S3] File available at ${mockUrl}`);
        return mockUrl;
    }
};

// Mock WhatsApp Service (360dialog)
const whatsappService = {
    sendMessage: async (to, message, invoiceId) => {
        console.log(`[Mock WhatsApp] Preparing to send message to ${to}`);
        console.log(`[Mock WhatsApp] Message: ${message}`);
        const mockMessageSid = `WH_SID_${Date.now()}`;
        // In a real app, this would make an API call to the BSP
        // On success, we would update the invoice status
        await Invoice.findByIdAndUpdate(invoiceId, { whatsappStatus: 'sent', messageSid: mockMessageSid });
        io.emit('invoice_status_update', { invoiceId, status: 'sent' });
        console.log(`[Mock WhatsApp] Message sent successfully. SID: ${mockMessageSid}`);
        
        // Simulate delivery/read receipts
        setTimeout(() => {
            Invoice.findOneAndUpdate({_id: invoiceId, whatsappStatus: 'sent'}, { whatsappStatus: 'delivered' }).then(inv => {
                if(inv) {
                    io.emit('invoice_status_update', { invoiceId, status: 'delivered' });
                    console.log(`[Mock WhatsApp] Message SID ${mockMessageSid} delivered.`);
                }
            });
        }, 5000); // 5 seconds later
        setTimeout(() => {
             Invoice.findOneAndUpdate({_id: invoiceId, whatsappStatus: 'delivered'}, { whatsappStatus: 'read' }).then(inv => {
                if(inv) {
                    io.emit('invoice_status_update', { invoiceId, status: 'read' });
                    console.log(`[Mock WhatsApp] Message SID ${mockMessageSid} read.`);
                }
            });
        }, 10000); // 10 seconds later
        
        return { success: true, sid: mockMessageSid };
    }
};


//----------------------------------------------------------------------------//
//                  6. PDF INVOICE GENERATION SERVICE                         //
//----------------------------------------------------------------------------//

const invoiceService = {
    generatePdf: (invoiceData) => {
        return new Promise((resolve, reject) => {
            const doc = new PDFDocument({ margin: 50 });
            const buffers = [];
            doc.on('data', buffers.push.bind(buffers));
            doc.on('end', () => {
                const pdfData = Buffer.concat(buffers);
                resolve(pdfData);
            });
            doc.on('error', reject);

            // --- PDF Content ---
            doc.fontSize(20).text('Tax Invoice', { align: 'center' });
            doc.moveDown();

            // Company & Customer Details
            doc.fontSize(12).text('Your Company Inc.', { align: 'left' });
            doc.text('123 Business Rd, Business City, 12345');
            doc.text(`GSTIN: YOUR_GST_NUMBER`);
            
            doc.text(`Invoice #: ${invoiceData.invoiceNumber}`, { align: 'right' });
            doc.text(`Date: ${new Date(invoiceData.createdAt).toLocaleDateString()}`, { align: 'right' });
            
            doc.moveDown(2);
            doc.text('Bill To:');
            doc.text(invoiceData.customer.name);
            doc.text(invoiceData.customer.billingAddress);
            doc.text(`WhatsApp: ${invoiceData.customer.whatsappNumber}`);
            doc.moveDown(2);

            // Table Header
            const tableTop = doc.y;
            doc.font('Helvetica-Bold');
            doc.text('Item', 50, tableTop);
            doc.text('HSN', 150, tableTop);
            doc.text('Qty', 250, tableTop, { width: 50, align: 'right' });
            doc.text('Rate', 300, tableTop, { width: 70, align: 'right' });
            doc.text('Amount', 370, tableTop, { width: 90, align: 'right' });
            doc.font('Helvetica');
            doc.y += 20;

            // Table Rows
            let total = 0;
            invoiceData.lineItems.forEach(item => {
                const itemY = doc.y;
                doc.text(item.productName, 50, itemY, { width: 100 });
                doc.text(item.hsnCode, 150, itemY, { width: 100 });
                doc.text(item.quantity.toString(), 250, itemY, { width: 50, align: 'right' });
                doc.text(parseFloat(item.price).toFixed(2), 300, itemY, { width: 70, align: 'right' });
                const amount = item.quantity * parseFloat(item.price);
                doc.text(amount.toFixed(2), 370, itemY, { width: 90, align: 'right' });
                total += amount;
                doc.y += 20;
            });
            
            // Totals
            doc.font('Helvetica-Bold');
            doc.text(`Subtotal: ${total.toFixed(2)}`, { align: 'right' });
            doc.text(`CGST: ${parseFloat(invoiceData.gstDetails.cgst).toFixed(2)}`, { align: 'right' });
            doc.text(`SGST: ${parseFloat(invoiceData.gstDetails.sgst).toFixed(2)}`, { align: 'right' });
            doc.text(`Total: ${parseFloat(invoiceData.totalAmount).toFixed(2)}`, { align: 'right' });
            doc.font('Helvetica');
            
            doc.end();
        });
    }
};


//----------------------------------------------------------------------------//
//                                7. ROUTES                                   //
//----------------------------------------------------------------------------//

// --- Auth Routes ---
app.post('/api/auth/register', async (req, res) => {
    const { username, password, role } = req.body;
    try {
        let user = await User.findOne({ username });
        if (user) return res.status(400).json({ msg: 'User already exists' });

        user = new User({ username, password, role });
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);
        await user.save();

        const payload = { user: { id: user.id, role: user.role } };
        jwt.sign(payload, JWT_SECRET, { expiresIn: '5h' }, (err, token) => {
            if (err) throw err;
            res.json({ token });
        });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        let user = await User.findOne({ username });
        if (!user) return res.status(400).json({ msg: 'Invalid credentials' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ msg: 'Invalid credentials' });

        const payload = { user: { id: user.id, role: user.role } };
        jwt.sign(payload, JWT_SECRET, { expiresIn: '5h' }, (err, token) => {
            if (err) throw err;
            res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
        });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

app.get('/api/auth/user', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.json(user);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});


// --- Product Routes ---
app.get('/api/products', auth, async (req, res) => {
    try {
        const products = await Product.find();
        res.json(products);
    } catch (err) {
        res.status(500).json({ msg: 'Server error' });
    }
});

app.post('/api/products', auth, authorize(['products:create']), async (req, res) => {
    try {
        const newProduct = new Product(req.body);
        const product = await newProduct.save();
        res.json(product);
    } catch (err) {
        res.status(500).json({ msg: 'Server error', error: err.message });
    }
});

// --- Invoice Routes ---
app.get('/api/invoices', auth, authorize(['invoices:read_all']), async (req, res) => {
    try {
        const invoices = await Invoice.find().populate('customer').sort({ createdAt: -1 });
        res.json(invoices);
    } catch (err) {
        res.status(500).json({ msg: 'Server error' });
    }
});

app.post('/api/invoices', auth, authorize(['invoices:create']), async (req, res) => {
    const { customerId, lineItems, paymentStatus } = req.body; // lineItems: [{variantSku, quantity}]

    const session = await mongoose.startSession();
    session.startTransaction();

    try {
        let totalAmount = 0;
        let totalGst = { cgst: 0, sgst: 0, igst: 0 };
        const populatedLineItems = [];

        for (const item of lineItems) {
            const product = await Product.findOne({ "variants.sku": item.variantSku }).session(session);
            if (!product) throw new Error(`Product with SKU ${item.variantSku} not found.`);

            const variant = product.variants.find(v => v.sku === item.variantSku);
            if (variant.stock.quantity < item.quantity) {
                throw new Error(`Not enough stock for SKU ${item.variantSku}. Available: ${variant.stock.quantity}`);
            }

            // Atomically update stock
            const updateResult = await Product.updateOne(
                { "variants.sku": item.variantSku, "variants.stock.quantity": { $gte: item.quantity } },
                { 
                    $inc: { "variants.$.stock.quantity": -item.quantity },
                    $set: { "variants.$.stock.lastUpdated": new Date() }
                },
                { session }
            );

            if (updateResult.modifiedCount === 0) {
                 throw new Error(`Stock update failed for ${item.variantSku}. Race condition or insufficient stock.`);
            }
            
            // Create audit log
            await InventoryTransaction.create([{
                product: product._id,
                variantSku: item.variantSku,
                type: 'SALE',
                quantityChange: -item.quantity,
                user: req.user.id
            }], { session });

            // Check for low stock alert
            const updatedProduct = await Product.findOne({ "variants.sku": item.variantSku }).session(session);
            const updatedVariant = updatedProduct.variants.find(v => v.sku === item.variantSku);
            if(updatedVariant.stock.quantity <= updatedVariant.stock.reorderPoint) {
                console.log(`[Alert] Low stock for ${product.productName} - ${variant.sku}. Current: ${updatedVariant.stock.quantity}`);
                io.emit('low_stock_alert', { 
                    productName: product.productName,
                    sku: variant.sku,
                    quantity: updatedVariant.stock.quantity,
                    reorderPoint: updatedVariant.stock.reorderPoint
                });
            }

            const price = parseFloat(variant.price.toString());
            const itemTotal = price * item.quantity;
            totalAmount += itemTotal;
            
            // Assuming CGST/SGST for simplicity
            const gstAmount = itemTotal * (variant.gstRate / 100);
            totalGst.cgst += gstAmount / 2;
            totalGst.sgst += gstAmount / 2;

            populatedLineItems.push({
                product: product._id,
                variantSku: variant.sku,
                productName: `${product.productName} (${Object.values(variant.attributes).join(', ')})`,
                quantity: item.quantity,
                price: variant.price,
                gstRate: variant.gstRate,
                hsnCode: product.hsnCode
            });
        }
        
        const finalTotal = totalAmount + totalGst.cgst + totalGst.sgst + totalGst.igst;

        const newInvoice = new Invoice({
            invoiceNumber: `INV-${Date.now()}`,
            customer: customerId,
            lineItems: populatedLineItems,
            totalAmount: finalTotal.toFixed(2),
            gstDetails: {
                cgst: totalGst.cgst.toFixed(2),
                sgst: totalGst.sgst.toFixed(2),
                igst: totalGst.igst.toFixed(2)
            },
            paymentStatus,
        });

        const savedInvoice = await newInvoice.save({ session });
        
        // Populate customer for PDF generation
        await savedInvoice.populate('customer');

        // Generate and "upload" PDF
        const pdfBuffer = await invoiceService.generatePdf(savedInvoice);
        const pdfUrl = await s3Service.upload(pdfBuffer, `${savedInvoice.invoiceNumber}.pdf`);
        
        savedInvoice.pdfUrl = pdfUrl;
        await savedInvoice.save({ session });

        await session.commitTransaction();

        // Send WhatsApp notification after transaction is committed
        const message = `Dear ${savedInvoice.customer.name}, your invoice #${savedInvoice.invoiceNumber} is ready. View it here: ${pdfUrl}`;
        await whatsappService.sendMessage(savedInvoice.customer.whatsappNumber, message, savedInvoice._id);

        res.status(201).json(savedInvoice);

    } catch (err) {
        await session.abortTransaction();
        console.error(err);
        res.status(400).json({ msg: err.message });
    } finally {
        session.endSession();
    }
});


// --- Customer Routes ---
app.get('/api/customers', auth, async (req, res) => {
    try {
        const customers = await Customer.find();
        res.json(customers);
    } catch (err) {
        res.status(500).json({ msg: 'Server error' });
    }
});

app.post('/api/customers', auth, async (req, res) => {
    try {
        const newCustomer = new Customer(req.body);
        const customer = await newCustomer.save();
        res.json(customer);
    } catch (err) {
        res.status(500).json({ msg: 'Server error' });
    }
});


//----------------------------------------------------------------------------//
//                         8. WEBSOCKETS & SERVER START                       //
//----------------------------------------------------------------------------//

io.on('connection', (socket) => {
    console.log('A user connected to WebSocket:', socket.id);
    socket.on('disconnect', () => {
        console.log('User disconnected:', socket.id);
    });
});

server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
