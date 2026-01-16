const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = 'limpa_mais_secret_key'; // Substitua por uma chave segura em produção

// Middleware
app.use(cors());
app.use(express.json());

// Conexão com o MongoDB
mongoose.connect('mongodb://localhost:27017/limpa_mais_db', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('MongoDB conectado'))
.catch(err => console.error('Erro ao conectar ao MongoDB:', err));

// Definição dos Schemas e Models
const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  role: { type: String, enum: ['auxiliar', 'operador', 'manipulador', 'motorista'], required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const ProductSchema = new mongoose.Schema({
  name: { type: String, required: true },
  type: { type: String, enum: ['materia_prima', 'insumo', 'produto_acabado'], required: true },
  capacity: { type: String }, // ex: 500ml, 1L
  unit: { type: String, required: true }, // ex: un, litro
  currentStock: { type: Number, default: 0 },
  minStock: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

const DeliverySchema = new mongoose.Schema({
  productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
  type: { type: String, enum: ['saida', 'entrada', 'producao_entrada', 'producao_saida'], required: true },
  quantity: { type: Number, required: true },
  description: { type: String },
  date: { type: Date, default: Date.now },
  previousStock: { type: Number, required: true },
  currentStock: { type: Number, required: true }
});

const OrderSchema = new mongoose.Schema({
  productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
  quantity: { type: Number, required: true },
  produced: { type: Number, default: 0 },
  status: { type: String, enum: ['pendente', 'em_producao', 'concluida', 'cancelada'], default: 'pendente' },
  dueDate: { type: Date, required: true },
  createdAt: { type: Date, default: Date.now }
});

const SaleSchema = new mongoose.Schema({
  productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
  quantity: { type: Number, required: true },
  customer: { type: String },
  date: { type: Date, default: Date.now },
  total: { type: String, required: true }
});

const User = mongoose.model('User', UserSchema);
const Product = mongoose.model('Product', ProductSchema);
const Delivery = mongoose.model('Delivery', DeliverySchema);
const Order = mongoose.model('Order', OrderSchema);
const Sale = mongoose.model('Sale', SaleSchema);

// Middleware de autenticação
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Acesso negado' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Token inválido' });
    }
    req.user = user;
    next();
  });
};

// Rotas de Autenticação
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, role, email, password } = req.body;

    // Validação de senha
    if (!/^[A-Za-z0-9]{6,}$/.test(password)) {
      return res.status(400).json({ message: 'A senha deve ter no mínimo 6 caracteres e conter apenas números ou letras.' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email já cadastrado' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ name, role, email, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: 'Usuário registrado com sucesso!' });
  } catch (error) {
    res.status(500).json({ message: 'Erro ao registrar usuário', error: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Credenciais inválidas' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Credenciais inválidas' });
    }

    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, user: { id: user._id, name: user.name, role: user.role, email: user.email } });
  } catch (error) {
    res.status(500).json({ message: 'Erro ao fazer login', error: error.message });
  }
});

// Rotas Protegidas - Produtos
app.get('/api/products', authenticateToken, async (req, res) => {
  try {
    const products = await Product.find();
    res.json(products);
  } catch (error) {
    res.status(500).json({ message: 'Erro ao buscar produtos', error: error.message });
  }
});

app.post('/api/products', authenticateToken, async (req, res) => {
  try {
    const product = new Product(req.body);
    await product.save();
    res.status(201).json(product);
  } catch (error) {
    res.status(500).json({ message: 'Erro ao criar produto', error: error.message });
  }
});

app.put('/api/products/:id', authenticateToken, async (req, res) => {
  try {
    const product = await Product.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!product) {
      return res.status(404).json({ message: 'Produto não encontrado' });
    }
    res.json(product);
  } catch (error) {
    res.status(500).json({ message: 'Erro ao atualizar produto', error: error.message });
  }
});

app.delete('/api/products/:id', authenticateToken, async (req, res) => {
  try {
    const product = await Product.findByIdAndDelete(req.params.id);
    if (!product) {
      return res.status(404).json({ message: 'Produto não encontrado' });
    }
    res.json({ message: 'Produto excluído com sucesso' });
  } catch (error) {
    res.status(500).json({ message: 'Erro ao excluir produto', error: error.message });
  }
});

// Rotas Protegidas - Entregas
app.get('/api/deliveries', authenticateToken, async (req, res) => {
  try {
    const deliveries = await Delivery.find().populate('productId');
    res.json(deliveries);
  } catch (error) {
    res.status(500).json({ message: 'Erro ao buscar entregas', error: error.message });
  }
});

app.post('/api/deliveries', authenticateToken, async (req, res) => {
  try {
    const delivery = new Delivery(req.body);
    await delivery.save();

    // Atualizar estoque do produto
    const product = await Product.findById(delivery.productId);
    if (product) {
      if (['entrada', 'producao_entrada'].includes(delivery.type)) {
        product.currentStock += delivery.quantity;
      } else if (['saida', 'producao_saida'].includes(delivery.type)) {
        product.currentStock -= delivery.quantity;
      }
      await product.save();
    }

    res.status(201).json(delivery);
  } catch (error) {
    res.status(500).json({ message: 'Erro ao registrar entrega', error: error.message });
  }
});

// Rotas Protegidas - Ordens
app.get('/api/orders', authenticateToken, async (req, res) => {
  try {
    const orders = await Order.find().populate('productId');
    res.json(orders);
  } catch (error) {
    res.status(500).json({ message: 'Erro ao buscar ordens', error: error.message });
  }
});

app.post('/api/orders', authenticateToken, async (req, res) => {
  try {
    const order = new Order(req.body);
    await order.save();
    res.status(201).json(order);
  } catch (error) {
    res.status(500).json({ message: 'Erro ao criar ordem', error: error.message });
  }
});

// Rotas Protegidas - Vendas
app.get('/api/sales', authenticateToken, async (req, res) => {
  try {
    const sales = await Sale.find().populate('productId');
    res.json(sales);
  } catch (error) {
    res.status(500).json({ message: 'Erro ao buscar vendas', error: error.message });
  }
});

app.post('/api/sales', authenticateToken, async (req, res) => {
  try {
    const sale = new Sale(req.body);
    await sale.save();

    // Atualizar estoque do produto
    const product = await Product.findById(sale.productId);
    if (product) {
      product.currentStock -= sale.quantity;
      await product.save();
    }

    res.status(201).json(sale);
  } catch (error) {
    res.status(500).json({ message: 'Erro ao registrar venda', error: error.message });
  }
});

// Rota para Dashboard
app.get('/api/dashboard', authenticateToken, async (req, res) => {
  try {
    const [products, sales, orders, deliveries] = await Promise.all([
      Product.countDocuments(),
      Sale.find().sort({ date: -1 }).limit(5).populate('productId'),
      Order.countDocuments({ status: { $ne: 'concluida' } }),
      Delivery.find().sort({ date: -1 }).limit(5).populate('productId')
    ]);

    const lowStockCount = await Product.countDocuments({ currentStock: { $lte: '$minStock' } });
    const totalSalesValue = sales.reduce((sum, s) => sum + parseFloat(s.total), 0);

    res.json({
      totalProducts: products,
      lowStockCount,
      totalSalesValue: totalSalesValue.toFixed(2),
      activeOrders: orders,
      recentSales: sales,
      recentDeliveries: deliveries
    });
  } catch (error) {
    res.status(500).json({ message: 'Erro ao carregar dashboard', error: error.message });
  }
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});