
const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();

const JWT_SECRET = "modi_hai_to_admin_hai";

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const FLAG1 = "MODI{Desh_Bachalo_Guys}";
const FLAG2 = "MODI{BECHO_JANTA_PARTY}";
const FLAG3 = "MODI{Sab_Jaan_Gaye}";
const MASTER_FLAG = "MASTER{Desh_Bachalo_Guys_BECHO_JANTA_PARTY_Sab_Jaan_Gaye}";

function auth(req, res, next) {
    const token = req.cookies && req.cookies.token;
    req.user = null;

    if (!token) return next();

    try {
        // JWT challenge: the signature MUST be valid. Participants must discover
        // the CTF secret and re-sign the modified role claim using HS256.
        req.user = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
    } catch (error) {
        // Invalid/expired signatures are not authenticated sessions.
        res.clearCookie('token', { path: '/' });
    }

    return next();
}

app.use(auth);

app.get('/', (req, res) => {
    res.render('index', {
        user: req.user || null
    });
});

app.post('/login', (req, res) => {

    const { username, password } = req.body;

    if(username === 'amit' && password === 'mitron@2026'){

        const token = jwt.sign({
            username,
            role:'user'
        }, JWT_SECRET);

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production' || Boolean(process.env.VERCEL),
            sameSite: 'lax',
            path: '/',
            maxAge: 60 * 60 * 1000
        });

        return res.status(200).json({
            success: true,
            message: 'Login Successful'
        });
    }

    return res.status(401).json({
        success: false,
        message: 'Wrong Credentials'
    });
});

app.get('/robots.txt', (req, res) => {
    res.type('text/plain');
    res.send(`
User-agent: *
Disallow: /modi
Disallow: /admin
`);
});

app.get('/modi', (req, res) => {
    res.render('modi');
});

// Intentional IDOR lab: object access is based on a caller-controlled userId.
// This deliberately vulnerable endpoint is for the local CTF challenge only.
app.get('/secure-message', (req, res) => {
    res.render('secure-message');
});

app.get('/api/secure-message', (req, res) => {
    const userId = String(req.query.userId || '');
    const messages = {
        '101': { username: 'amit', title: 'Message for Amit', body: 'Mitron, report ka first draft ready hai. Meeting se pehle review kar lena.' },
        '102': { username: 'yogi', title: 'Message for Yogi', body: 'Yogi ji, event ke arrangements confirm hain. Final update ka intezar hai.' },
        '4242': { username: 'ganesh', title: 'Private message for Ganesh', body: 'Ganesh, sab jaan gaye... asli raaz yahin tha. Flag: ' + FLAG3 }
    };

    const message = messages[userId];
    if (!message) {
        return res.status(404).json({ success: false, message: 'User/message not found. Check the request and userId.' });
    }

    // CTF flaw: no ownership/authorization check is performed for the requested userId.
    return res.json({ success: true, message });
});

app.post('/buy', (req, res) => {

    const price = Number(req.body.price);

    if(price === 1){
        return res.json({
            success:true,
            flag: FLAG1
        });
    }

    res.json({
        success:false,
        message:'Price too high'
    });
});

app.get('/admin', (req, res) => {
    // No valid JWT cookie means the visitor is not logged in.
    if (!req.user) {
        return res.redirect(302, '/');
    }

    // A valid user JWT is logged in, but does not grant admin access.
    // Keep this CTF role-check page so the challenge remains solvable.
    if (req.user.role !== 'admin') {
        return res.status(403).render('notadmin');
    }

    return res.render('admin', { flag: FLAG2 });
});

app.post('/submit-flags', (req, res) => {

    const { flag1, flag2, flag3 } = req.body;

    if(flag1 === FLAG1 && flag2 === FLAG2 && flag3 === FLAG3){

        return res.json({
            success:true,
            reward:'MITRON-CTF-WINNER-2026',
            masterFlag: MASTER_FLAG
        });
    }

    res.json({
        success:false,
        message:'Wrong Flags'
    });
});

module.exports = app;

// Vercel runs this as a serverless function. Only listen locally when started
// directly with `npm start` outside Vercel.
if (require.main === module && !process.env.VERCEL) {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
        console.log(`Server running on http://localhost:${PORT}`);
    });
}
