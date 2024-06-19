import express, { Request, Response, NextFunction } from 'express';
import bodyParser from 'body-parser';
import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import { Strategy as JwtStrategy, ExtractJwt } from 'passport-jwt';
import { User } from './types/user';
import { AuthService } from './service/auth-service';
import { CustomError } from './types/errors';
import cors, { CorsOptions } from 'cors';
import prometheusMiddleware from 'express-prometheus-middleware';
import promClient from 'prom-client';
import osUtils from 'os-utils';
import si from 'systeminformation';
import { Logger } from './util/logger';
require('dotenv').config();

const corsOptions: CorsOptions = {
  origin: (process.env.ALLOWED_ORIGIN!).split(','),
  optionsSuccessStatus: 200,
};

const app = express();
app.use(cors(corsOptions));

app.use(prometheusMiddleware({
  metricsPath: '/metrics',
  collectDefaultMetrics: true,
  requestDurationBuckets: [0.1, 0.5, 1, 1.5]
}));

const cpuUsageGauge = new promClient.Gauge({ name: 'cpu_usage', help: 'CPU Usage' });
const memoryUsageGauge = new promClient.Gauge({ name: 'memory_usage', help: 'Memory Usage' });
const fsUsageGauge = new promClient.Gauge({ name: 'fs_usage', help: 'File System Usage' });
const networkTrafficGauge = new promClient.Gauge({ name: 'network_traffic', help: 'Network Traffic' });

// Collecting OS metrics
function collectOSMetrics() {
  osUtils.cpuUsage(function(v){
    cpuUsageGauge.set(v);
  });
  si.mem().then(data => {
    memoryUsageGauge.set(data.active / data.total);
  });
  si.fsSize().then(data => {
    let used = 0;
    let size = 0;
    data.forEach(disk => {
      used += disk.used;
      size += disk.size;
    });
    fsUsageGauge.set(used / size);
  });
  si.networkStats().then(data => {
    let totalRx = 0;
    let totalTx = 0;
    data.forEach(net => {
      totalRx += net.rx_bytes;
      totalTx += net.tx_bytes;
    });
    networkTrafficGauge.set((totalRx + totalTx) / (1024 * 1024 * 1024)); // in GB
  });
}

// Collect metrics every 10 seconds
setInterval(collectOSMetrics, 10000);

// Additional custom metrics for HTTP traffic
const totalHttpRequests = new promClient.Counter({
  name: 'total_http_requests',
  help: 'Total number of HTTP requests'
});
const successfulHttpRequests = new promClient.Counter({
  name: 'successful_http_requests',
  help: 'Total number of successful HTTP requests'
});
const clientErrorHttpRequests = new promClient.Counter({
  name: 'client_error_http_requests',
  help: 'Total number of client error HTTP requests'
});
const serverErrorHttpRequests = new promClient.Counter({
  name: 'server_error_http_requests',
  help: 'Total number of server error HTTP requests'
});
const uniqueVisitorsGauge = new promClient.Gauge({
  name: 'unique_visitors',
  help: 'Number of unique visitors'
});
const notFoundHttpRequests = new promClient.Counter({
  name: 'not_found_http_requests',
  help: 'Total number of HTTP 404 requests'
});
const trafficInGbGauge = new promClient.Gauge({
  name: 'traffic_in_gb',
  help: 'Total traffic in GB'
});

// Middleware to track HTTP requests
app.use((req, res, next) => {
  totalHttpRequests.inc();

  res.on('finish', () => {
    if (res.statusCode >= 200 && res.statusCode < 400) {
      successfulHttpRequests.inc();
    } else if (res.statusCode >= 400 && res.statusCode < 500) {
      clientErrorHttpRequests.inc();
      if (res.statusCode === 404) {
        notFoundHttpRequests.inc();
      }
    } else if (res.statusCode >= 500) {
      serverErrorHttpRequests.inc();
    }
  });

  next();
});

const visitorMap = new Map();

// Middleware to track unique visitors and traffic
app.use((req, res, next) => {
  const ip = req.ip;
  const userAgent = req.headers['user-agent'];
  const visitorKey = `${ip}-${userAgent}`;

  if (!visitorMap.has(visitorKey)) {
    visitorMap.set(visitorKey, { timestamp: Date.now() });
  } else {
    visitorMap.get(visitorKey).timestamp = Date.now();
  }

  uniqueVisitorsGauge.set(visitorMap.size);

  res.on('finish', () => {
    const responseSize = Number(res.getHeader('content-length')) || 0;
    trafficInGbGauge.inc(responseSize / (1024 * 1024 * 1024)); // in GB
  });

  next();
});


const PORT = process.env.PORT;

app.use(bodyParser.json());
app.use(passport.initialize());

const authService = new AuthService();

passport.use(new LocalStrategy(async (username, password, done) => {
  try {
    const token = await authService.login(username, password);
    done(null, { token });
} catch (err) {
    done(null, false, { message: (err as CustomError).message });
}
}));


// for token validation
passport.use(new JwtStrategy({
  jwtFromRequest: ExtractJwt.fromAuthHeaderWithScheme('Bearer'),
  secretOrKey: process.env.SECRET_KEY!,
  passReqToCallback: true
}, async (req, jwtPayload, done) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    const user = await authService.validateToken(token);
    if (user) {
        done(null, user);
    } else {
        done(null, false, { message: 'Invalid token' });
    }
} catch (err) {
    done(err, false);
}
}));

// Login route
app.post('/auth/login', (req: Request, res: Response, next: NextFunction) => {
  passport.authenticate('local', { session: false }, (err: unknown, user: User, info: unknown) => {
    if (err) {
      return next(err);
    }
    if (!user) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
    return res.json({ user });
  })(req, res, next);
});

// Token validation route
app.post('/auth/validate', passport.authenticate('jwt', { session: false }), (req: Request, res: Response) => {
  res.json({ message: 'Valid token', user: req.user });
});

app.post('/auth/register', async (req: Request, res: Response) => {
  Logger.log('Registering user');
  try {
    await authService.register(req.body);
    Logger.log('User registered successfully');
    return  res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    const code = err instanceof CustomError ? err.code : 500;
    return res.status(code).json({ message: (err as Error).message });
  }
});

app.patch('/auth/update/username',async (req: Request, res: Response) => {
  Logger.log('Updating username');
  try {
    const {username, newUsername} = req.body;
    await authService.updateUsername(username, newUsername);
    Logger.log('Username updated successfully');
    return  res.status(200).json({ message: 'Username updated successfully' });
  } catch (err) {
    const code = err instanceof CustomError ? err.code : 500;
    console.log(err)
    return res.status(code).json({ message: (err as Error).message });
  }
});

app.patch('/auth/update/password',async (req: Request, res: Response) => {
  Logger.log('Updating password');
  try {
    const {username, newPassword} = req.body;
    await authService.updatePassword(username, newPassword);
    Logger.log('Password updated successfully');
    return  res.status(200).json({ message: 'Password updated successfully' });
  } catch (err) {
    const code = err instanceof CustomError ? err.code : 500;
    return res.status(code).json({ message: (err as Error).message });
  }
});

app.get('/auth/health', (req: Request, res: Response) => {
    return res.status(200).json({message: "Hello, World!"});
})

app.listen(PORT, () => {
  console.log(`Authentication service running on http://localhost:${PORT}`);
});
