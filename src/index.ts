import express, { Request, Response, NextFunction } from 'express';
import bodyParser from 'body-parser';
import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import { Strategy as JwtStrategy, ExtractJwt } from 'passport-jwt';
import { User } from './types/user';
import { AuthService } from './service/auth-service';
import { CustomError } from './types/errors';
require('dotenv').config();

const app = express();
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
  console.log('Registering user');
  try {
    await authService.register(req.body);
    return  res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    const code = err instanceof CustomError ? err.code : 500;
    return res.status(code).json({ message: (err as Error).message });
  }
});

app.patch('/auth/update/username',async (req: Request, res: Response) => {
  console.log('Updating username');
  try {
    const {username, newUsername} = req.body;
    await authService.updateUsername(username, newUsername);
    return  res.status(200).json({ message: 'Username updated successfully' });
  } catch (err) {
    const code = err instanceof CustomError ? err.code : 500;
    console.log(err)
    return res.status(code).json({ message: (err as Error).message });
  }
});

app.patch('/auth/update/password',async (req: Request, res: Response) => {
  console.log('Updating password');
  try {
    const {username, newPassword} = req.body;
    await authService.updatePassword(username, newPassword);
    return  res.status(200).json({ message: 'Password updated successfully' });
  } catch (err) {
    const code = err instanceof CustomError ? err.code : 500;
    return res.status(code).json({ message: (err as Error).message });
  }
});

app.get('auth/health', (req: Request, res: Response) => {
    return res.status(200).json({message: "Hello, World!"});
})

app.listen(PORT, () => {
  console.log(`Authentication service running on http://localhost:${PORT}`);
});
