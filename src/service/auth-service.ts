import { AuthRepository } from "../repository/auth-repository";
import { BadRequestError, InternalServerError, UnauthorizedError } from "../types/errors";
import { User, UserPayload } from "../types/user";
import { validateUserPayload } from "../util/validation";
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { EventQueue } from "../gateway/event-queue";

export class AuthService {
    private authRepository;
    private eventQueue;
    constructor() { 
        this.authRepository = new AuthRepository();
        this.eventQueue = new EventQueue();
    }

    async login(username: string, password: string): Promise<string> {
        const user = await this.authRepository.getUser(username);
        if (!user || !(await bcrypt.compare(password, user.password))) {
            throw new UnauthorizedError('Incorrect username or password');
        }
        if (!process.env.SECRET_KEY) {
            throw new InternalServerError('Secret key not found');
        }
        return jwt.sign({ username: user.username }, process.env.SECRET_KEY, { expiresIn: '5h' });
    }

    async validateToken(token: string): Promise<Partial<User> | null> {
        try {
            console.log(`Validating token...`)
            const decoded = jwt.verify(token, process.env.SECRET_KEY!) as { username: string };
            console.log(`Decoded token: ${JSON.stringify(decoded)}`)
            const user = await this.authRepository.getUser(decoded.username);
            if (user) {
                return {username: user.username, role: user.role};
            }
            return null;
        } catch (err) {
            console.error(err);
            return null;
        }
    }

    private async hashPassword(password: string): Promise<string> {
        const salt = await bcrypt.genSalt(+process.env.SALT_ROUNDS!);
        return await bcrypt.hash(password, salt);
    }

    public async register(userPayload: UserPayload) {
        validateUserPayload(userPayload);
        let user: User | null = await this.authRepository.getUser(userPayload.username);
        if (user) {
            throw new BadRequestError('User already exists');
        }

        const hashPassword = await this.hashPassword(userPayload.password);

        user = {
            username: userPayload.username,
            password: hashPassword,
            role: userPayload.role,
        };

        
        await this.authRepository.addUser(user);
        try {
            const userData = {
                username: user.username,
                firstName: userPayload.firstName,
                lastName: userPayload.lastName,
                address: userPayload.address
            }
            this.eventQueue.execute(userData, 'user-registered');
        } catch (err) {
            console.error(err);
            throw new InternalServerError('Failed to emit user-registered event');
        }
    }

    public async updateUsername(username: string, newUsername: string) {
        const filter = { username: { $in: [username, newUsername] }}
        const users: User[] = await this.authRepository.getUsersByFilter(filter);
        const oldUser = users.find(user => user.username === username);
        const userWithNewUsername = users.find(user => user.username === newUsername);
        if (!oldUser) {
            throw new BadRequestError('User not found');
        }
        if (userWithNewUsername) {
            throw new BadRequestError('Username already taken');
        }
        await this.authRepository.updateUsername(username, newUsername);
        try {
            this.eventQueue.execute({oldUsername: username, newUsername}, 'username-updated');
        } catch (err) {
            console.error(err);
            throw new InternalServerError('Failed to emit username-updated event');
        }
    }

    public async updatePassword(username: string, newPassword: string) {
        const user = await this.authRepository.getUser(username);
        if (!user) {
            throw new BadRequestError('User not found');
        }
        const hashPassword = await this.hashPassword(newPassword);
        const compareResult = await bcrypt.compare(newPassword, user.password);
        if (compareResult) {
            throw new BadRequestError('New password cannot be the same as the old password');
        }
        await this.authRepository.updatePassword(username, hashPassword);
    }
}