import { AuthRepository } from "../repository/auth-repository";
import { BadRequestError, InternalServerError, UnauthorizedError } from "../types/errors";
import { User, UserPayload } from "../types/user";
import { validateUserPayload } from "../util/validation";
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { EventQueue } from "../gateway/event-queue";
import { Logger } from "../util/logger";

export class AuthService {
    private authRepository;
    private eventQueue;
    constructor() { 
        this.authRepository = new AuthRepository();
        this.eventQueue = new EventQueue();
    }

    async login(username: string, password: string): Promise<string> {
        Logger.log(`Logging in user ${username}`);
        const user = await this.authRepository.getUser(username);
        if (!user || !(await bcrypt.compare(password, user.password))) {
            Logger.error(`UnauthorizedError: Incorrect username or password`);
            throw new UnauthorizedError('Incorrect username or password');
        }
        if (!process.env.SECRET_KEY) {
            Logger.error(`InternalServerError: Secret key not found`);
            throw new InternalServerError('Secret key not found');
        }
        Logger.log(`User logged in successfully`);
        return jwt.sign({ username: user.username }, process.env.SECRET_KEY, { expiresIn: '5h' });
    }

    async validateToken(token: string): Promise<Partial<User> | null> {
        try {
            Logger.log(`Validating token...`)
            const decoded = jwt.verify(token, process.env.SECRET_KEY!) as { username: string };
            Logger.log(`Decoded token: ${JSON.stringify(decoded)}`)
            const user = await this.authRepository.getUser(decoded.username);
            if (user) {
                Logger.log(`Token validated successfully`)
                return {username: user.username, role: user.role};
            }
            Logger.error(`UnauthorizedError: Invalid token`);
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
        Logger.log('Registering user');
        validateUserPayload(userPayload);
        let user: User | null = await this.authRepository.getUser(userPayload.username);
        if (user) {
            Logger.error(`BadRequestError: User already exists`);
            throw new BadRequestError('User already exists');
        }

        const hashPassword = await this.hashPassword(userPayload.password);

        Logger.log(`Adding user ${userPayload.username}`)
        user = {
            username: userPayload.username,
            password: hashPassword,
            role: userPayload.role,
        };

        
        await this.authRepository.addUser(user);
        try {
            Logger.log('Emmiting user-registered event');
            const userData = {
                username: user.username,
                firstName: userPayload.firstName,
                lastName: userPayload.lastName,
                address: userPayload.address
            }
            this.eventQueue.execute(userData, 'user-registered');
            Logger.log('Event emitted successfully');
        } catch (err) {
            console.error(err);
            throw new InternalServerError('Failed to emit user-registered event');
        }
    }

    public async updateUsername(username: string, newUsername: string) {
        Logger.log(`Updating username from ${username} to ${newUsername}`);
        if (!newUsername) {
            Logger.error(`BadRequestError: New username cannot be empty`);
            throw new BadRequestError('New username cannot be empty');
        }
        const filter = { username: { $in: [username, newUsername] }}
        const users: User[] = await this.authRepository.getUsersByFilter(filter);
        const oldUser = users.find(user => user.username === username);
        const userWithNewUsername = users.find(user => user.username === newUsername);
        if (!oldUser) {
            Logger.error(`BadRequestError: User not found`);
            throw new BadRequestError('User not found');
        }
        if (userWithNewUsername) {
            Logger.error(`BadRequestError: Username already taken`);
            throw new BadRequestError('Username already taken');
        }
        await this.authRepository.updateUsername(username, newUsername);
        Logger.log(`Username updated successfully`);
        try {
            Logger.log('Emmiting username-updated event');
            this.eventQueue.executeFanOut({oldUsername: username, newUsername}, 'username-updated');
            Logger.log('Event emitted successfully');
        } catch (err) {
            console.error(err);
            Logger.error(`InternalServerError: Failed to emit username-updated event`);
            throw new InternalServerError('Failed to emit username-updated event');
        }
    }

    public async updatePassword(username: string, newPassword: string) {
        Logger.log(`Updating password for user ${username}`);
        const user = await this.authRepository.getUser(username);
        if (!user) {
            Logger.error(`BadRequestError: User not found`);
            throw new BadRequestError('User not found');
        }
        const hashPassword = await this.hashPassword(newPassword);
        const compareResult = await bcrypt.compare(newPassword, user.password);
        if (compareResult) {
            Logger.error(`BadRequestError: New password cannot be the same as the old password`);
            throw new BadRequestError('New password cannot be the same as the old password');
        }
        await this.authRepository.updatePassword(username, hashPassword);
        Logger.log(`Password updated successfully`);
    }
}