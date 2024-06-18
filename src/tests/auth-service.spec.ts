import { AuthRepository } from "../repository/auth-repository";
import { AuthService } from "../service/auth-service";
import { BadRequestError, InternalServerError, UnauthorizedError } from "../types/errors";
import { UserPayload, User, Role } from "../types/user";
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { EventQueue } from "../gateway/event-queue";
import { jest, describe, beforeEach, test, expect } from '@jest/globals';

jest.mock('../repository/auth-repository');
jest.mock('bcryptjs');
jest.mock('jsonwebtoken');
jest.mock('../gateway/event-queue');

describe('AuthService', () => {
    let service: AuthService;
    let repository: jest.Mocked<AuthRepository>;
    let eventQueue: jest.Mocked<EventQueue>;

    beforeEach(() => {
        repository = new AuthRepository() as jest.Mocked<AuthRepository>;
        eventQueue = new EventQueue() as jest.Mocked<EventQueue>;
        service = new AuthService();
        service['authRepository'] = repository;
        service['eventQueue'] = eventQueue;
    });

    describe('login', () => {
        test('should throw UnauthorizedError if username or password is incorrect', async () => {
            repository.getUser.mockResolvedValue(null);
            await expect(service.login('username', 'password')).rejects.toThrow(UnauthorizedError);

            repository.getUser.mockResolvedValue({ username: 'username', password: 'hashedPassword', role: Role.GUEST });
            (bcrypt.compare as jest.Mock).mockResolvedValue(false);
            await expect(service.login('username', 'password')).rejects.toThrow(UnauthorizedError);
        });

        test('should throw InternalServerError if secret key is not found', async () => {
            repository.getUser.mockResolvedValue({ username: 'username', password: 'hashedPassword', role: Role.GUEST });
            (bcrypt.compare as jest.Mock).mockResolvedValue(true);
            delete process.env.SECRET_KEY;
            await expect(service.login('username', 'password')).rejects.toThrow(InternalServerError);
        });

        test('should return a token if login is successful', async () => {
            repository.getUser.mockResolvedValue({ username: 'username', password: 'hashedPassword', role: Role.GUEST });
            (bcrypt.compare as jest.Mock).mockResolvedValue(true);
            process.env.SECRET_KEY = 'secret';
            (jwt.sign as jest.Mock).mockReturnValue('token');

            const token = await service.login('username', 'password');
            expect(token).toBe('token');
        });
    });

    describe('validateToken', () => {
        test('should return null if token is invalid', async () => {
            (jwt.verify as jest.Mock).mockImplementation(() => { throw new Error(); });
            const result = await service.validateToken('invalidToken');
            expect(result).toBeNull();
        });

        test('should return user info if token is valid', async () => {
            (jwt.verify as jest.Mock).mockReturnValue({ username: 'username' });
            repository.getUser.mockResolvedValue({ username: 'username', password: 'hashedPassword', role: Role.GUEST });

            const result = await service.validateToken('validToken');
            expect(result).toEqual({ username: 'username', role: Role.GUEST });
        });
    });

    describe('register', () => {
        test('should throw BadRequestError if user already exists', async () => {
            repository.getUser.mockResolvedValue({ username: 'username', password: 'hashedPassword', role: Role.GUEST });

            await expect(service.register({ username: 'username', password: 'password', role: Role.GUEST, firstName: 'firstName', lastName: 'lastName', address: 'address' } as UserPayload)).rejects.toThrow(BadRequestError);
        });

        test('should hash password and call addUser', async () => {
            repository.getUser.mockResolvedValue(null);
            (bcrypt.hash as jest.Mock).mockResolvedValue('hashedPassword');
            const userPayload: UserPayload = { 
                username: 'username', 
                password: 'password', 
                role: Role.GUEST, 
                firstName: 'firstName', 
                lastName: 'lastName', 
                address: 'address' 
            };

            await service.register(userPayload);
            expect(repository.addUser).toHaveBeenCalledWith(expect.objectContaining({
                username: 'username',
                password: 'hashedPassword',
                role: Role.GUEST
            }));
        });

        test('should emit user-registered event', async () => {
            repository.getUser.mockResolvedValue(null);
            (bcrypt.hash as jest.Mock).mockResolvedValue('hashedPassword');
            const userPayload = { username: 'username', password: 'password', role: Role.GUEST, firstName: 'firstName', lastName: 'lastName', address: 'address' } as UserPayload;

            await service.register(userPayload);
            expect(eventQueue.execute).toHaveBeenCalledWith(expect.objectContaining({
                username: 'username',
                firstName: 'firstName',
                lastName: 'lastName',
                address: 'address'
            }), 'user-registered');
        });

        test('should throw InternalServerError if event emission fails', async () => {
            repository.getUser.mockResolvedValue(null);
            (bcrypt.hash as jest.Mock).mockResolvedValue('hashedPassword');
            eventQueue.execute.mockImplementation(() => { throw new Error(); });

            await expect(service.register({ username: 'username', password: 'password', role: Role.GUEST, firstName: 'firstName', lastName: 'lastName', address: 'address' } as UserPayload)).rejects.toThrow(InternalServerError);
        });
    });

    describe('updateUsername', () => {
        test('should throw BadRequestError if user is not found or username already taken', async () => {
            repository.getUsersByFilter.mockResolvedValue([]);
            await expect(service.updateUsername('oldUsername', 'newUsername')).rejects.toThrow(BadRequestError);

            repository.getUsersByFilter.mockResolvedValue([{ username: 'newUsername', password: 'hashedPassword', role: Role.GUEST }]);
            await expect(service.updateUsername('oldUsername', 'newUsername')).rejects.toThrow(BadRequestError);
        });

        test('should update username and emit event', async () => {
            repository.getUsersByFilter.mockResolvedValue([{ username: 'oldUsername', password: 'hashedPassword', role: Role.GUEST }]);
            await service.updateUsername('oldUsername', 'newUsername');
            expect(repository.updateUsername).toHaveBeenCalledWith('oldUsername', 'newUsername');
            expect(eventQueue.execute).toHaveBeenCalledWith({ oldUsername: 'oldUsername', newUsername: 'newUsername' }, 'username-updated');
        });

        test('should throw InternalServerError if event emission fails', async () => {
            repository.getUsersByFilter.mockResolvedValue([{ username: 'oldUsername', password: 'hashedPassword', role: Role.GUEST }]);
            eventQueue.execute.mockImplementation(() => { throw new Error(); });

            await expect(service.updateUsername('oldUsername', 'newUsername')).rejects.toThrow(InternalServerError);
        });
    });

    describe('updatePassword', () => {
        test('should throw BadRequestError if user is not found or password is the same', async () => {
            repository.getUser.mockResolvedValue(null);
            await expect(service.updatePassword('username', 'newPassword')).rejects.toThrow(BadRequestError);

            repository.getUser.mockResolvedValue({ username: 'username', password: 'hashedPassword', role: Role.GUEST });
            (bcrypt.compare as jest.Mock).mockResolvedValue(true);
            await expect(service.updatePassword('username', 'newPassword')).rejects.toThrow(BadRequestError);
        });

        test('should hash new password and call updatePassword', async () => {
            repository.getUser.mockResolvedValue({ username: 'username', password: 'hashedPassword', role: Role.GUEST });
            (bcrypt.compare as jest.Mock).mockResolvedValue(false);
            (bcrypt.hash as jest.Mock).mockResolvedValue('newHashedPassword');

            await service.updatePassword('username', 'newPassword');
            expect(repository.updatePassword).toHaveBeenCalledWith('username', 'newHashedPassword');
        });
    });
});
