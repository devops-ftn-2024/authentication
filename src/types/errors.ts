export class CustomError extends Error {
    code: number;
    constructor(message: string, code: number) {
        super(message);
        this.name = this.constructor.name;
        this.code = code;
    }
}

export class NotFoundError extends CustomError {
    constructor(message: string) {
        super(message, 404);
        this.name = 'NotFoundError';
    }
}

export class BadRequestError extends CustomError {
    constructor(message: string) {
        super(message, 400);
        this.name = 'BadRequestError';
    }
}

export class UnauthorizedError extends CustomError {
    constructor(message: string) {
        super(message, 401);
        this.name = 'UnauthorizedError';
    }
}

export class ForbiddenError extends CustomError {
    constructor(message: string) {
        super(message, 403);
        this.name = 'ForbiddenError';
    }
}

export class InternalServerError extends CustomError {
    constructor(message: string) {
        super(message, 500);
        this.name = 'InternalServerError';
    }
}