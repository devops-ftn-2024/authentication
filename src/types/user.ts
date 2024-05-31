export interface User {
    id?: string;
    username: string;
    password: string;
    role: Role;
}

export enum Role {
    HOST,
    GUEST
}

export interface UserPayload {
    username: string;
    password: string;
    role: Role;
    firstName: string;
    lastName: string;
    address: string;
}