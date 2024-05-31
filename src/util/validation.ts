import { UserPayload } from "../types/user";

export const  validateUserPayload = (userPayload: UserPayload) => {
    if (!userPayload.username) {
        throw new Error("Username is required");
    }
    if (!userPayload.password) {
        throw new Error("Password is required");
    }
    if (!userPayload.role) {
        throw new Error("Role is required");
    }
    if (!userPayload.firstName) {
        throw new Error("First name is required");
    }
    if (!userPayload.lastName) {
        throw new Error("Last name is required");
    }
    if (!userPayload.address) {
        throw new Error("Address is required");
    }
}