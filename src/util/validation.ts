import { UserPayload } from "../types/user";
import { Logger } from "./logger";

export const  validateUserPayload = (userPayload: UserPayload) => {
    if (!userPayload.username) {
        Logger.error("Username is required");
        throw new Error("Username is required");
    }
    if (!userPayload.password) {
        Logger.error("Password is required");
        throw new Error("Password is required");
    }
    if (!userPayload.role) {
        Logger.error("Role is required");
        throw new Error("Role is required");
    }
    if (!userPayload.firstName) {
        Logger.error("First name is required");
        throw new Error("First name is required");
    }
    if (!userPayload.lastName) {
        Logger.error("Last name is required");
        throw new Error("Last name is required");
    }
    if (!userPayload.address) {
        Logger.error("Address is required");
        throw new Error("Address is required");
    }
}