import { Collection, MongoClient } from "mongodb";
import { User } from "../types/user";

export class AuthRepository {
    private client: MongoClient;
    private database_name: string;
    private collection_name: string;
    private collection: Collection<User>;

    constructor() {
        if (!process.env.MONGO_URI) {
            throw new Error("Missing MONGO_URI environment variable");
        }
        if (!process.env.MONGO_DB_NAME) {
            throw new Error("Missing MONGO_DB_NAME environment variable");
        }
        if (!process.env.MONGO_COLLECTION_NAME) {
            throw new Error("Missing MONGO_COLLECTION_NAME environment variable");
        }
        this.client = new MongoClient(process.env.MONGO_URI);
        this.database_name = process.env.MONGO_DB_NAME;
        this.collection_name = process.env.MONGO_COLLECTION_NAME;
        this.collection = this.client.db(this.database_name).collection(this.collection_name);
    }

    public async addUser(user: User) {
        await this.client.connect();
        await this.collection.insertOne(user);
        await this.client.close();
    }

    public async getUser(username: string): Promise<User | null> {
        await this.client.connect();
        const user = await this.collection.findOne({ username });
        await this.client.close();
        return user;
    }

    public async updateUsername(username: string, newUsername: string) {
        await this.client.connect();
        await this.collection.updateOne({ username }, { $set: { username: newUsername } });
        await this.client.close();
    }

    public async updatePassword(username: string, newPassword: string) {
        await this.client.connect();
        await this.collection.updateOne({ username}, { $set: { password: newPassword } });
        await this.client.close();
    }

    public async getUsersByFilter(filter: any): Promise<User[]> {
        await this.client.connect();
        const users = await this.collection.find(filter).toArray();
        await this.client.close();
        return users;
    }
   
}