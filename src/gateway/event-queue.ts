import amqp from "amqplib/callback_api.js";
import { Logger } from "../util/logger";
import { AuthService } from "../service/auth-service";

export class EventQueue {
    private rabbit;
    constructor(private authService: AuthService) {
        this.rabbit = amqp;
        this.init();
    }

    executeFanOut(payload: any, channelName: string) {
        this.rabbit.connect(`amqp://${process.env.RABBITMQ_USERNAME}:${process.env.RABBITMQ_PASSWORD}@${process.env.RABBITMQ_HOST}:${process.env.RABBITMQ_PORT}/`, function(error, connection) {
            if (error) {
                throw error;
            }

            connection.createChannel(function (error1, channel) {
                if (error1) {
                    throw error1;
                }

                var data = JSON.stringify(payload);
                channel.assertExchange(channelName, 'fanout', { durable: true });
                channel.publish(channelName, '', Buffer.from(data));
            });
        });
    }

    execute(payload: any, channelName: string) {
        this.rabbit.connect(`amqp://${process.env.RABBITMQ_USERNAME}:${process.env.RABBITMQ_PASSWORD}@${process.env.RABBITMQ_HOST}:${process.env.RABBITMQ_PORT}/`, function(error, connection) {
            if (error) {
                throw error;
            }

            connection.createChannel(function (error1, channel) {
                if (error1) {
                    throw error1;
                }

                var data = JSON.stringify(payload);
                channel.assertQueue(channelName, { durable: false });
                channel.sendToQueue(channelName, Buffer.from(data));
            });
        });
    }

    private init() {
        amqp.connect(`amqp://${process.env.RABBITMQ_USERNAME}:${process.env.RABBITMQ_PASSWORD}@${process.env.RABBITMQ_HOST}:${process.env.RABBITMQ_PORT}/`, (error, connection) => {
            if (error) {
                Logger.error("Error connecting to RabbitMQ");
                return;
                //throw error;
            }
    
            connection.createChannel((error1, channel) => {
                if (error1) {
                    Logger.error("Error creating channel");
                   throw error1;
                }

                const exchangeNameDelete = 'user-deleted';
                channel.assertExchange(exchangeNameDelete, 'fanout', { durable: true });
    
                channel.assertQueue('', { exclusive: true }, (error2, q) => {
                    if (error2) {
                        throw error2;
                    }
    
                    channel.bindQueue(q.queue, exchangeNameDelete, '');
    
                    console.log(`Waiting for messages in ${q.queue}. To exit press CTRL+C`);
    
                    channel.consume(q.queue, (payload) => {
                        console.log(`Deleting entities that have username: ${payload}`);
                        if (payload !== null) {
                            const username: string= JSON.parse(payload.content.toString()).username;
                            console.log(`Deleting entities with username: ${JSON.stringify(username)}`);
                            this.authService.deleteUser(username);
                        }
                    }, { noAck: true });
                });
            });
        });
    }


}
