import amqp from "amqplib/callback_api.js";

export class EventQueue {
    private rabbit;
    constructor() {
        this.rabbit = amqp;
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
}
