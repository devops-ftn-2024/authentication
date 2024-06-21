import fs from 'fs';
import path from 'path';

enum Level {
    INFO,
    WARNING,
    ERROR
}

export class Logger {
    private static folderPath = path.join(`${__dirname}/../..`, 'logs');
    private static filePath = path.join(this.folderPath, 'accommodatio-authentication-service.log');

    static log(message: string) {
        console.log(message);
        this.logToFile(Level.INFO, message);
    }

    static warn(message: string) {
        console.warn(message);
        this.logToFile(Level.WARNING, message);
    }

    static error(message: string) {
        console.error(message);
        this.logToFile(Level.ERROR, message);
    }

    private static logToFile(level: Level, message: string) {
        if (!fs.existsSync(this.folderPath)) {
            fs.mkdirSync(this.folderPath);
          }
          
        if (!fs.existsSync(this.filePath)) {
        fs.writeFileSync(this.filePath, '', 'utf8');
        }
        
        const log = `${new Date().toISOString()} [${Level[level]}] ${message}`
        fs.appendFileSync(this.filePath, log + '\n', 'utf8');
    }
}