FROM node:22-alpine

RUN mkdir -p /home/node/app/node_modules && chown -R node:node /home/node/app

WORKDIR /home/node/app

COPY package*.json ./

USER node

RUN npm ci

COPY --chown=node:node . .

RUN npx tsc

EXPOSE 3001

RUN apk update && apk add curl

CMD ["node", "dist/index.js"]