FROM node:22-alpine

RUN mkdir -p /home/node/app/node_modules && chown -R node:node /home/node/app

WORKDIR /home/node/app

COPY package*.json ./

RUN apk update && apk add curl

USER node

RUN npm ci

COPY --chown=node:node . .

RUN npx tsc

EXPOSE 3001

CMD ["node", "dist/index.js"]