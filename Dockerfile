FROM node:22-alpine AS build

WORKDIR /app

COPY package*.json .

RUN npm ci

COPY . .

RUN npm run build

FROM node:22-alpine AS runner

RUN apk update && apk add curl

WORKDIR /app

RUN chown -R node:node /app

USER node

COPY package*.json .

RUN npm ci

COPY --from=build --chown=node:node /app/dist ./dist
COPY --chown=node:node .babelrc .

EXPOSE 3001

CMD ["node", "dist/index.js"]