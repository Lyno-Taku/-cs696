FROM node:20-alpine

WORKDIR /Pace-app

COPY package*.json ./
RUN npm ci --omit=dev

COPY . .

EXPOSE 8000

CMD ["node", "server.js"]
