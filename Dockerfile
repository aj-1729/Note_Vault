FROM node:22-alpine

WORKDIR /app

COPY package*.json ./

RUN npm ci

COPY . . 

EXPOSE 8001

CMD ["npm", "start"]