FROM node:latest

WORKDIR /usr/src/client

COPY package*.json /app

RUN npm install

COPY . .

EXPOSE 3000

CMD [ "npm", "start" ]