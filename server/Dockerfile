FROM node:latest

WORKDIR /usr/src/server

COPY package*.json /app

RUN npm install

COPY . .

EXPOSE 5000

CMD [ "npm", "run", "dev" ]

