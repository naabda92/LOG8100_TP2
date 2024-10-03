# Use Node.js as the base image (as DVNA is a Node.js app)
FROM node:carbon
LABEL MAINTAINER "Subash SN"

# Set the working directory inside the container
WORKDIR /app

# Copy package.json and package-lock.json to the working directory
COPY package*.json ./

# Copy the rest of the application files into the working directory
COPY . .

RUN apt-get update && apt-get install -y iputils-ping

# Install project dependencies
RUN npm install -g nodemon && npm install

RUN npm uninstall bcrypt
RUN npm install bcrypt

# Start the DVNA app
CMD ["npm", "start"]