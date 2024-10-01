# Use Node.js as the base image (as DVNA is a Node.js app)
FROM node:20

# Set the working directory inside the container
WORKDIR /usr/src/app

# Copy package.json and package-lock.json to the working directory
COPY package*.json ./

# Install project dependencies
RUN npm install

# Copy the rest of the application files into the working directory
COPY . .

# Expose the port DVNA will run on
EXPOSE 9090

# Start the DVNA app
CMD ["npm", "start"]