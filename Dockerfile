# Use Node.js as the base image (as DVNA is a Node.js app)
FROM ubuntu:24.04
LABEL MAINTAINER "Subash SN"

# Set the working directory inside the container
WORKDIR /app

# Install required packages, NVM, and Node.js
RUN apt-get update && \
    apt-get install -y curl wget iputils-ping && \
    curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.1/install.sh | bash && \
    bash -c "source ~/.nvm/nvm.sh && nvm install 8.17.0 && nvm use 8.17.0 && nvm alias default 8.17.0 && nvm install-latest-npm"
	
# Ensure that NVM is available globally in future Docker layers and at runtime
ENV NVM_DIR="/root/.nvm"
ENV NODE_VERSION="8.17.0"
ENV NVM_SYMLINK_CURRENT=true
ENV PATH="$NVM_DIR/versions/node/v$NODE_VERSION/bin:$PATH"

# Copy package.json and package-lock.json to the working directory
COPY package*.json ./

# Copy the rest of the application files into the working directory
COPY . .

# Install Nodemon globally and project dependencies
RUN . ~/.nvm/nvm.sh && npm install -g nodemon && npm install

# Uninstall bcrypt and reinstall it
RUN . ~/.nvm/nvm.sh && npm uninstall bcrypt && npm install bcrypt

# Expose necessary ports
EXPOSE 9090

# Start the DVNA app
CMD ["/bin/bash", "-c", ". ~/.nvm/nvm.sh && npm start"]