
# Stage 1: Build the React application
FROM node:18-alpine AS build

# Set the working directory
WORKDIR /app

# Copy package.json and package-lock.json
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy the rest of the application code
COPY . .

# Build the application
RUN npm run build

# Stage 2: Serve the application using a lightweight web server
FROM nginx:1.21-alpine

# Copy the built static files from the build stage
COPY --from=build /app/build /usr/share/nginx/html

# Expose port 80 for the web server
EXPOSE 80

# The default nginx command will start the server
CMD ["nginx", "-g", "daemon off;"]

