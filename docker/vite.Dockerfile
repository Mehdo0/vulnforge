FROM node:22-alpine

WORKDIR /app

# Copy package files first for better layer caching
COPY frontend/package*.json ./

# Install dependencies
RUN npm install

# Copy frontend source
COPY frontend/ .

# Run Vite dev server
CMD ["npx", "vite", "--host", "0.0.0.0", "--port", "5173"]
