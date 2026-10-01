# Multi-stage build for frontend
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files
COPY frontend/package*.json ./
RUN npm ci

# Copy source files
COPY frontend/ ./

# Build production assets (if using a build step)
# RUN npm run build

# Production stage - serve with nginx
FROM nginx:alpine AS production

# Copy built assets from builder
COPY --from=builder /app /usr/share/nginx/html

# Copy nginx configuration
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]