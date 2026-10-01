# Production stage - serve static assets with Nginx
FROM nginx:alpine

# Copy static frontend files to Nginx web root
COPY . /usr/share/nginx/html

# Copy custom Nginx configuration with security headers
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]