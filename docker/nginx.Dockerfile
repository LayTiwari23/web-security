# docker/nginx.Dockerfile

FROM nginx:1.27-alpine

# Remove the default configuration
RUN rm /etc/nginx/conf.d/default.conf

# Copy your custom Nginx config
# (we'll assume you'll create compose/nginx.conf or similar)
COPY nginx/nginx.conf /etc/nginx/conf.d/app.conf
# Static files volume location (optional)
# If you mount /app/static from the FastAPI container or a shared volume,
# you can serve them directly from Nginx.
RUN mkdir -p /app/static
WORKDIR /app

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]