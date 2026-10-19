# syntax=docker/dockerfile:1.7
# AISW console: static build served by unprivileged nginx, /api proxied to the API service.
#   docker build -f deploy/docker/web.Dockerfile -t aisw-web:<version> .
FROM node:24.11.1-bookworm-slim AS build
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.30.6-alpine
COPY deploy/docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /web/dist /usr/share/nginx/html
USER 101
EXPOSE 8080
