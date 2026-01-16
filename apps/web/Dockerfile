FROM node:20-alpine as builder
WORKDIR /app/apps/web
COPY apps/web/package*.json ./
RUN npm install
COPY apps/web ./
RUN npm run build

FROM nginx:1.25-alpine
COPY apps/web/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /app/apps/web/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
