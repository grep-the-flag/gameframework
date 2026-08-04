FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

FROM deps AS dev
COPY . .
CMD ["npm", "run", "dev", "--", "--host"]

FROM deps AS build
COPY . .
RUN npm run build

FROM nginxinc/nginx-unprivileged:alpine AS prod
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 8080
