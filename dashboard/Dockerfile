# Stage 1: Base node environment
FROM node:22-alpine AS base
WORKDIR /app
COPY package.json yarn.lock* ./

# Stage 2: Development (Used for local hot-reloading)
FROM base AS dev-stage
RUN yarn install
# The command can be overridden by compose, but we set a solid default
CMD ["yarn", "dev", "--host", "0.0.0.0"]

# Stage 3: Build toolchain (Compiles the production code)
FROM base AS build-stage
RUN yarn install --frozen-lockfile
COPY . .
RUN yarn build

# Stage 4: Production web server
FROM nginx:alpine AS production-stage
COPY --from=build-stage /app/dist /usr/share/nginx/html
COPY ./nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]