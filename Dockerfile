FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json tsconfig.build.json ./
RUN npm ci
COPY src ./src
RUN npm run build && npm prune --omit=dev

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
COPY policies ./policies
COPY harness/policy.yaml ./harness/policy.yaml
COPY harness/scenarios ./harness/scenarios
USER node
EXPOSE 8787
ENTRYPOINT ["node", "dist/cli.js"]
CMD ["serve", "--policy", "policies/default.yaml"]
