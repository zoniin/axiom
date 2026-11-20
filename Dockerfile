FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json tsconfig.build.json ./
RUN npm ci --ignore-scripts
COPY src ./src
RUN npm run build && npm prune --omit=dev

FROM node:22-alpine
LABEL org.opencontainers.image.title="Axiom Guard" \
      org.opencontainers.image.description="Deterministic runtime security gateway for LLM apps and agents" \
      org.opencontainers.image.source="https://github.com/zoniin/axiom" \
      org.opencontainers.image.licenses="MIT"
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
COPY policies ./policies
COPY harness/scenarios ./harness/scenarios
USER node
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s CMD wget -qO- http://127.0.0.1:8787/health >/dev/null || exit 1
ENTRYPOINT ["node", "dist/cli.js"]
CMD ["serve", "--policy", "policies/default.yaml"]
