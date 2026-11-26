FROM node:26-alpine3.22 AS build
RUN apk upgrade --no-cache
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run lint && npm run build

FROM node:26-alpine3.22 AS runtime
ENV NODE_ENV=production PORT=8080 NODE_OPTIONS=--expose-gc
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium
RUN apk upgrade --no-cache && apk add --no-cache chromium
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force \
	&& rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
	&& rm -f /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack
COPY --from=build --chown=node:node /app/dist ./dist
COPY --from=build --chown=node:node /app/server-dist ./server-dist
RUN mkdir -p /var/lib/vulnstream/deadletters /var/lib/vulnstream/ml && chown -R node:node /var/lib/vulnstream
USER node
EXPOSE 8080
# Probe /live (process liveness), not /ready (readiness): /ready runs a
# database SELECT and returns 503 during any database stall, so using it as the
# container healthcheck restarts a healthy process on every slow checkpoint.
# This matches compose.yaml, which overrides the healthcheck with /live for the
# same reason. /ready stays available for load-balancer readiness gating.
HEALTHCHECK --interval=30s --timeout=8s --start-period=60s CMD node -e "fetch('http://127.0.0.1:8080/live').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node","server-dist/main.js"]
