FROM node:22-slim
# git is needed to clone the repos being scanned; python3 is optional (AI diagrams)
RUN apt-get update && apt-get install -y --no-install-recommends git python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY backend/package*.json backend/
RUN cd backend && npm ci --omit=dev
COPY . .
ENV NODE_ENV=production PORT=5001
EXPOSE 5001
USER node
CMD ["node", "backend/server.js"]
