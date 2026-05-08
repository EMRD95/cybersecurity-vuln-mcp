# Multi-stage build for stdio MCP server
# Supports both Node.js and Docker run modes

# ---- Builder ----
FROM node:22-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci --include=dev
COPY . .
RUN npm run build

# ---- Production ----
FROM node:22-alpine

ENV NODE_ENV=production
WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY --from=builder /app/dist ./dist

# Only STDERR should log; stdout is reserved for MCP JSONRPC messages
CMD ["node", "dist/stdio.js"]
