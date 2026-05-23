FROM node:20-slim

WORKDIR /app

# Install build tools for better-sqlite3 native addon
RUN apt-get update && apt-get install -y \
    python3 make g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy package.json only first (layer cache)
COPY package.json ./

# Install all deps
RUN npm install --omit=dev

# Copy source
COPY . .

# SQLite data dir
RUN mkdir -p /data

EXPOSE 4000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD node -e "require('http').get('http://localhost:'+process.env.PORT+'/api/health',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"

CMD ["node", "index.js"]
