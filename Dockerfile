# MCP server over stdio. Glama and other MCP hosts start it with `docker run -i`.
FROM node:22-slim
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY index.js ./
COPY lib ./lib
COPY bin ./bin
ENTRYPOINT ["node", "bin/mcp.mjs"]
