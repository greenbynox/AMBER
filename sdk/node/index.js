const { randomUUID } = require("crypto");

let config = {
  endpoint: null,
  projectId: null,
  apiKey: null,
  environment: null,
  release: null,
  autoCapture: true,
  maxBreadcrumbs: 50,
};

let breadcrumbs = [];
let installedHandlers = false;

function init(options) {
  config = {
    ...config,
    ...options,
  };

  if (config.autoCapture && !installedHandlers) {
    installedHandlers = true;
    process.on("uncaughtException", (err) => {
      captureException(err);
    });
    process.on("unhandledRejection", (reason) => {
      const error = reason instanceof Error ? reason : new Error(String(reason));
      captureException(error);
    });
  }
}

function captureException(error, context = {}) {
  if (!config.endpoint || !config.projectId || !config.apiKey) {
    return;
  }

  const mergedBreadcrumbs = mergeBreadcrumbs(context.breadcrumbs);

  const event = {
    event_id: randomUUID(),
    project_id: config.projectId,
    timestamp: new Date().toISOString(),
    level: "error",
    message: error?.message || "Erreur inconnue",
    exception: {
      type: error?.name || "Error",
      message: error?.message || "Erreur inconnue",
      stacktrace: parseStack(error?.stack),
    },
    context: {
      env: config.environment || context.env,
      release: config.release || context.release,
      user: context.user,
      tags: context.tags,
      breadcrumbs: mergedBreadcrumbs,
    },
    sdk: {
      name: "ember-node",
      version: "0.1.0",
    },
  };

  sendEvent(event).catch(() => {});
}

function addBreadcrumb(message, options = {}) {
  if (!message) return;
  const crumb = {
    timestamp: new Date().toISOString(),
    message: String(message),
    category: options.category,
    level: options.level || "info",
    data: options.data,
  };

  breadcrumbs.push(crumb);
  if (breadcrumbs.length > config.maxBreadcrumbs) {
    breadcrumbs = breadcrumbs.slice(-config.maxBreadcrumbs);
  }
}

function clearBreadcrumbs() {
  breadcrumbs = [];
}

function mergeBreadcrumbs(extra) {
  const list = breadcrumbs.slice();
  if (Array.isArray(extra)) {
    list.push(...extra);
  }
  return list.length ? list : undefined;
}

function parseStack(stack) {
  if (!stack) return undefined;
  const lines = stack.split("\n").slice(1);
  const frames = [];
  for (const line of lines) {
    const trimmed = line.trim();
    const match = trimmed.match(/at\s+(.*)\s+\((.*):(\d+):(\d+)\)$/) ||
      trimmed.match(/at\s+(.*):(\d+):(\d+)$/);

    if (match) {
      if (match.length === 5) {
        frames.push({
          function: match[1],
          filename: match[2],
          line: Number(match[3]),
          col: Number(match[4]),
          in_app: true,
        });
      } else if (match.length === 4) {
        frames.push({
          function: "(anonymous)",
          filename: match[1],
          line: Number(match[2]),
          col: Number(match[3]),
          in_app: true,
        });
      }
    }
  }
  return frames.length ? frames : undefined;
}

async function sendEvent(event) {
  const url = new URL("/ingest", config.endpoint);
  await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-ember-key": config.apiKey,
    },
    body: JSON.stringify(event),
  });
}

module.exports = {
  init,
  captureException,
  addBreadcrumb,
  clearBreadcrumbs,
};
