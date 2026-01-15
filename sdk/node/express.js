const { captureException, addBreadcrumb } = require("./index");

function emberRequestHandler(options = {}) {
  return function (req, res, next) {
    addBreadcrumb("http.request", {
      category: "http",
      data: {
        method: req.method,
        path: req.originalUrl || req.url,
      },
    });

    res.on("finish", () => {
      addBreadcrumb("http.response", {
        category: "http",
        data: {
          status: res.statusCode,
          path: req.originalUrl || req.url,
          method: req.method,
        },
        level: res.statusCode >= 500 ? "error" : "info",
      });
    });

    if (options.userResolver) {
      req.emberUser = options.userResolver(req);
    }

    next();
  };
}

function emberErrorHandler(options = {}) {
  return function (err, req, res, next) {
    captureException(err, {
      tags: {
        method: req.method,
        route: req.originalUrl || req.url,
        ...options.tags,
      },
      user: options.userResolver ? options.userResolver(req) : req.emberUser,
    });
    next(err);
  };
}

module.exports = {
  emberRequestHandler,
  emberErrorHandler,
};
