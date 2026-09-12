from contextlib import asynccontextmanager
import asyncio
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, Response
from fastapi.exceptions import RequestValidationError
from fastapi.staticfiles import StaticFiles

from backend.api.routes import agent_router, router
from backend.core.config import get_settings, validate_settings
from backend.core.logging import configure_logging, get_logger
from backend.database.session import init_db
from backend.managed.monitor import monitor_managed_devices


def _error_response(status_code: int, error: str, message: str) -> JSONResponse:
    return JSONResponse({"error": error, "message": message}, status_code=status_code)


def _error_name(status_code: int) -> str:
    return {
        status.HTTP_400_BAD_REQUEST: "bad_request",
        status.HTTP_401_UNAUTHORIZED: "unauthorized",
        status.HTTP_403_FORBIDDEN: "forbidden",
        status.HTTP_404_NOT_FOUND: "not_found",
        status.HTTP_422_UNPROCESSABLE_CONTENT: "validation_error",
        status.HTTP_429_TOO_MANY_REQUESTS: "rate_limited",
        status.HTTP_500_INTERNAL_SERVER_ERROR: "internal_error",
    }.get(status_code, "error")


def _make_lifespan(settings):
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        init_db()
        stop_monitor = asyncio.Event()
        monitor_task = asyncio.create_task(monitor_managed_devices(settings, stop_monitor))
        app.state.managed_device_monitor = monitor_task
        logger = get_logger("backend.main")
        logger.info(
            "application_started",
            extra={
                "ccc_module": "api",
                "metadata": {
                    "host": settings.api_host,
                    "port": settings.api_port,
                    "auth_enabled": settings.auth_enabled,
                },
            },
        )
        try:
            yield
        finally:
            stop_monitor.set()
            await asyncio.wait_for(monitor_task, timeout=5)
            logger.info("application_stopped", extra={"ccc_module": "api"})

    return lifespan


def create_app(settings=None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)
    validate_settings(settings)

    app = FastAPI(
        title="Cyber Command Center",
        version="1.0.0",
        description="Local defensive cybersecurity lab API.",
        lifespan=_make_lifespan(settings),
    )
    app.dependency_overrides[get_settings] = lambda: settings
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_allowed_origins),
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH"],
        allow_headers=["authorization", "x-api-key", "content-type", "x-filename"],
    )
    app.include_router(router)
    app.include_router(agent_router)

    dashboard_dir = Path(__file__).resolve().parent.parent / "frontend" / "dashboard"
    static_dir = Path(__file__).resolve().parent.parent / "frontend" / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/", include_in_schema=False)
    def dashboard_index() -> FileResponse:
        return FileResponse(dashboard_dir / "index.html")

    @app.get("/dashboard", include_in_schema=False)
    def dashboard_alias() -> FileResponse:
        return FileResponse(dashboard_dir / "index.html")

    @app.middleware("http")
    async def security_headers(request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        logger = get_logger("backend.errors")
        logger.warning(
            "http_exception",
            extra={
                "ccc_module": "api",
                "metadata": {"path": request.url.path, "status_code": exc.status_code},
            },
        )
        message = exc.detail if isinstance(exc.detail, str) else "Request failed."
        return _error_response(exc.status_code, _error_name(exc.status_code), message)

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        logger = get_logger("backend.errors")
        logger.warning(
            "validation_error",
            extra={"ccc_module": "api", "metadata": {"path": request.url.path}},
        )
        return _error_response(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "validation_error",
            "The request payload was not valid.",
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        logger = get_logger("backend.errors")
        logger.exception(
            "unhandled_exception",
            extra={"ccc_module": "api", "metadata": {"path": request.url.path}},
        )
        return _error_response(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "internal_error",
            "Something went wrong.",
        )

    return app


app = create_app()
