from pathlib import Path
import runpy
import re

import pytest

from app import create_app


PROJECT_ROOT = Path(__file__).resolve().parents[1]
STRONG_TEST_SECRET = "test-only-secret-key-for-config-tests-0123456789"


def test_production_rejects_missing_secret(monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)

    with pytest.raises(RuntimeError, match="Production requires a private SECRET_KEY"):
        create_app({
            "ENV": "production",
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        })


@pytest.mark.parametrize(
    "secret",
    [
        "too-short",
        "change-this-secret-key",
        "x" * 64,
        "1234567890" * 5,
        " " + STRONG_TEST_SECRET,
    ],
)
def test_production_rejects_insecure_secrets(secret):
    with pytest.raises(RuntimeError, match="Production requires a private SECRET_KEY"):
        create_app({
            "ENV": "production",
            "SECRET_KEY": secret,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        })


def test_production_requires_explicit_database_url(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("FLASK_SQLALCHEMY_DATABASE_URI", raising=False)

    with pytest.raises(RuntimeError, match="Production requires an explicit DATABASE_URL"):
        create_app({"ENV": "production", "SECRET_KEY": STRONG_TEST_SECRET})


def test_production_rejects_unknown_environment():
    with pytest.raises(RuntimeError, match="FLASK_ENV must be one of"):
        create_app({"ENV": "prod"})


def test_production_accepts_explicit_settings_and_disables_debug():
    app = create_app({
        "ENV": "production",
        "SECRET_KEY": STRONG_TEST_SECRET,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "DEBUG": True,
    })

    assert app.config["DEBUG"] is False
    assert app.config["SESSION_COOKIE_SECURE"] is True
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    assert app.config["REMEMBER_COOKIE_SECURE"] is True
    assert app.config["REMEMBER_COOKIE_HTTPONLY"] is True


def test_local_development_mode_remains_available():
    app = create_app({"ENV": "development"})

    assert app.config["ENV"] == "development"


def test_wsgi_entrypoint_rejects_nonproduction_mode(monkeypatch):
    monkeypatch.setenv("FLASK_ENV", "development")

    with pytest.raises(RuntimeError, match="requires FLASK_ENV=production"):
        runpy.run_path(str(PROJECT_ROOT / "wsgi.py"))


def test_docker_context_excludes_local_databases_and_secrets():
    dockerignore = (PROJECT_ROOT / ".dockerignore").read_text(encoding="utf-8")
    required_patterns = (
        "*.db",
        "*.sqlite",
        "*.sqlite3",
        "instance/",
        ".env*",
        ".venv/",
        ".git/",
    )

    for pattern in required_patterns:
        assert pattern in dockerignore


def test_dockerfile_copies_only_runtime_files_and_uses_nonroot_user():
    dockerfile = (PROJECT_ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert not re.search(r"(?m)^COPY\s+\.\s", dockerfile)
    assert "COPY --chown=appuser:appuser app/ ./app/" in dockerfile
    assert "COPY --chown=appuser:appuser wsgi.py ./wsgi.py" in dockerfile
    assert "USER appuser" in dockerfile


def test_compose_requires_credentials_and_does_not_publish_database_port():
    compose = (PROJECT_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    init_sql = (
        PROJECT_ROOT / "database" / "01_create_database.sql"
    ).read_text(encoding="utf-8")

    for variable in (
        "SECRET_KEY",
        "MYSQL_ROOT_PASSWORD",
        "MYSQL_USER",
        "MYSQL_PASSWORD",
    ):
        assert f"${{{variable}:?" in compose

    database_service = re.search(
        r"(?ms)^  db:\n(.*?)(?=^volumes:|\Z)",
        compose,
    )
    assert database_service is not None
    assert "\n    ports:" not in database_service.group(1)
    for variable in ("MYSQL_ROOT_PASSWORD", "MYSQL_USER", "MYSQL_PASSWORD"):
        assert re.search(
            rf'(?m)^\s+{variable}:\s+"?\$\{{{variable}:\?',
            compose,
        )
    assert "IDENTIFIED BY" not in init_sql
