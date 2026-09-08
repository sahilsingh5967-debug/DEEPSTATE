import importlib


def test_import_backend_modules():
    """Verify all backend packages and modules import cleanly."""
    modules = [
        "backend.app.main",
        "backend.app.core.config",
        "backend.app.models.schemas",
        "backend.app.api.v1.router",
        "backend.app.analyzers",
        "backend.app.assessment",
        "backend.app.ml",
        "backend.app.services",
    ]
    for mod_name in modules:
        mod = importlib.import_module(mod_name)
        assert mod is not None
