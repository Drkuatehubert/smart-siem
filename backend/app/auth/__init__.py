# Ré-exporte le router pour que d'autres modules puissent faire
# `from app.auth import router` sans connaître le détail de controller.py.
from app.auth.controller import router

__all__ = ["router"]
