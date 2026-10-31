# Stack del proyecto

Herramientas previstas para el proyecto. La columna **Estado** indica si la herramienta ya está configurada en el repositorio o si falta incorporarla.

## Stack por área

| Parte | Stack | Para qué | Estado |
| :--- | :--- | :--- | :--- |
| **Backend y API** | **Python 3.11+ · FastAPI · Pydantic · Uvicorn** | Recibir registros y devolver alertas | Configurado en `Backend/` |
| **Procesamiento** | **pandas · scikit-learn** | Preparar los registros y detectar anomalías con Isolation Forest | Pendiente de instalar |
| **Reglas de seguridad** | **Python** | Detectar casos claros, como muchos inicios de sesión fallidos o accesos en horarios inusuales | Pendiente de implementar |
| **Interfaz** | **React 19 · Vite · TypeScript** | Mostrar eventos, alertas, severidad y explicación | Configurado en `Frontend/mi-proyecto/` |
| **Gráficos** | **Recharts** | Visualizar alertas por tipo, severidad o tiempo | Pendiente de instalar |
| **Persistencia** | **SQLite** | Guardar los eventos y las alertas durante la demo | Pendiente de implementar |
| **Explicaciones con IA** | **Un solo proveedor de LLM (por definir)** | Explicar las alertas en español sencillo | Pendiente de decidir el proveedor |
| **Notificaciones (opcional)** | **Telegram Bot API** | Enviar una alerta durante la demo | Opcional |

## Herramientas de desarrollo

| Área | Herramienta | Uso |
| :--- | :--- | :--- |
| Backend | `pip` con entorno virtual (`.venv`) | Instalar dependencias desde `Backend/pyproject.toml` |
| Backend | `pytest` · `httpx` | Pruebas de la API |
| Frontend | `pnpm` (versión fijada en `packageManager`) | Instalar dependencias y ejecutar scripts |
| Frontend | ESLint · typescript-eslint | Análisis estático del código |

## Pendientes conocidos

- **Proveedor de LLM:** falta elegir cuál usará el equipo.
- **Lint del frontend:** `pnpm lint` falla porque typescript-eslint todavía no es compatible con TypeScript 7.0 (el proyecto usa `typescript ~7.0.2`).
