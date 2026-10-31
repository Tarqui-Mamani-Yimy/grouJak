import { createRoot } from "react-dom/client";
import App from "./App";
import "./styles.css";

const container = document.getElementById("root");
if (!container) {
  throw new Error("No se encontró el contenedor de la aplicación");
}

createRoot(container).render(<App />);
