import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { apiGet, apiPost, liveSocketUrl } from "./api";
import type {
  Alert,
  AttackerAction,
  AttackerLogLine,
  Finding,
  Rule,
  Severity,
  WsMessage,
} from "./types";

type ConnectionState = "connecting" | "live" | "offline";
type AttackState = "idle" | "running" | "stopped";

const MAX_LINES = 400;

const RULE_LABELS: Record<Rule, string> = {
  brute_force: "Fuerza bruta",
  success_after_failures: "Éxito tras fallos",
};

const SEVERITY_LABELS: Record<Severity, string> = {
  low: "Baja",
  medium: "Media",
  high: "Alta",
  critical: "Crítica",
};

const CHECK_LABELS: Record<Finding["check"], string> = {
  missing_headers: "Cabeceras",
  exposed_path: "Rutas expuestas",
  no_https: "Sin HTTPS",
  no_rate_limit: "Sin rate limit",
};

const ACTION_LABELS: Record<AttackerAction, string> = {
  recon: "recon",
  probe_path: "ruta",
  brute_force_attempt: "login",
  brute_force_success: "éxito",
  blocked: "bloqueo",
};

function formatTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "--:--:--";
  }
  return date.toLocaleTimeString("es-MX", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

function formatDateTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "sin fecha";
  }
  return date.toLocaleString("es-MX", {
    day: "2-digit",
    month: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

function upsertById<T extends { id: number }>(items: T[], incoming: T): T[] {
  const index = items.findIndex((item) => item.id === incoming.id);
  if (index === -1) {
    return [...items, incoming];
  }
  return items.map((item) => (item.id === incoming.id ? incoming : item));
}

interface AlertCardProps {
  alert: Alert;
  findings: Finding[];
  blocking: boolean;
  onBlock: (alert: Alert) => void;
}

function AlertCard({ alert, findings, blocking, onBlock }: AlertCardProps) {
  const result = alert.ai_result;
  const severity: Severity =
    result?.severity ?? (alert.rule === "success_after_failures" ? "high" : "medium");
  const correlated = findings.filter((finding) =>
    alert.correlated_finding_ids.includes(finding.id),
  );

  return (
    <article className={`alert-card severity-${severity} ${alert.blocked ? "is-blocked" : ""}`}>
      <div className="alert-top">
        <span className={`severity-badge ${severity}`}>{SEVERITY_LABELS[severity]}</span>
        <span className="rule-label">{RULE_LABELS[alert.rule]}</span>
        {alert.blocked && <span className="blocked-badge">IP bloqueada</span>}
        <span className="alert-time">{formatDateTime(alert.created_at)}</span>
      </div>

      <div className="alert-metrics">
        <div>
          <span>IP</span>
          <strong>{alert.source_ip}</strong>
        </div>
        <div>
          <span>Usuario</span>
          <strong>{alert.user}</strong>
        </div>
        <div>
          <span>Intentos</span>
          <strong>{alert.count}</strong>
        </div>
        <div>
          <span>Ventana</span>
          <strong>{alert.window_seconds}s</strong>
        </div>
        <div>
          <span>Activo</span>
          <strong>{alert.host}</strong>
        </div>
        <div>
          <span>Alerta</span>
          <strong>#{alert.id}</strong>
        </div>
      </div>

      {result ? (
        <div className="ai-block">
          <p className="explanation">{result.explanation}</p>
          <p className="cause">
            <span>Causa probable:</span> {result.probable_cause}
          </p>
          <ol className="actions">
            {result.recommended_actions.map((action, index) => (
              <li key={index}>{action}</li>
            ))}
          </ol>
          <div className="confidence">
            <span>Confianza IA</span>
            <div className="bar">
              <i style={{ width: `${Math.round(result.confidence * 100)}%` }} />
            </div>
            <strong>{Math.round(result.confidence * 100)}%</strong>
          </div>
        </div>
      ) : (
        <p className="analyzing">
          <span className="pulse" />
          La IA defensora está analizando…
        </p>
      )}

      {correlated.length > 0 && (
        <div className="correlation">
          <span>Correlación:</span>
          {correlated.map((finding) => (
            <span className="chip-finding" key={finding.id}>
              {CHECK_LABELS[finding.check]}
            </span>
          ))}
        </div>
      )}

      <button
        type="button"
        className={`btn block ${alert.blocked ? "is-blocked" : ""}`}
        disabled={alert.blocked || blocking}
        onClick={() => onBlock(alert)}
      >
        {alert.blocked ? "IP bloqueada" : blocking ? "Bloqueando…" : "Bloquear IP"}
      </button>
    </article>
  );
}

export default function App() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [lines, setLines] = useState<AttackerLogLine[]>([]);
  const [connection, setConnection] = useState<ConnectionState>("connecting");
  const [attack, setAttack] = useState<AttackState>("idle");
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const consoleRef = useRef<HTMLDivElement>(null);
  const watchdogRef = useRef<number | undefined>(undefined);

  const refresh = useCallback(async () => {
    try {
      const [nextAlerts, nextFindings] = await Promise.all([
        apiGet<Alert[]>("/api/v1/alerts"),
        apiGet<Finding[]>("/api/v1/findings"),
      ]);
      setAlerts(nextAlerts);
      setFindings(nextFindings);
    } catch {
      // El indicador de conexión refleja la caída del backend.
    }
  }, []);

  const handleWsMessage = useCallback((message: WsMessage) => {
    if (message.type === "alert_new") {
      setAlerts((previous) => upsertById(previous, message.alert));
      return;
    }
    if (message.type === "finding_new") {
      setFindings((previous) => upsertById(previous, message.finding));
      return;
    }
    if (message.type === "attacker_log") {
      setLines((previous) => {
        const next = [...previous, message.line];
        return next.length > MAX_LINES ? next.slice(next.length - MAX_LINES) : next;
      });
      if (
        message.line.action === "blocked" ||
        message.line.detail.includes("Atacante detenido") ||
        message.line.detail.includes("Ataque detenido")
      ) {
        setAttack("stopped");
      }
      return;
    }
    if (message.type === "blocked") {
      setAttack("stopped");
      const findingIds = new Set(message.finding_ids ?? []);
      setAlerts((previous) =>
        previous.map((alert) =>
          alert.id === message.alert_id ? { ...alert, blocked: true } : alert,
        ),
      );
      if (findingIds.size > 0) {
        setFindings((previous) =>
          previous.map((finding) =>
            findingIds.has(finding.id)
              ? { ...finding, status: "mitigated" }
              : finding,
          ),
        );
      }
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    let socket: WebSocket | null = null;
    let retry: number | undefined;
    let closed = false;

    const connect = () => {
      if (closed) {
        return;
      }
      setConnection("connecting");
      socket = new WebSocket(liveSocketUrl());
      socket.onopen = () => {
        if (closed) {
          return;
        }
        setConnection("live");
        void refresh();
      };
      socket.onmessage = (event) => {
        try {
          handleWsMessage(JSON.parse(event.data) as WsMessage);
        } catch {
          // Mensaje no reconocido: se ignora.
        }
      };
      socket.onclose = () => {
        if (closed) {
          return;
        }
        setConnection("offline");
        retry = window.setTimeout(connect, 2000);
      };
      socket.onerror = () => {
        socket?.close();
      };
    };

    connect();
    return () => {
      closed = true;
      if (retry !== undefined) {
        window.clearTimeout(retry);
      }
      socket?.close();
    };
  }, [handleWsMessage, refresh]);

  useEffect(() => {
    const element = consoleRef.current;
    if (element) {
      element.scrollTop = element.scrollHeight;
    }
  }, [lines]);

  useEffect(() => {
    if (attack !== "running" && watchdogRef.current !== undefined) {
      window.clearTimeout(watchdogRef.current);
      watchdogRef.current = undefined;
    }
  }, [attack]);

  useEffect(
    () => () => {
      if (watchdogRef.current !== undefined) {
        window.clearTimeout(watchdogRef.current);
      }
    },
    [],
  );

  useEffect(() => {
    if (!error) {
      return;
    }
    const timer = window.setTimeout(() => setError(null), 6000);
    return () => window.clearTimeout(timer);
  }, [error]);

  const openFindings = useMemo(
    () => findings.filter((finding) => finding.status === "open").length,
    [findings],
  );
  const sortedFindings = useMemo(
    () => [...findings].sort((a, b) => a.id - b.id),
    [findings],
  );
  const sortedAlerts = useMemo(
    () => [...alerts].sort((a, b) => b.id - a.id),
    [alerts],
  );

  async function runScan() {
    setBusy("scan");
    setError(null);
    try {
      await apiPost<Finding[]>("/api/v1/scan");
      await refresh();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "No se pudo ejecutar el escaneo");
    } finally {
      setBusy(null);
    }
  }

  async function startAttack(mode: "scripted" | "agentic") {
    setError(null);
    try {
      await apiPost("/api/v1/attacker/run", { mode });
      setAttack("running");
      if (watchdogRef.current !== undefined) {
        window.clearTimeout(watchdogRef.current);
      }
      watchdogRef.current = window.setTimeout(() => {
        setAttack((previous) => (previous === "running" ? "stopped" : previous));
      }, 120_000);
    } catch (caught) {
      setError(
        caught instanceof Error ? caught.message : "No se pudo iniciar el ataque",
      );
    }
  }

  async function simulateAlert() {
    setBusy("demo");
    setError(null);
    try {
      await apiPost("/api/v1/demo/alert");
    } catch (caught) {
      setError(
        caught instanceof Error ? caught.message : "No se pudo crear la alerta demo",
      );
    } finally {
      setBusy(null);
    }
  }

  async function handleBlock(alert: Alert) {
    setBusy(`block-${alert.id}`);
    setError(null);
    try {
      await apiPost("/api/v1/block-ip", {
        ip: alert.source_ip,
        alert_id: alert.id,
      });
      setAlerts((previous) =>
        previous.map((item) =>
          item.id === alert.id ? { ...item, blocked: true } : item,
        ),
      );
      const correlated = new Set(alert.correlated_finding_ids);
      setFindings((previous) =>
        previous.map((finding) =>
          correlated.has(finding.id)
            ? { ...finding, status: "mitigated" }
            : finding,
        ),
      );
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "No se pudo bloquear la IP");
    } finally {
      setBusy(null);
    }
  }

  const connectionLabel =
    connection === "live"
      ? "EN VIVO"
      : connection === "connecting"
        ? "CONECTANDO"
        : "SIN CONEXIÓN";

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark">S</span>
          <div>
            <h1>SENTINEL</h1>
            <p>Centro de operaciones · demo local</p>
          </div>
        </div>
        <div className="controls">
          <button
            type="button"
            className="btn"
            onClick={runScan}
            disabled={busy !== null}
          >
            {busy === "scan" ? "Escaneando…" : "Escanear"}
          </button>
          <button
            type="button"
            className="btn danger"
            onClick={() => startAttack("scripted")}
            disabled={attack === "running" || busy !== null}
          >
            Atacar (scripted)
          </button>
          <button
            type="button"
            className="btn"
            onClick={() => startAttack("agentic")}
            disabled={attack === "running" || busy !== null}
          >
            Atacar (agéntico)
          </button>
          <button
            type="button"
            className="btn ghost"
            onClick={simulateAlert}
            disabled={busy !== null}
          >
            Alerta demo
          </button>
          <span className={`connection ${connection}`}>
            <span className="status-dot" />
            {connectionLabel}
          </span>
        </div>
      </header>

      {error && (
        <div className="error-banner" role="alert">
          {error}
        </div>
      )}

      <main className="columns">
        <section className="terminal attacker" aria-label="Consola del atacante">
          <header className="terminal-header">
            <div className="terminal-title">
              <span className="dot red" />
              🔴 ATACANTE (IA)
            </div>
            <span className={`attack-state ${attack}`}>
              {attack === "running"
                ? "atacando…"
                : attack === "stopped"
                  ? "atacante detenido"
                  : "en espera"}
            </span>
          </header>
          <div className="terminal-body console" ref={consoleRef} aria-live="polite">
            {lines.length === 0 && (
              <p className="empty">
                Consola de ataque vacía. Usa “Atacar (scripted)” o “Atacar
                (agéntico)” para iniciar la simulación contra la app de demo.
              </p>
            )}
            {lines.map((line, index) => (
              <div
                className={`log-line ${line.action}`}
                key={`${line.timestamp}-${index}`}
              >
                <span className="prompt">$</span>
                <span className="time">{formatTime(line.timestamp)}</span>
                <span className="action">[{ACTION_LABELS[line.action]}]</span>
                <span className="detail">{line.detail}</span>
              </div>
            ))}
          </div>
        </section>

        <section className="terminal defender" aria-label="Panel del defensor">
          <header className="terminal-header">
            <div className="terminal-title">
              <span className="dot green" />
              🛡️ DEFENSOR
            </div>
            <span className="defender-counts">
              {openFindings} hallazgos abiertos · {alerts.length} alertas
            </span>
          </header>
          <div className="terminal-body defender-body">
            <div className="defender-section">
              <h2>
                Hallazgos del escáner <span>{findings.length}</span>
              </h2>
              {sortedFindings.length === 0 ? (
                <p className="empty">
                  Sin hallazgos todavía. Pulsa “Escanear” para poblar el panel.
                </p>
              ) : (
                <div className="finding-list">
                  {sortedFindings.map((finding) => (
                    <article
                      className={`finding ${finding.status}`}
                      key={finding.id}
                    >
                      <div className="finding-top">
                        <span className={`severity-badge ${finding.severity}`}>
                          {SEVERITY_LABELS[finding.severity]}
                        </span>
                        <strong>{CHECK_LABELS[finding.check]}</strong>
                        <span className={`finding-status ${finding.status}`}>
                          {finding.status === "open" ? "abierto" : "mitigado"}
                        </span>
                        <span className="finding-time">
                          {formatDateTime(finding.detected_at)}
                        </span>
                      </div>
                      <p>{finding.detail}</p>
                    </article>
                  ))}
                </div>
              )}
            </div>

            <div className="defender-section">
              <h2>
                Alertas correlacionadas <span>{alerts.length}</span>
              </h2>
              {sortedAlerts.length === 0 ? (
                <p className="empty">
                  Aún no hay alertas. Lanza el ataque o usa “Alerta demo” como
                  plan B.
                </p>
              ) : (
                <div className="alert-list">
                  {sortedAlerts.map((alert) => (
                    <AlertCard
                      key={alert.id}
                      alert={alert}
                      findings={findings}
                      blocking={busy === `block-${alert.id}`}
                      onBlock={handleBlock}
                    />
                  ))}
                </div>
              )}
            </div>
          </div>
        </section>
      </main>

      <footer className="footer">
        Objetivo fijo: app-login-demo · 127.0.0.1 · reglas deterministas → correlación
        → IA → humano aprueba el bloqueo · sin credenciales en pantalla
      </footer>
    </div>
  );
}
