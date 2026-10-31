export type Severity = "low" | "medium" | "high" | "critical";

export interface AIResult {
  severity: Severity;
  explanation: string;
  probable_cause: string;
  recommended_actions: string[];
  confidence: number;
}

export type Rule = "brute_force" | "success_after_failures";

export interface Alert {
  id: number;
  rule: Rule;
  host: string;
  source_ip: string;
  user: string;
  count: number;
  window_seconds: number;
  created_at: string;
  correlated_finding_ids: number[];
  ai_result: AIResult | null;
  notified: boolean;
  blocked: boolean;
}

export type FindingCheck =
  | "missing_headers"
  | "exposed_path"
  | "no_https"
  | "no_rate_limit";

export interface Finding {
  id: number;
  host: string;
  check: FindingCheck;
  severity: "low" | "medium" | "high";
  detail: string;
  status: "open" | "mitigated";
  detected_at: string;
}

export type AttackerAction =
  | "recon"
  | "probe_path"
  | "brute_force_attempt"
  | "brute_force_success"
  | "blocked";

export interface AttackerLogLine {
  timestamp: string;
  action: AttackerAction;
  detail: string;
}

export type WsMessage =
  | { type: "alert_new"; alert: Alert }
  | { type: "finding_new"; finding: Finding }
  | { type: "attacker_log"; line: AttackerLogLine }
  | {
      type: "blocked";
      ip: string;
      alert_id: number;
      blocked: boolean;
      finding_ids?: number[];
    };
