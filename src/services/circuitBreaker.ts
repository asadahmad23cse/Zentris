import { config } from "../config";
import { logger } from "../utils/logger";

type CircuitState = "closed" | "open" | "half-open";

interface CircuitBreakerStats {
  failures: number;
  successes: number;
  state: CircuitState;
  lastFailureTime: number | null;
}

const parseEnvNumber = (name: string, fallback: number): number => {
  const rawValue = process.env[name];
  if (!rawValue || rawValue.trim().length === 0) {
    return fallback;
  }

  const parsed = Number.parseInt(rawValue, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }

  return parsed;
};

export class CircuitBreaker {
  private readonly failureThreshold: number;
  private readonly successThreshold: number;
  private readonly timeout: number;
  private readonly enabled: boolean;

  private state: CircuitState = "closed";
  private failures = 0;
  private successes = 0;
  private lastFailureTime: number | null = null;

  public constructor() {
    this.failureThreshold = parseEnvNumber("CIRCUIT_BREAKER_FAILURE_THRESHOLD", 5);
    this.successThreshold = parseEnvNumber("CIRCUIT_BREAKER_SUCCESS_THRESHOLD", 2);
    this.timeout = parseEnvNumber("CIRCUIT_BREAKER_TIMEOUT_MS", 30000);
    this.enabled = config.CIRCUIT_BREAKER_ENABLED;
  }

  public async execute<T>(fn: () => Promise<T>, fallback?: () => T): Promise<T> {
    if (!this.enabled) {
      return fn();
    }

    if (this.state === "open") {
      const now = Date.now();
      const canTryHalfOpen =
        this.lastFailureTime !== null && now - this.lastFailureTime >= this.timeout;

      if (canTryHalfOpen) {
        this.transitionTo("half-open", "timeout_elapsed");
      } else {
        if (fallback) return Promise.resolve(fallback());
        throw new CircuitOpenError("Upstream circuit is open");
      }
    }

    try {
      const result = await fn();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure(error);
      throw error;
    }
  }

  public getState(): CircuitState {
    return this.state;
  }

  public getStats(): CircuitBreakerStats {
    return {
      failures: this.failures,
      successes: this.successes,
      state: this.state,
      lastFailureTime: this.lastFailureTime
    };
  }

  private onSuccess(): void {
    if (this.state === "half-open") {
      this.successes += 1;
      if (this.successes >= this.successThreshold) {
        this.transitionTo("closed", "half_open_success_threshold_reached");
        this.failures = 0;
        this.successes = 0;
        this.lastFailureTime = null;
      }
      return;
    }

    if (this.state === "closed") {
      this.failures = 0;
      this.successes = 0;
      return;
    }
  }

  private onFailure(error: unknown): void {
    this.lastFailureTime = Date.now();

    if (this.state === "half-open") {
      this.failures = this.failureThreshold;
      this.successes = 0;
      this.transitionTo("open", "half_open_failure");
      logger.warn({ err: error }, "circuit_breaker_execution_failed");
      return;
    }

    this.failures += 1;
    this.successes = 0;
    logger.warn({ err: error, failures: this.failures }, "circuit_breaker_execution_failed");

    if (this.state === "closed" && this.failures >= this.failureThreshold) {
      this.transitionTo("open", "failure_threshold_reached");
    }
  }

  private transitionTo(nextState: CircuitState, reason: string): void {
    if (this.state === nextState) {
      return;
    }

    logger.info(
      {
        fromState: this.state,
        toState: nextState,
        reason,
        failures: this.failures,
        successes: this.successes,
        lastFailureTime: this.lastFailureTime
      },
      "circuit_breaker_state_transition"
    );

    this.state = nextState;
  }
}

export class CircuitOpenError extends Error {
  public readonly statusCode = 503;

  public constructor(message: string) {
    super(message);
    this.name = "CircuitOpenError";
  }
}
