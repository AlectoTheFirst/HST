import { Component, type ReactNode } from "react";

/** Catches a render error and a lazy chunk that failed to load, anywhere below. */
export class RootErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state: { error: Error | null } = { error: null };

  static getDerivedStateFromError(error: unknown) {
    return { error: error instanceof Error ? error : new Error(String(error)) };
  }

  render() {
    const error = this.state.error;
    if (!error) return this.props.children;
    return (
      <div className="forbidden-shell">
        <div className="forbidden-card" role="alert">
          <b>Page not displayed</b>
          {error.message && <p>{error.message}</p>}
          <button type="button" onClick={() => window.location.reload()}>
            Reload
          </button>
        </div>
      </div>
    );
  }
}
