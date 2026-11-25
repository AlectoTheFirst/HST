import { Component, type ReactNode } from "react";

/** The boundary keeps the workspace and its chat mounted after a failed lazy import or draft render. */
export class ApplicationPageBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state: { error: Error | null } = { error: null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  render() {
    const error = this.state.error;
    if (!error) return this.props.children;
    return <section className="application-draft" aria-label="Application page error">
      <h2>Business applications could not be displayed</h2>
      <p role="alert">The page failed to load or render</p>
      <button type="button" onClick={() => window.location.reload()}>Reload page</button>
      <details><summary>Error details</summary><pre>{error.message || String(error)}</pre></details>
    </section>;
  }
}
