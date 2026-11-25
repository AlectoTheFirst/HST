import { Fragment, useEffect, useRef, type ReactNode } from "react";
import { useDialogFocus } from "../../shell/useDialogFocus";

export function PageHeader({ title, meta, children }: { title: string; meta?: ReactNode; children?: ReactNode }) {
  return (
    <header className="inv-head">
      <div className="inv-head-title">
        <h1>{title}</h1>
        {meta && <div className="inv-head-meta">{meta}</div>}
      </div>
      {children && <div className="inv-actions">{children}</div>}
    </header>
  );
}

export function Card({ title, actions, children, className = "", label }: {
  title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; label?: string;
}) {
  return (
    <section className={`editorcard inv-card ${className}`} aria-label={label}>
      {(title || actions) && (
        <div className="bar">
          {title && <h2 className="card-title">{title}</h2>}
          {actions && <div className="inv-actions">{actions}</div>}
        </div>
      )}
      {children}
    </section>
  );
}

export type Fact = [label: string, value: ReactNode];

export function Facts({ rows }: { rows: Fact[] }) {
  return (
    <dl className="inv-facts">
      {rows.map(([label, value]) => (
        <Fragment key={label}>
          <dt>{label}</dt>
          <dd>{value}</dd>
        </Fragment>
      ))}
    </dl>
  );
}

export function Stat({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="inv-stat">
      <span className="inv-stat-label">{label}</span>
      <span className="inv-stat-value">{value}</span>
    </div>
  );
}

/** Escape closes the dialog unless `locked`. */
export function Modal({ label, title, onClose, locked = false, wide = false, footer, children }: {
  label: string; title: ReactNode; onClose: () => void; locked?: boolean; wide?: boolean; footer?: ReactNode; children: ReactNode;
}) {
  const card = useRef<HTMLDivElement>(null);
  useDialogFocus(card);
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => { if (event.key === "Escape" && !locked) onClose(); };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [locked, onClose]);
  return (
    <div className="modal-scrim inv-scrim">
      <div ref={card} tabIndex={-1} className={`modal-card inv-modal${wide ? " wide" : ""}`} role="dialog" aria-modal="true" aria-label={label}>
        <div className="modal-head">
          <h2 className="modal-label">{title}</h2>
          <button type="button" className="modal-close" disabled={locked} onClick={onClose}>Close</button>
        </div>
        <div className="modal-body">{children}</div>
        {footer && <div className="inv-modal-foot">{footer}</div>}
      </div>
    </div>
  );
}

export function ConfirmDialog({ label, title, children, confirmLabel, cancelLabel = "Cancel", pending = false, danger = false, confirmDisabled = false, onConfirm, onCancel }: {
  label: string; title: ReactNode; children: ReactNode; confirmLabel: string; cancelLabel?: string;
  pending?: boolean; danger?: boolean; confirmDisabled?: boolean; onConfirm: () => void; onCancel: () => void;
}) {
  return (
    <Modal label={label} title={title} onClose={onCancel} locked={pending} footer={<>
      <button type="button" className="secondary" disabled={pending} onClick={onCancel}>{cancelLabel}</button>
      <button type="button" className={danger ? "primary inv-danger" : "primary"} disabled={pending || confirmDisabled} onClick={onConfirm}>{confirmLabel}</button>
    </>}>
      {children}
    </Modal>
  );
}
