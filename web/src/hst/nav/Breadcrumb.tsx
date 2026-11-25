export interface Crumb {
  uid: string | null;
  label: string;
}

interface Props {
  trail: Crumb[];
  onSelect(uid: string | null): void;
}

export default function Breadcrumb({ trail, onSelect }: Props) {
  return (
    <nav className="hst-breadcrumb" aria-label="Breadcrumb">
      <ol>
        {trail.map((c, i) => (
          <li key={c.uid ?? "estate"}>
            {i < trail.length - 1 ? (
              <button type="button" onClick={() => onSelect(c.uid)}>
                {c.label}
              </button>
            ) : (
              <span aria-current="location">{c.label}</span>
            )}
          </li>
        ))}
      </ol>
    </nav>
  );
}
